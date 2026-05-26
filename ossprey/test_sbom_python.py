from __future__ import annotations
import os
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch
import pytest
import tempfile

from ossprey.sbom_python import (
    create_sbom_from_env,
    create_sbom_from_requirements,
    get_cyclonedx_binary,
    get_poetry_purls_from_lock,
    update_sbom_from_pipfile,
    update_sbom_from_poetry,
    update_sbom_from_uv,
    update_sbom_from_virtualenv,
    NotAPoetryProjectError,
)
from ossprey.virtualenv import VirtualEnv
from ossbom.model.ossbom import OSSBOM


def test_get_sbom():
    sbom = create_sbom_from_env()

    assert sbom.format == "OSSBOM"


def test_get_sbom_from_venv():

    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package("numpy")

    requirements_file = venv.create_requirements_file_from_env()

    # Get the SBOM
    sbom = create_sbom_from_requirements(requirements_file)

    assert sbom.format == "OSSBOM"
    assert len(sbom.components) == 1
    assert any(map(lambda x: x.name == "numpy", sbom.components.values()))


def test_get_sbom_from_venv_local_package():

    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package("test/test_packages/python_simple_math")

    requirements_file = venv.create_requirements_file_from_env()

    # Get the SBOM
    sbom = create_sbom_from_requirements(requirements_file)

    assert sbom.format == "OSSBOM"
    assert len(sbom.components) == 7
    assert any(map(lambda x: x.name == "simple_math", sbom.components.values()))


@patch("shutil.which")
def test_returns_shutil_which(mock_which):
    mock_which.return_value = "/usr/local/bin/cyclonedx-py"
    assert get_cyclonedx_binary() == "cyclonedx-py"


@patch("shutil.which", return_value=None)
def test_returns_venv_bin(mock_which):
    fake_bin = Path(sys.executable).parent / "cyclonedx-py"

    with patch("os.path.join", return_value=str(fake_bin)):
        result = get_cyclonedx_binary()
        assert str(fake_bin) in result


@patch("os.path.exists", return_value=False)
@patch("shutil.which", return_value=None)
def test_raises_when_not_found(mock_which, mock_exists):
    with pytest.raises(FileNotFoundError, match="cyclonedx-py binary not found."):
        get_cyclonedx_binary()


def test_not_a_poetry_project_error(tmp_path):
    """Test that NotAPoetryProjectError is raised when poetry.lock is missing."""
    ossbom = OSSBOM()
    with pytest.raises(NotAPoetryProjectError, match="does not contain a poetry.lock"):
        update_sbom_from_poetry(ossbom, str(tmp_path))


@patch("ossprey.scan.update_sbom_from_uv")
@patch("ossprey.scan.update_sbom_from_poetry")
def test_fallback_to_uv_on_not_a_poetry_project(mock_update_poetry, mock_update_uv):
    """scan_python falls back to uv when poetry.lock is missing."""
    from ossprey.scan import scan_python

    mock_update_poetry.side_effect = NotAPoetryProjectError(
        "Directory /tmp/test_dir does not contain a poetry.lock file"
    )

    mock_update_uv.return_value = OSSBOM()

    modes = ["poetry"]
    scan_python(modes, OSSBOM(), "/tmp/test_dir")

    mock_update_poetry.assert_called_once()
    mock_update_uv.assert_called_once()
    assert "pipenv" not in modes


@patch("ossprey.scan.update_sbom_from_virtualenv")
@patch("ossprey.scan.update_sbom_from_uv")
@patch("ossprey.scan.update_sbom_from_poetry")
def test_fallback_to_pipenv_when_uv_fails(
    mock_update_poetry, mock_update_uv, mock_update_venv
):
    """If uv also fails, scan_python falls back to pipenv."""
    from ossprey.scan import scan_python

    mock_update_poetry.side_effect = NotAPoetryProjectError(
        "Directory /tmp/test_dir does not contain a poetry.lock file"
    )
    mock_update_uv.side_effect = subprocess.CalledProcessError(
        returncode=1, cmd=["uv", "pip", "compile"], stderr="resolver error"
    )
    mock_update_venv.return_value = OSSBOM()

    modes = ["poetry"]
    scan_python(modes, OSSBOM(), "/tmp/test_dir")

    mock_update_poetry.assert_called_once()
    mock_update_uv.assert_called_once()
    mock_update_venv.assert_called_once()
    assert "pipenv" in modes


@patch("ossprey.scan.update_sbom_from_virtualenv")
@patch("ossprey.scan.update_sbom_from_uv")
@patch("ossprey.scan.update_sbom_from_poetry")
def test_fallback_to_pipenv_when_uv_missing(
    mock_update_poetry, mock_update_uv, mock_update_venv
):
    """If uv binary is missing, scan_python falls back to pipenv."""
    from ossprey.scan import scan_python

    mock_update_poetry.side_effect = NotAPoetryProjectError(
        "Directory /tmp/test_dir does not contain a poetry.lock file"
    )
    mock_update_uv.side_effect = FileNotFoundError("uv binary not found")
    mock_update_venv.return_value = OSSBOM()

    modes = ["poetry"]
    scan_python(modes, OSSBOM(), "/tmp/test_dir")

    mock_update_poetry.assert_called_once()
    mock_update_uv.assert_called_once()
    mock_update_venv.assert_called_once()
    assert "pipenv" in modes


def test_update_sbom_from_uv_parses_compile_output(tmp_path):
    """update_sbom_from_uv parses uv pip compile output and includes the root pkg."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_bytes(b'[project]\nname = "rootpkg"\nversion = "1.2.3"\n')

    fake_stdout = (
        "# uv compile output\n"
        "colorama==0.4.6 ; sys_platform == 'win32'\n"
        "    # via click\n"
        "requests==2.31.0\n"
        "numpy==1.24.0\n"
    )
    completed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=fake_stdout, stderr=""
    )
    with patch("subprocess.run", return_value=completed), \
         patch("ossprey.sbom_python.get_uv_binary", return_value="/fake/uv"):
        ossbom = update_sbom_from_uv(OSSBOM(), str(tmp_path))

    components = {c.name: c.version for c in ossbom.get_components()}
    assert components == {
        "colorama": "0.4.6",
        "numpy": "1.24.0",
        "requests": "2.31.0",
    }


def test_update_sbom_from_uv_raises_on_failure(tmp_path):
    """update_sbom_from_uv propagates CalledProcessError from uv."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_bytes(b'[project]\nname = "x"\nversion = "0"\n')

    with patch("subprocess.run") as mock_run, \
         patch("ossprey.sbom_python.get_uv_binary", return_value="/fake/uv"):
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["uv", "pip", "compile"], stderr="resolution-impossible"
        )
        with pytest.raises(subprocess.CalledProcessError):
            update_sbom_from_uv(OSSBOM(), str(tmp_path))


def test_update_sbom_from_uv_missing_pyproject(tmp_path):
    """update_sbom_from_uv raises FileNotFoundError when pyproject.toml is absent."""
    with pytest.raises(FileNotFoundError, match="pyproject.toml not found"):
        update_sbom_from_uv(OSSBOM(), str(tmp_path))


def test_create_sbom_from_requirements_called_process_error():
    """Test that CalledProcessError is re-raised from create_sbom_from_requirements."""
    with patch("ossprey.sbom_python.get_cyclonedx_binary", return_value="cyclonedx-py"), \
         patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["cyclonedx-py", "requirements"], stderr="error"
        )
        with pytest.raises(subprocess.CalledProcessError):
            create_sbom_from_requirements("/tmp/requirements.txt")


def test_create_sbom_from_env_called_process_error():
    """Test that CalledProcessError is re-raised from create_sbom_from_env."""
    with patch("ossprey.sbom_python.get_cyclonedx_binary", return_value="cyclonedx-py"), \
         patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["cyclonedx-py", "environment"], stderr="error"
        )
        with pytest.raises(subprocess.CalledProcessError):
            create_sbom_from_env()


def test_get_poetry_purls_from_lock():
    """Test that get_poetry_purls_from_lock reads packages from a poetry.lock file."""
    lock_content = b"""
[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP for Humans"

[[package]]
name = "numpy"
version = "1.24.0"
description = "Numerical Python"
"""
    with tempfile.NamedTemporaryFile(suffix=".lock", delete=False) as f:
        f.write(lock_content)
        lock_path = f.name

    try:
        purls = get_poetry_purls_from_lock(lock_path)
        names = [p.name for p in purls]
        assert "requests" in names
        assert "numpy" in names
        assert len(purls) == 2
    finally:
        os.unlink(lock_path)


def test_update_sbom_from_poetry_raises_when_no_lock():
    """update_sbom_from_poetry raises NotAPoetryProjectError when no poetry.lock present.

    No side effects: does not run `poetry install` to generate a lock. Caller (scan_python)
    catches this and falls back to uv-based pyproject resolution.
    """
    ossbom = OSSBOM()
    with pytest.raises(NotAPoetryProjectError, match="does not contain a poetry.lock"):
        update_sbom_from_poetry(ossbom, "test/test_packages/poetry_simple_math")


def test_update_sbom_from_pipfile_lock(tmp_path):
    """update_sbom_from_pipfile parses Pipfile.lock JSON and emits components."""
    import json

    (tmp_path / "Pipfile.lock").write_text(
        json.dumps(
            {
                "_meta": {"requires": {"python_version": "3.12"}},
                "default": {
                    "requests": {"version": "==2.31.0", "index": "pypi"},
                    "urllib3": {"version": "==2.1.0"},
                },
                "develop": {"pytest": {"version": "==7.4.4"}},
            }
        )
    )

    ossbom = update_sbom_from_pipfile(OSSBOM(), str(tmp_path))
    comps = {c.name: c.version for c in ossbom.get_components()}
    assert comps == {"requests": "2.31.0", "urllib3": "2.1.0", "pytest": "7.4.4"}


def test_update_sbom_from_pipfile_unlocked(tmp_path):
    """update_sbom_from_pipfile falls back to Pipfile TOML when no lock present.

    Skips wildcard ("*") specifiers and table-form specifiers without a version.
    """
    (tmp_path / "Pipfile").write_text(
        '[[source]]\n'
        'url = "https://pypi.org/simple"\n'
        'name = "pypi"\n\n'
        '[packages]\n'
        'requests = "==2.31.0"\n'
        'flask = {version = "==3.0.0", extras = ["async"]}\n'
        'wildcard = "*"\n\n'
        '[dev-packages]\n'
        'pytest = "==7.4.4"\n'
    )

    ossbom = update_sbom_from_pipfile(OSSBOM(), str(tmp_path))
    comps = {c.name: c.version for c in ossbom.get_components()}
    assert comps == {"requests": "2.31.0", "flask": "3.0.0", "pytest": "7.4.4"}


def test_update_sbom_from_pipfile_raises_when_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="neither Pipfile.lock nor Pipfile"):
        update_sbom_from_pipfile(OSSBOM(), str(tmp_path))
