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
    update_sbom_from_poetry,
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


@patch("ossprey.scan.update_sbom_from_virtualenv")
@patch("ossprey.scan.update_sbom_from_poetry")
def test_fallback_to_pipenv_on_not_a_poetry_project(mock_update_poetry, mock_update_venv):
    """Test that scan_python falls back to pipenv when NotAPoetryProjectError occurs."""
    from ossprey.scan import scan_python

    mock_update_poetry.side_effect = NotAPoetryProjectError(
        "Directory /tmp/test_dir does not contain a poetry.lock file"
    )

    mock_sbom = OSSBOM()
    mock_update_venv.return_value = mock_sbom

    modes = ["poetry"]
    scan_python(modes, OSSBOM(), "/tmp/test_dir")

    mock_update_poetry.assert_called_once()
    mock_update_venv.assert_called_once()
    assert "pipenv" in modes


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


def test_update_sbom_from_poetry_with_existing_lock():
    """Test that update_sbom_from_poetry reads from existing poetry.lock."""
    ossbom = OSSBOM()
    result = update_sbom_from_poetry(ossbom, "test/test_packages/poetry_simple_math")

    assert isinstance(result, OSSBOM)
    names = [c.name for c in result.get_components()]
    assert "requests" in names
    assert "numpy" in names
