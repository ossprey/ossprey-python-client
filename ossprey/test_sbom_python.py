from __future__ import annotations
import sys
from pathlib import Path
import pytest
from unittest.mock import patch

from ossprey.sbom_python import (
    create_sbom_from_env,
    create_sbom_from_requirements,
    get_cyclonedx_binary,
    update_sbom_from_poetry,
    update_sbom_from_virtualenv,
    PoetryNotFoundError,
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


@patch("os.path.exists", return_value=False)
@patch("shutil.which", return_value=None)
def test_poetry_not_found_error(mock_which, mock_exists):
    """Test that PoetryNotFoundError is raised when poetry command is not available."""
    ossbom = OSSBOM()
    with pytest.raises(PoetryNotFoundError, match="poetry command not found in PATH"):
        update_sbom_from_poetry(ossbom, "/tmp/test_dir")


@patch("subprocess.run")
@patch("os.path.exists")
@patch("shutil.which", return_value="/usr/bin/poetry")
def test_not_a_poetry_project_error(mock_which, mock_exists, mock_run):
    """Test that NotAPoetryProjectError is raised when pyproject.toml doesn't contain poetry configuration."""
    import subprocess
    from unittest.mock import mock_open
    
    # Mock os.path.exists to return False for poetry.lock, True for pyproject.toml
    def exists_side_effect(path):
        if "poetry.lock" in path:
            return False
        elif "pyproject.toml" in path:
            return True
        return False
    
    mock_exists.side_effect = exists_side_effect
    
    # Mock subprocess.run to raise CalledProcessError
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1, 
        cmd=["poetry", "install"],
        output="",
        stderr="Error: not a poetry project"
    )
    
    # Mock pyproject.toml reading to return non-poetry project
    mock_toml_data = b'[build-system]\nrequires = ["setuptools"]\n'
    
    with patch("builtins.open", mock_open(read_data=mock_toml_data)):
        ossbom = OSSBOM()
        with pytest.raises(NotAPoetryProjectError, match="does not contain a valid poetry project"):
            update_sbom_from_poetry(ossbom, "/tmp/test_dir")


@patch("ossprey.scan.update_sbom_from_virtualenv")
@patch("ossprey.scan.update_sbom_from_poetry")
def test_fallback_to_pipenv_on_poetry_not_found(mock_update_poetry, mock_update_venv):
    """Test that scan_python falls back to pipenv when PoetryNotFoundError occurs."""
    from ossprey.scan import scan_python
    
    # Make update_sbom_from_poetry raise PoetryNotFoundError
    mock_update_poetry.side_effect = PoetryNotFoundError("poetry command not found in PATH")
    
    # Create a mock return value for virtualenv
    mock_sbom = OSSBOM()
    mock_update_venv.return_value = mock_sbom
    
    # Call scan_python with poetry mode
    modes = ["poetry"]
    result = scan_python(modes, OSSBOM(), "/tmp/test_dir")
    
    # Verify that poetry was attempted
    mock_update_poetry.assert_called_once()
    
    # Verify that pipenv was called as fallback
    mock_update_venv.assert_called_once()
    
    # Verify that pipenv was added to modes
    assert "pipenv" in modes


@patch("ossprey.scan.update_sbom_from_virtualenv")
@patch("ossprey.scan.update_sbom_from_poetry")
def test_fallback_to_pipenv_on_not_a_poetry_project(mock_update_poetry, mock_update_venv):
    """Test that scan_python falls back to pipenv when NotAPoetryProjectError occurs."""
    from ossprey.scan import scan_python
    
    # Make update_sbom_from_poetry raise NotAPoetryProjectError
    mock_update_poetry.side_effect = NotAPoetryProjectError(
        "Directory /tmp/test_dir does not contain a valid poetry project"
    )
    
    # Create a mock return value for virtualenv
    mock_sbom = OSSBOM()
    mock_update_venv.return_value = mock_sbom
    
    # Call scan_python with poetry mode
    modes = ["poetry"]
    result = scan_python(modes, OSSBOM(), "/tmp/test_dir")
    
    # Verify that poetry was attempted
    mock_update_poetry.assert_called_once()
    
    # Verify that pipenv was called as fallback
    mock_update_venv.assert_called_once()
    
    # Verify that pipenv was added to modes
    assert "pipenv" in modes
