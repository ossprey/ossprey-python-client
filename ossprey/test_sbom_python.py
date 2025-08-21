from __future__ import annotations
import sys
from pathlib import Path
import pytest
from unittest.mock import patch

from ossprey.sbom_python import create_sbom_from_env, create_sbom_from_requirements, get_cyclonedx_binary
from ossprey.virtualenv import VirtualEnv


def test_get_sbom():
    sbom = create_sbom_from_env()

    assert sbom.format == 'OSSBOM'


def test_get_sbom_from_venv():

    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package('numpy')

    requirements_file = venv.create_requirements_file_from_env()

    # Get the SBOM
    sbom = create_sbom_from_requirements(requirements_file)

    assert sbom.format == 'OSSBOM'
    assert len(sbom.components) == 1
    assert any(map(lambda x: x.name == 'numpy', sbom.components.values()))


def test_get_sbom_from_venv_local_package():

    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package('test/python_simple_math')
  
    requirements_file = venv.create_requirements_file_from_env()

    # Get the SBOM
    sbom = create_sbom_from_requirements(requirements_file)

    assert sbom.format == 'OSSBOM'
    assert len(sbom.components) == 7
    assert any(map(lambda x: x.name == 'simple_math', sbom.components.values()))


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
