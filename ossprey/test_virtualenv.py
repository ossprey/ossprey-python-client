from __future__ import annotations
import os
import subprocess
import sys
from unittest.mock import patch

from ossprey.virtualenv import VirtualEnv
import pytest


def test_virtual_env_creation() -> None:

    venv = VirtualEnv()

    # Check if the virtual environment files exist
    assert os.path.isdir(os.path.join(venv.get_venv_dir(), "bin"))


def test_accessing_virtual_env() -> None:

    venv = VirtualEnv()
    venv.enter()

    assert len([name.startswith(f"{venv.get_venv_dir()}/lib") for name in sys.path]) > 0

    installed_packages = venv.list_installed_packages()

    # Make sure we are in a new venv
    assert len(installed_packages) == 1
    assert installed_packages[0]["name"] == "pip"


def test_package_installation() -> None:
    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package("numpy")

    installed_packages = venv.list_installed_packages()

    # Make sure we are in a new venv
    assert len(installed_packages) == 2
    assert any(map(lambda x: x["name"] == "numpy", installed_packages))


def test_local_requirements_file() -> None:
    venv = VirtualEnv()
    venv.enter()
    venv.install_package("numpy")

    requirements_file = venv.create_requirements_file_from_env()

    # Read the file
    with open(requirements_file, "r") as f:
        lines = f.readlines()
        assert len(lines) == 1
        assert lines[0].startswith("numpy")


def test_local_installation() -> None:
    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package("test/test_packages/python_simple_math")

    installed_packages = venv.list_installed_packages()

    # Make sure we are in a new venv
    assert len(installed_packages) == 8
    assert any(map(lambda x: x["name"] == "numpy", installed_packages))


def test_context_manager() -> None:
    """Test that VirtualEnv works as a context manager."""
    original_path = sys.path[:]

    with VirtualEnv() as venv:
        assert venv is not None
        assert os.path.isdir(os.path.join(venv.get_venv_dir(), "bin"))
        in_venv_path = sys.path[:]

    # After exiting the context manager, sys.path should be restored
    assert sys.path == original_path


def test_exec_called_process_error() -> None:
    """Test that _exec raises CalledProcessError when the command fails."""
    venv = VirtualEnv()
    with pytest.raises(subprocess.CalledProcessError):
        venv._exec(["false"])  # 'false' command always exits with code 1


def test_enter_missing_site_packages() -> None:
    """Test that enter() raises FileNotFoundError if site-packages doesn't exist."""
    venv = VirtualEnv()
    # Point to a non-existent directory by patching get_venv_dir
    with patch.object(venv, "get_venv_dir", return_value="/nonexistent/path"):
        with pytest.raises(FileNotFoundError):
            venv.enter()
