import os
import sys

from ossprey.virtualenv import VirtualEnv


def test_virtual_env_creation():

    venv = VirtualEnv()

    # Check if the virtual environment files exist
    assert os.path.isdir(os.path.join(venv.get_venv_dir(), 'bin'))


def test_accessing_virtual_env():

    venv = VirtualEnv()
    venv.enter()

    assert len([name.startswith(f"{venv.get_venv_dir()}/lib") for name in sys.path]) > 0

    installed_packages = venv.list_installed_packages()

    # Make sure we are in a new venv
    assert len(installed_packages) == 1
    assert installed_packages[0]['name'] == 'pip'


def test_package_installation():
    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package('numpy')

    installed_packages = venv.list_installed_packages()

    # Make sure we are in a new venv
    assert len(installed_packages) == 2
    assert any(map(lambda x: x['name'] == 'numpy', installed_packages))


def test_local_requirements_file():
    venv = VirtualEnv()
    venv.enter()
    venv.install_package('numpy')

    requirements_file = venv.create_requirements_file_from_env()

    # Read the file
    with open(requirements_file, 'r') as f:
        lines = f.readlines()
        assert len(lines) == 1
        assert lines[0].startswith('numpy')


def test_local_installation():
    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package('test/python_simple_math')

    installed_packages = venv.list_installed_packages()

    # Make sure we are in a new venv
    assert len(installed_packages) == 8
    assert any(map(lambda x: x['name'] == 'numpy', installed_packages))
