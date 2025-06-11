from ossprey.sbom_python import create_sbom_from_env, create_sbom_from_requirements
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
