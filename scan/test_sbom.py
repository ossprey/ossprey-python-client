from scan.sbom import create_sbom_from_env, create_sbom_from_requirements
from scan.virtualenv import VirtualEnv


def test_get_sbom():
    sbom = create_sbom_from_env()

    assert sbom.get('bomFormat') == 'CycloneDX'


def test_get_sbom_from_venv():

    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package('numpy')

    requirements_file = venv.create_requirements_file_from_env()

    # Get the SBOM
    sbom = create_sbom_from_requirements(requirements_file)

    assert sbom.get('bomFormat') == 'CycloneDX'
    assert len(sbom['components']) == 1
    assert any(map(lambda x: x['name'] == 'numpy', sbom['components']))


def test_get_sbom_from_venv_local_package():

    venv = VirtualEnv()
    venv.enter()

    # Install a package
    venv.install_package('test/simple_math')
  
    requirements_file = venv.create_requirements_file_from_env()

    # Get the SBOM
    sbom = create_sbom_from_requirements(requirements_file)

    assert sbom.get('bomFormat') == 'CycloneDX'
    assert len(sbom['components']) == 7
    assert any(map(lambda x: x['name'] == 'simple_math', sbom['components']))
