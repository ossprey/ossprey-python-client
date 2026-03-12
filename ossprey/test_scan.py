from __future__ import annotations
import subprocess
from unittest.mock import patch, MagicMock

from ossprey.scan import scan, scan_python
from ossbom.model.ossbom import OSSBOM
from ossprey.exceptions import NoPackageManagerException
from ossprey.sbom_python import PoetryNotFoundError, NotAPoetryProjectError
import pytest


@pytest.mark.parametrize("mode", ["python-requirements", "auto"])
def test_scan_py_success(mode: str) -> None:
    ret = scan("test/test_packages/python_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)
    assert [comp.name for comp in ret.get_components()] == ["numpy", "requests"]


def test_scan_py_success_pipenv() -> None:
    ret = scan("test/test_packages/python_simple_math", mode="pipenv", local_scan=True)
    assert isinstance(ret, OSSBOM)

    result = [
        "certifi",
        "charset-normalizer",
        "idna",
        "numpy",
        "requests",
        "simple_math",
        "urllib3",
    ]
    assert [comp.name for comp in ret.get_components()] == result


@pytest.mark.parametrize("mode", ["auto", "poetry"])
def test_scan_poetry_success(mode: str) -> None:
    ret = scan("test/test_packages/poetry_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)

    result = ["certifi", "charset-normalizer", "idna", "numpy", "requests", "urllib3"]
    assert [comp.name for comp in ret.get_components()] == result


@pytest.mark.parametrize("mode", ["pipenv"])
def test_scan_poetry_success_pipenv(mode: str) -> None:
    ret = scan("test/test_packages/poetry_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)

    result = [
        "certifi",
        "charset-normalizer",
        "idna",
        "numpy",
        "poetry-simple-math",
        "requests",
        "urllib3",
    ]
    assert [comp.name for comp in ret.get_components()] == result


@pytest.mark.parametrize("mode", ["npm", "auto"])
def test_scan_npm_success(mode: str) -> None:
    ret = scan("test/test_packages/npm_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)
    assert len(ret.get_components()) == 322


@pytest.mark.parametrize(["mode", "num_components"], [("yarn", 323), ("auto", 323)])
def test_scan_yarn_success(mode: str, num_components: int) -> None:
    ret = scan("test/test_packages/yarn_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)
    assert len(ret.get_components()) == num_components


def test_scan_failure() -> None:
    with pytest.raises(Exception) as excinfo:
        scan(
            "test/test_packages/python_simple_math_no_exist",
            mode="python-requirements",
            local_scan=True,
        )
    assert (
        "Package test/test_packages/python_simple_math_no_exist does not exist"
        in str(excinfo.value)
    )


def test_scan_invalid_mode() -> None:
    with pytest.raises(Exception) as excinfo:
        scan(
            "test/test_packages/python_simple_math",
            mode="invalid-mode",
            local_scan=True,
        )
    assert "Invalid scanning method" in str(excinfo.value)


def test_scan_no_package_manager(tmp_path) -> None:
    """Test that NoPackageManagerException is raised in auto mode with empty directory."""
    with pytest.raises(NoPackageManagerException):
        scan(str(tmp_path), mode="auto", local_scan=True)


def test_scan_dry_run_malicious() -> None:
    """Test that dry-run-malicious adds a vulnerability to the SBOM."""
    ret = scan(
        "test/test_packages/python_simple_math",
        mode="python-requirements",
        local_scan="dry-run-malicious",
    )
    assert isinstance(ret, OSSBOM)
    assert len(ret.vulnerabilities) == 1
    vuln = ret.vulnerabilities[0]
    assert vuln.id == "TEST-2024-0001"
    assert "numpy" in vuln.purl or "requests" in vuln.purl


def test_scan_dry_run_malicious_no_components(tmp_path) -> None:
    """Test that dry-run-malicious raises if there are no components."""
    # fs mode on empty dir yields no components
    with pytest.raises(Exception, match="No components found"):
        scan(str(tmp_path), mode="fs", local_scan="dry-run-malicious")


def test_scan_poetry_fallback_to_pipenv_on_called_process_error() -> None:
    """Test that scan_python falls back to pipenv when CalledProcessError is raised."""
    mock_sbom = OSSBOM()
    with patch("ossprey.scan.update_sbom_from_poetry") as mock_poetry, \
         patch("ossprey.scan.update_sbom_from_virtualenv", return_value=mock_sbom) as mock_venv:
        mock_poetry.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["poetry", "install"],
            output="",
            stderr="error",
        )
        modes = ["poetry"]
        result = scan_python(modes, OSSBOM(), "/tmp/test_dir")

    mock_poetry.assert_called_once()
    mock_venv.assert_called_once()
    assert "pipenv" in modes


def test_scan_with_ossprey_api(monkeypatch) -> None:
    """Test that scan calls the Ossprey API when local_scan is None."""
    from unittest.mock import MagicMock
    from ossprey.scan import scan
    from ossbom.converters.factory import SBOMConverterFactory

    mock_ossprey = MagicMock()
    mock_ossprey.validate.return_value = {"components": [], "vulnerabilities": []}

    minibom = {"components": [], "vulnerabilities": []}
    expected_sbom = OSSBOM()

    with patch("ossprey.scan.Ossprey", return_value=mock_ossprey), \
         patch("ossprey.scan.SBOMConverterFactory.to_minibom", return_value=minibom), \
         patch("ossprey.scan.SBOMConverterFactory.from_minibom", return_value=expected_sbom):
        result = scan(
            "test/test_packages/python_simple_math",
            mode="python-requirements",
            local_scan=None,
            url="https://api.example.com",
            api_key="test-key",
        )

    mock_ossprey.validate.assert_called_once_with(minibom)
    assert result is expected_sbom


def test_scan_with_ossprey_api_failure(monkeypatch) -> None:
    """Test that ScanFailedException is raised when the API returns None."""
    from ossprey.exceptions import ScanFailedException

    mock_ossprey_instance = MagicMock()
    mock_ossprey_instance.validate.return_value = None

    with patch("ossprey.scan.Ossprey", return_value=mock_ossprey_instance), \
         patch("ossprey.scan.SBOMConverterFactory.to_minibom", return_value={}):
        with pytest.raises(ScanFailedException):
            scan(
                "test/test_packages/python_simple_math",
                mode="python-requirements",
                local_scan=None,
                url="https://api.example.com",
                api_key="test-key",
            )

