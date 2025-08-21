from __future__ import annotations
from ossprey.scan import scan
from ossbom.model.ossbom import OSSBOM
import pytest


@pytest.mark.parametrize("mode", ["python-requirements", "auto"])
def test_scan_py_success(mode: str) -> None:
    ret = scan("test/python_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)
    assert [comp.name for comp in ret.get_components()] == ["numpy", "requests"]


def test_scan_py_success_pipenv() -> None:
    ret = scan("test/python_simple_math", mode="pipenv", local_scan=True)
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
    ret = scan("test/poetry_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)

    result = ["certifi", "charset-normalizer", "idna", "numpy", "requests", "urllib3"]
    assert [comp.name for comp in ret.get_components()] == result


@pytest.mark.parametrize("mode", ["pipenv"])
def test_scan_poetry_success_pipenv(mode: str) -> None:
    ret = scan("test/poetry_simple_math", mode=mode, local_scan=True)
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
    ret = scan("test/npm_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)
    assert len(ret.get_components()) == 322


@pytest.mark.parametrize(["mode", "num_components"], [("yarn", 323), ("auto", 323)])
def test_scan_yarn_success(mode: str, num_components: int) -> None:
    ret = scan("test/yarn_simple_math", mode=mode, local_scan=True)
    assert isinstance(ret, OSSBOM)
    assert len(ret.get_components()) == num_components


def test_scan_failure() -> None:
    with pytest.raises(Exception) as excinfo:
        scan(
            "test/python_simple_math_no_exist",
            mode="python-requirements",
            local_scan=True,
        )
    assert "Package test/python_simple_math_no_exist does not exist" in str(
        excinfo.value
    )


def test_scan_invalid_mode() -> None:
    with pytest.raises(Exception) as excinfo:
        scan("test/python_simple_math", mode="invalid-mode", local_scan=True)
    assert "Invalid scanning method" in str(excinfo.value)
