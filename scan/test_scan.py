import pytest

from scan.scan import main


def test_main_function(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["script.py"])
    monkeypatch.setenv("INPUT_PACKAGE", "test/python_simple_math")
    monkeypatch.setenv("INPUT_MODE", "python-requirements")
    monkeypatch.setenv("INPUT_DRY_RUN", "True")

    main()

    captured = capsys.readouterr()
    print(captured.out)
    assert "No vulnerabilities found" in captured.out


@pytest.mark.parametrize("soft_error, expected_ret", [
    ("True", 0),
    ("False", 1)])
def test_main_function_soft_error(monkeypatch, soft_error, expected_ret):
    monkeypatch.setattr("sys.argv", ["script.py"])
    monkeypatch.setenv("INPUT_PACKAGE", "test/python_simple_math_no_exist")
    monkeypatch.setenv("INPUT_MODE", "python-requirements")
    monkeypatch.setenv("INPUT_DRY_RUN", "True")
    monkeypatch.setenv("INPUT_SOFT_ERROR", soft_error)

    ret = main()

    assert ret == expected_ret
