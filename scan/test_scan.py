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
