import pytest

from argparse import Namespace
from scan.args import parse_arguments


@pytest.fixture(autouse=True)
def set_ossprey_api_key(monkeypatch):
    monkeypatch.setenv("API_KEY", "SPECIAL_KEY")


@pytest.mark.parametrize(
    "cli_args,env_vars,expected",
    [
        # Test case 1: CLI only
        (
            ["script.py", "--url", "https://example.com", "--mode", "pipenv", "--verbose"],
            {},
            Namespace(
                url="https://example.com",
                package="",
                dry_run=False,
                github_comments=False,
                verbose=True,
                mode="pipenv",
                api_key="SPECIAL_KEY",
                soft_error=False,
            ),
        ),
        # Test case 2: Environment variable fallback
        (
            ["script.py", "--mode", "python-requirements"],
            {"INPUT_URL": "https://env-url.com", "INPUT_DRY_RUN": "true"},
            Namespace(
                url="https://env-url.com",
                package="",
                dry_run=True,
                github_comments=False,
                verbose=False,
                mode="python-requirements",
                api_key="SPECIAL_KEY",
                soft_error=False,
            ),
        ),
        # Test case 3: CLI overrides environment variables
        (
            ["script.py", "--url", "https://cli-url.com", "--dry-run", "--mode", "pipenv", "--api-key", "UNSPECIAL_KEY"],
            {"INPUT_URL": "https://env-url.com", "INPUT_DRY_RUN": "false"},
            Namespace(
                url="https://cli-url.com",
                package="",
                dry_run=True,
                github_comments=False,
                verbose=False,
                mode="pipenv",
                api_key="UNSPECIAL_KEY",
                soft_error=False,
            ),
        ),
        # Test case 4: Handles only env vars
        (
            ["script.py"],
            {"INPUT_URL": "https://env-url.com", "INPUT_PACKAGE": "newtest", "INPUT_MODE": "pipenv"},
            Namespace(
                url="https://env-url.com",
                package="newtest",
                dry_run=False,
                github_comments=False,
                verbose=False,
                mode="pipenv",
                api_key="SPECIAL_KEY",
                soft_error=False,
            ),
        ),
    ],
)
def test_parse_arguments(monkeypatch, cli_args, env_vars, expected):
    # Mock sys.argv
    monkeypatch.setattr("sys.argv", cli_args)

    # Mock environment variables
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    # Call the parser
    args = parse_arguments()

    # Assert the parsed arguments match the expected result
    assert vars(args) == vars(expected)


def test_mutually_exclusive_group_error(monkeypatch):
    # Mock sys.argv with no mutually exclusive arguments
    monkeypatch.setattr("sys.argv", ["script.py"])

    # Assert that the script raises a SystemExit error due to missing required arguments
    with pytest.raises(SystemExit) as excinfo:
        parse_arguments()

    # Validate the exit code and error message
    assert excinfo.value.code == 2  # argparse exits with code 2 for argument parsing errors


def test_mode_only_accepts_approved_values(monkeypatch):
    # Mock sys.argv with no mutually exclusive arguments
    monkeypatch.setattr("sys.argv", ["script.py", "--mode", "invalid"])

    # Assert that the script raises a SystemExit error due to missing required arguments
    with pytest.raises(SystemExit) as excinfo:
        parse_arguments()

    # Validate the exit code and error message
    assert excinfo.value.code == 2  # argparse exits with code 2 for argument parsing errors
