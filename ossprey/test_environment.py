from __future__ import annotations

import subprocess
from unittest.mock import patch, MagicMock

from ossprey.environment import (
    get_current_git_branch,
    get_codespace_environment,
    get_gh_actions_environment,
    get_environment_details,
)
from ossbom.model.environment import Environment


def test_get_current_git_branch_success():
    """Test that get_current_git_branch returns a branch name on success."""
    mock_result = MagicMock()
    mock_result.stdout = "main\n"
    with patch("subprocess.run", return_value=mock_result):
        result = get_current_git_branch()
    assert result == "main"


def test_get_current_git_branch_no_git():
    """Test that None is returned when git binary is not available."""
    with patch("shutil.which", return_value=None):
        result = get_current_git_branch()
    assert result is None


def test_get_current_git_branch_called_process_error():
    """Test that None is returned on CalledProcessError (not a git repo)."""
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(128, ["git"])):
        result = get_current_git_branch()
    assert result is None


def test_get_current_git_branch_with_path():
    """Test that get_current_git_branch can accept a custom path."""
    mock_result = MagicMock()
    mock_result.stdout = "feature-branch\n"
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        result = get_current_git_branch("/some/path")
    assert result == "feature-branch"
    call_args = mock_run.call_args[0][0]
    assert "-C" in call_args
    assert "/some/path" in call_args


def test_get_codespace_environment(monkeypatch):
    """Test environment creation in Codespaces mode."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")
    monkeypatch.setenv("CODESPACE_NAME", "my-codespace")

    with patch("ossprey.environment.get_current_git_branch", return_value="feature-branch"):
        env = get_codespace_environment("my_package")

    assert env is not None


def test_get_gh_actions_environment(monkeypatch):
    """Test environment creation in GitHub Actions mode."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")

    env = get_gh_actions_environment("my_package")

    assert env is not None


def test_get_gh_actions_environment_no_ref(monkeypatch):
    """Test GitHub Actions environment creation without GITHUB_REF_NAME."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)

    env = get_gh_actions_environment("my_package")

    assert env is not None


def test_get_environment_details_codespaces(monkeypatch):
    """Test that get_environment_details uses codespace environment when CODESPACES is set."""
    monkeypatch.setenv("CODESPACES", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")
    monkeypatch.setenv("CODESPACE_NAME", "my-codespace")

    with patch("ossprey.environment.get_current_git_branch", return_value="main"):
        env = get_environment_details("my_package")

    assert env is not None


def test_get_environment_details_github_actions(monkeypatch):
    """Test that get_environment_details uses GitHub Actions environment."""
    monkeypatch.delenv("CODESPACES", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")

    env = get_environment_details("my_package")

    assert env is not None


def test_get_environment_details_local(monkeypatch):
    """Test that get_environment_details returns a default Environment when neither is set."""
    monkeypatch.delenv("CODESPACES", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    env = get_environment_details("my_package")

    assert isinstance(env, Environment)
