from __future__ import annotations

import os
import pytest
import tempfile

from unittest.mock import patch, MagicMock

from ossprey.github_actions_reporter import (
    print_gh_action_errors,
    get_component_reference,
    append_to_github_output,
    can_report_to_github,
    post_comments_to_pull_request,
    post_comment_to_github_summary,
)
from ossbom.model.ossbom import OSSBOM
from ossprey.github_actions_reporter import GitHubDetails


def test_no_vulnerabilities():
    sbom = OSSBOM()
    sbom.vulnerabilities = []
    package_path = "test/path"

    with patch("builtins.print") as mock_print, patch("ossprey.github_actions_reporter.append_to_github_output") as mock_append:
        result = print_gh_action_errors(sbom, package_path)

        mock_print.assert_called_with("No malware found")
        mock_append.assert_called_once_with(False, "false")
        assert result is True


@pytest.mark.parametrize("post_to_github", [False, True])
def test_with_vulnerabilities(post_to_github):
    sbom = OSSBOM()
    sbom.vulnerabilities = [MagicMock(purl="pkg:pypi/testpkg@1.0.0")]
    package_path = "test/path"

    github_mock = GitHubDetails(
        is_pull_request=True,
        token=None,
        repo="repo",
        pull_number=1,
        commit_sha="sha"
    )
    with patch("ossprey.github_actions_reporter.create_github_details", return_value=github_mock), \
         patch("builtins.print") as mock_print, \
         patch("ossprey.github_actions_reporter.get_component_reference", return_value=("file.py", 10)), \
         patch("ossprey.github_actions_reporter.append_to_github_output") as mock_append, \
         patch("ossprey.github_actions_reporter.post_comments_to_pull_request"), \
         patch("ossprey.github_actions_reporter.post_comment_to_github_summary"):

        result = print_gh_action_errors(sbom, package_path, post_to_github)

        mock_print.assert_any_call("Error: WARNING: testpkg:1.0.0 contains malware. Remediate this immediately")

        if post_to_github:
            mock_print.assert_any_call("::error file=file.py,line=10::WARNING: testpkg:1.0.0 contains malware. Remediate this immediately")
            mock_append.assert_any_call(True, "true")
        else:
            mock_append.assert_called_once_with(True, "true")
        assert result is False


def test_with_github_posting():
    sbom = OSSBOM()
    sbom.vulnerabilities = [MagicMock(purl="pkg:pypi/testpkg@1.0.0")]
    package_path = "test/path"
    details_mock = MagicMock(is_pull_request=True, token="token", repo="repo", pull_number=1, commit_sha="sha")

    with patch("ossprey.github_actions_reporter.create_github_details", return_value=details_mock), \
         patch("ossprey.github_actions_reporter.get_component_reference", return_value=("file.py", 10)), \
         patch("ossprey.github_actions_reporter.append_to_github_output") as mock_append, \
         patch("ossprey.github_actions_reporter.post_comments_to_pull_request") as mock_post_comment, \
         patch("ossprey.github_actions_reporter.post_comment_to_github_summary") as mock_post_summary:

        result = print_gh_action_errors(sbom, package_path, post_to_github=True)

        mock_append.assert_called_with(True, "true")
        mock_post_comment.assert_called_once_with("token", "repo", 1, "sha", "WARNING: testpkg:1.0.0 contains malware. Remediate this immediately", "file.py", 10)
        mock_post_summary.assert_called_once_with("token", "repo", 1, "WARNING: testpkg:1.0.0 contains malware. Remediate this immediately")
        assert result is False


def test_print_gh_action_errors_no_git():
    """Test that post_to_github is skipped when git is not available."""
    sbom = OSSBOM()
    sbom.vulnerabilities = [MagicMock(purl="pkg:pypi/testpkg@1.0.0")]

    with patch("ossprey.github_actions_reporter.can_report_to_github", return_value=False), \
         patch("ossprey.github_actions_reporter.create_github_details") as mock_create, \
         patch("ossprey.github_actions_reporter.get_component_reference", return_value=(None, None)), \
         patch("ossprey.github_actions_reporter.append_to_github_output"):
        result = print_gh_action_errors(sbom, "test/path", post_to_github=True)

    mock_create.assert_not_called()
    assert result is False


def test_get_component_reference_found(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("numpy==1.24.0\nrequests==2.31.0\n")

    file_path, line_num = get_component_reference("numpy", str(tmp_path))

    assert file_path == str(req)
    assert line_num == 1


def test_get_component_reference_not_found(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("numpy==1.24.0\n")

    file_path, line_num = get_component_reference("nonexistent-pkg", str(tmp_path))

    assert file_path is None
    assert line_num is None


def test_get_component_reference_no_files(tmp_path):
    file_path, line_num = get_component_reference("numpy", str(tmp_path))

    assert file_path is None
    assert line_num is None


def test_get_component_reference_setup_py(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text("install_requires=['requests>=2.0']\n")

    file_path, line_num = get_component_reference("requests", str(tmp_path))

    assert file_path == str(setup)
    assert line_num == 1


def test_append_to_github_output_with_env(tmp_path, monkeypatch):
    output_file = tmp_path / "github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    append_to_github_output("malware_found", "true")

    content = output_file.read_text()
    assert "malware_found=true\n" in content


def test_append_to_github_output_without_env(monkeypatch):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    # Should not raise even without GITHUB_OUTPUT set
    append_to_github_output("malware_found", "true")


def test_can_report_to_github_with_git():
    with patch("shutil.which", return_value="/usr/bin/git"):
        assert can_report_to_github() is True


def test_can_report_to_github_without_git():
    with patch("shutil.which", return_value=None):
        assert can_report_to_github() is False


def test_post_comments_to_pull_request_success():
    mock_response = MagicMock()
    mock_response.status_code = 201

    with patch("requests.post", return_value=mock_response) as mock_post:
        post_comments_to_pull_request("token", "org/repo", "1", "abc123", "malware found", "requirements.txt", 5)

    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert "https://api.github.com/repos/org/repo/pulls/1/comments" in call_kwargs[0]


def test_post_comments_to_pull_request_failure(capsys):
    mock_response = MagicMock()
    mock_response.status_code = 422
    mock_response.json.return_value = {"message": "Unprocessable Entity"}

    with patch("requests.post", return_value=mock_response):
        post_comments_to_pull_request("token", "org/repo", "1", "abc123", "malware found", "requirements.txt", 5)

    captured = capsys.readouterr()
    assert "422" in captured.out


def test_post_comment_to_github_summary_success(capsys):
    mock_response = MagicMock()
    mock_response.status_code = 201

    with patch("requests.post", return_value=mock_response):
        post_comment_to_github_summary("token", "org/repo", "1", "malware found")

    captured = capsys.readouterr()
    assert "Comment added successfully." in captured.out


def test_post_comment_to_github_summary_failure(capsys):
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"message": "Forbidden"}

    with patch("requests.post", return_value=mock_response):
        post_comment_to_github_summary("token", "org/repo", "1", "malware found")

    captured = capsys.readouterr()
    assert "403" in captured.out


def test_get_component_reference_file_read_error(tmp_path, capsys):
    """Test that get_component_reference handles file read errors gracefully."""
    req = tmp_path / "requirements.txt"
    req.write_text("numpy==1.24.0\n")

    with patch("builtins.open", side_effect=OSError("permission denied")):
        file_path, line_num = get_component_reference("numpy", str(tmp_path))

    assert file_path is None
    assert line_num is None
    captured = capsys.readouterr()
    assert "Error reading file" in captured.out


def test_create_github_details_non_pr(monkeypatch):
    """Test create_github_details for a non-pull-request event."""
    from ossprey.github_actions_reporter import create_github_details

    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")

    details = create_github_details()

    assert details.token == "test-token"
    assert details.repo == "org/repo"
    assert details.is_pull_request is False
    assert details.commit_sha is None


def test_create_github_details_pull_request_non_numeric(monkeypatch):
    """Test create_github_details for a pull_request event with non-numeric pull number."""
    from ossprey.github_actions_reporter import create_github_details

    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/main/merge")

    details = create_github_details()

    assert details.is_pull_request is True
    assert details.commit_sha is None


def test_create_github_details_pull_request_with_pr_number(monkeypatch):
    """Test create_github_details for a pull_request event with a numeric PR number."""
    from ossprey.github_actions_reporter import create_github_details

    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/42/merge")

    mock_pr = MagicMock()
    mock_pr.head.sha = "abc123def456"
    mock_repo = MagicMock()
    mock_repo.get_pull.return_value = mock_pr
    mock_repo.full_name = "org/repo"
    mock_github_instance = MagicMock()
    mock_github_instance.get_repo.return_value = mock_repo

    with patch("github.Github", return_value=mock_github_instance):
        details = create_github_details()

    assert details.is_pull_request is True
    assert details.commit_sha == "abc123def456"
    assert details.pull_number == "42"
