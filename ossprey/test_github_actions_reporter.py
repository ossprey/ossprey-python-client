from unittest.mock import patch, MagicMock

from ossprey.github_actions_reporter import print_gh_action_errors
from ossbom.model.ossbom import OSSBOM


def test_no_vulnerabilities():
    sbom = OSSBOM()
    sbom.vulnerabilities = []
    package_path = "test/path"
    
    with patch("builtins.print") as mock_print, patch("ossprey.github_actions_reporter.append_to_github_output") as mock_append:
        result = print_gh_action_errors(sbom, package_path)
        
        mock_print.assert_called_with("No vulnerabilities found")
        mock_append.assert_called_once_with(False, "false")
        assert result is True


def test_with_vulnerabilities():
    sbom = OSSBOM()
    sbom.vulnerabilities = [MagicMock(purl="pkg:pypi/testpkg@1.0.0")]
    package_path = "test/path"
    
    with patch("builtins.print") as mock_print, \
         patch("ossprey.github_actions_reporter.get_component_reference", return_value=("file.py", 10)), \
         patch("ossprey.github_actions_reporter.append_to_github_output") as mock_append:
        
        result = print_gh_action_errors(sbom, package_path)
        
        mock_print.assert_any_call("Error: WARNING: testpkg:1.0.0 contains malware. Remediate this immediately")
        mock_print.assert_any_call("::error file=file.py,line=10::WARNING: testpkg:1.0.0 contains malware. Remediate this immediately")
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
