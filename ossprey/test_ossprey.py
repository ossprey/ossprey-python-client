from __future__ import annotations

import pytest
import requests
from unittest.mock import patch, MagicMock

from ossprey.ossprey import Ossprey
from ossprey.exceptions import (
    MissingAPIKeyException,
    MissingSBOMException,
    ScanFailedException,
    ScanTimeoutException,
)


def test_ossprey_init_success():
    """Test that Ossprey can be created with a valid API key."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")
    assert ossprey.api_url == "https://api.example.com"
    assert ossprey.api_key == "test-api-key"
    assert ossprey.session is not None


def test_ossprey_init_missing_api_key():
    """Test that MissingAPIKeyException is raised when API key is None."""
    with pytest.raises(MissingAPIKeyException):
        Ossprey("https://api.example.com", None)


def test_ossprey_init_empty_api_key():
    """Test that MissingAPIKeyException is raised when API key is empty."""
    with pytest.raises(MissingAPIKeyException):
        Ossprey("https://api.example.com", "")


def test_create_session_returns_session():
    """Test that create_session returns a requests.Session."""
    session = Ossprey.create_session()
    assert isinstance(session, requests.Session)


def test_create_session_has_retry_adapter():
    """Test that the session has retry adapters mounted."""
    session = Ossprey.create_session()
    assert "http://" in session.adapters
    assert "https://" in session.adapters


def test_validate_200():
    """Test that validate returns the JSON response on status 200."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "clean"}

    with patch.object(ossprey, "submit", return_value=mock_response):
        result = ossprey.validate({"test": "data"})

    assert result == {"result": "clean"}


def test_validate_202_calls_wait_for_completion():
    """Test that validate calls wait_for_completion on status 202."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 202
    mock_response.json.return_value = {"sbom_id": "sbom-123", "scan_id": "scan-456"}

    expected_result = {"components": []}
    with patch.object(ossprey, "submit", return_value=mock_response), \
         patch.object(ossprey, "wait_for_completion", return_value=expected_result) as mock_wait:
        result = ossprey.validate({"test": "data"})
        mock_wait.assert_called_once_with("sbom-123", "scan-456")

    assert result == expected_result


def test_validate_429_returns_none():
    """Test that validate returns None on 429 rate limit."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 429

    with patch.object(ossprey, "submit", return_value=mock_response):
        result = ossprey.validate({"test": "data"})

    assert result is None


def test_validate_500_returns_none():
    """Test that validate returns None on unexpected server error."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {"message": "Internal server error"}

    with patch.object(ossprey, "submit", return_value=mock_response):
        result = ossprey.validate({"test": "data"})

    assert result is None


def test_validate_error_response_with_message():
    """Test that validate logs the message from the error response."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"message": "Bad request details"}

    with patch.object(ossprey, "submit", return_value=mock_response):
        result = ossprey.validate({"test": "data"})

    assert result is None


def test_submit_sends_correct_request():
    """Test that submit sends a POST request to the correct endpoint."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch.object(ossprey.session, "post", return_value=mock_response) as mock_post:
        response = ossprey.submit({"test": "data"})

    mock_post.assert_called_once()
    url = mock_post.call_args[0][0]
    assert url == "https://api.example.com/public/v1/scans"

    headers = mock_post.call_args[1]["headers"]
    assert headers["x-api-key"] == "test-api-key"
    assert headers["Content-Type"] == "application/json"

    assert response == mock_response


def test_wait_for_completion_succeeded_with_output():
    """Test that wait_for_completion returns output on SUCCEEDED status."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "SUCCEEDED", "output": {"components": []}}

    with patch.object(ossprey.session, "get", return_value=mock_response), \
         patch("time.sleep"):
        result = ossprey.wait_for_completion("sbom-123", "scan-456")

    assert result == {"components": []}


def test_wait_for_completion_succeeded_no_output_raises():
    """Test that MissingSBOMException is raised when SUCCEEDED but no output."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "SUCCEEDED"}

    with patch.object(ossprey.session, "get", return_value=mock_response), \
         patch("time.sleep"):
        with pytest.raises(MissingSBOMException):
            ossprey.wait_for_completion("sbom-123", "scan-456")


def test_wait_for_completion_error_status_raises():
    """Test that ScanFailedException is raised when the status endpoint returns an error."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 500

    with patch.object(ossprey.session, "get", return_value=mock_response), \
         patch("time.sleep"):
        with pytest.raises(ScanFailedException):
            ossprey.wait_for_completion("sbom-123", "scan-456")


def test_wait_for_completion_timeout_raises():
    """Test that ScanTimeoutException is raised after exhausting retries."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 202
    mock_response.json.return_value = {"status": "RUNNING"}

    with patch.object(ossprey.session, "get", return_value=mock_response), \
         patch("time.sleep"):
        with pytest.raises(ScanTimeoutException):
            ossprey.wait_for_completion("sbom-123", "scan-456")


def test_wait_for_completion_polls_correct_url():
    """Test that wait_for_completion polls the correct status URL with correct params."""
    ossprey = Ossprey("https://api.example.com", "test-api-key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "SUCCEEDED", "output": {"data": "value"}}

    with patch.object(ossprey.session, "get", return_value=mock_response) as mock_get, \
         patch("time.sleep"):
        ossprey.wait_for_completion("sbom-abc", "scan-xyz")

    mock_get.assert_called()
    call_kwargs = mock_get.call_args[1]
    assert call_kwargs["params"] == {"sbom_id": "sbom-abc", "scan_id": "scan-xyz"}
    assert call_kwargs["headers"]["x-api-key"] == "test-api-key"
