"""Fixtures and markers for ossprey smoke tests."""

from __future__ import annotations

import os
import pytest
from pathlib import Path


def pytest_configure(config):
    config.addinivalue_line("markers", "smoke: mark test as a smoke test")
    config.addinivalue_line("markers", "slow: mark test as slow (installs packages)")
    config.addinivalue_line("markers", "network: mark test as requiring network access")


@pytest.fixture
def project_root() -> Path:
    """Return the absolute path to the project root."""
    return Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def test_packages_dir(project_root) -> Path:
    """Return the absolute path to test/test_packages/."""
    return project_root / "test" / "test_packages"


@pytest.fixture
def has_api_key() -> bool:
    """Check if API_KEY env var is set."""
    return bool(os.environ.get("API_KEY"))
