from __future__ import annotations

import logging

from ossprey.log import get_logging_config, init_logging


def test_get_logging_config_debug():
    config = get_logging_config(logging.DEBUG)

    assert config["version"] == 1
    assert "handlers" in config
    assert "console" in config["handlers"]
    assert "file" in config["handlers"]
    assert "" in config["loggers"]
    assert config["loggers"][""]["level"] == logging.DEBUG
    assert config["disable_existing_loggers"] is False


def test_get_logging_config_warning():
    config = get_logging_config(logging.WARNING)

    assert config["loggers"][""]["level"] == logging.WARNING


def test_get_logging_config_has_formatter():
    config = get_logging_config(logging.INFO)

    assert "formatters" in config
    assert "standard" in config["formatters"]
    assert "format" in config["formatters"]["standard"]


def test_get_logging_config_console_handler():
    config = get_logging_config(logging.DEBUG)

    console = config["handlers"]["console"]
    assert console["class"] == "logging.StreamHandler"
    assert console["stream"] == "ext://sys.stdout"


def test_get_logging_config_file_handler():
    config = get_logging_config(logging.DEBUG)

    file_handler = config["handlers"]["file"]
    assert file_handler["class"] == "logging.FileHandler"
    assert file_handler["filename"] == "app.log"


def test_init_logging_verbose():
    """Test that verbose mode enables DEBUG logging."""
    init_logging(verbose=True)
    root_logger = logging.getLogger("")
    assert root_logger.level == logging.DEBUG


def test_init_logging_non_verbose():
    """Test that non-verbose mode uses WARNING level."""
    init_logging(verbose=False)
    root_logger = logging.getLogger("")
    assert root_logger.level == logging.WARNING
