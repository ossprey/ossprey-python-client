from __future__ import annotations
import logging
import logging.config
from typing import Dict, Any


def get_logging_config(log_level: int) -> Dict[str, Any]:
    LOGGING_CONFIG = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'DEBUG',
                'formatter': 'standard',
                'stream': 'ext://sys.stdout',
            },
            'file': {
                'class': 'logging.FileHandler',
                'level': 'INFO',
                'formatter': 'standard',
                'filename': 'app.log',
                'mode': 'a',
            },
        },
        'loggers': {
            '': {  # root logger
                'handlers': ['console', 'file'],
                'level': log_level,
                'propagate': True
            }
        }
    }

    return LOGGING_CONFIG


def init_logging(verbose: bool = False) -> None:
    log_level = logging.DEBUG if verbose else logging.WARNING

    config = get_logging_config(log_level)

    logging.config.dictConfig(config)
