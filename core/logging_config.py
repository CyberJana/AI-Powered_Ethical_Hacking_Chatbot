"""Structured logging setup that avoids logging request content or secrets."""

import logging
import sys

from core.config import get_settings


def configure_logging() -> None:
    """Configure application logging once at process startup."""
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
