"""Unit tests for SUBMISSION_MODE fail-safe enforcement.

Verifies that when SUBMISSION_MODE is enabled (via environment or settings),
VIGIL refuses to start if ARMORIQ_MODE is not 'live'.
"""

import asyncio
import os
import pytest
from unittest.mock import patch
from fastapi import FastAPI

from backend.main import lifespan
from backend.app.config import settings


def test_submission_mode_rejects_local_demo():
    """VIGIL must raise RuntimeError on startup when SUBMISSION_MODE=1 and ARMORIQ_MODE=local-demo."""
    async def _run():
        app = FastAPI()
        with patch.object(settings, "submission_mode", True):
            with patch.object(settings, "armoriq_mode", "local-demo"):
                with pytest.raises(RuntimeError) as exc_info:
                    async with lifespan(app):
                        pass
                assert "SUBMISSION_MODE is active but ARMORIQ_MODE is 'local-demo'" in str(exc_info.value)

    asyncio.run(_run())


def test_submission_mode_rejects_disabled():
    """VIGIL must raise RuntimeError on startup when SUBMISSION_MODE=1 and ARMORIQ_MODE=disabled."""
    async def _run():
        app = FastAPI()
        with patch.object(settings, "submission_mode", True):
            with patch.object(settings, "armoriq_mode", "disabled"):
                with pytest.raises(RuntimeError) as exc_info:
                    async with lifespan(app):
                        pass
                assert "SUBMISSION_MODE is active but ARMORIQ_MODE is 'disabled'" in str(exc_info.value)

    asyncio.run(_run())


def test_submission_mode_env_var_triggers_rejection(monkeypatch):
    """VIGIL must detect SUBMISSION_MODE=1 via environment variable."""
    async def _run():
        app = FastAPI()
        monkeypatch.setenv("SUBMISSION_MODE", "1")
        with patch.object(settings, "submission_mode", False):
            with patch.object(settings, "armoriq_mode", "mock"):
                with pytest.raises(RuntimeError) as exc_info:
                    async with lifespan(app):
                        pass
                assert "SUBMISSION_MODE is active but ARMORIQ_MODE is 'mock'" in str(exc_info.value)

    asyncio.run(_run())
