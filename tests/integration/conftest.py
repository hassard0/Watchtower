"""Integration test config — only run when WATCHTOWER_PI_HOST is set."""
import os

import pytest


@pytest.fixture(scope="session")
def pi_host() -> str:
    h = os.environ.get("WATCHTOWER_PI_HOST")
    if not h:
        pytest.skip("set WATCHTOWER_PI_HOST=watchtower.local to run integration tests")
    return h
