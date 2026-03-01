import os
from pathlib import Path

import pytest


@pytest.fixture
def hostname():
    return os.environ["HOST"]


@pytest.fixture
def username():
    return os.environ["USER"]


@pytest.fixture
def password():
    return os.environ.get("PASSWORD")


@pytest.fixture
def ppkey():
    key_file = os.environ.get("KEY_FILE")
    return Path(__file__).parent.joinpath(key_file).read_text() if key_file else None
