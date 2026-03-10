import random

import pytest


@pytest.fixture(scope="session")
def proxy_port():
    return random.randint(60000, 65000)
