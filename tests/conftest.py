import logging

import pytest

from overtun.primitives import Address


@pytest.fixture
def debug_on():
    logging.getLogger("overtun").setLevel(logging.DEBUG)
    yield
    logging.getLogger("overtun").setLevel(logging.WARNING)


@pytest.fixture
def proxy_address():
    return Address("127.0.0.1", 10443)


@pytest.fixture
def outlet_address():
    return Address("127.0.0.1", 20443)
