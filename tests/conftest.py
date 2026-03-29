import pytest

from overtun.intyperr import Address


@pytest.fixture
def proxy_address():
    return Address("127.0.0.1", 10443)


@pytest.fixture
def outlet_address():
    return Address("127.0.0.1", 20443)
