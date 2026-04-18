import pytest

from overtun.primitives import Address


@pytest.fixture
def proxy_address():
    return Address.parse("127.0.0.1", 10443)
