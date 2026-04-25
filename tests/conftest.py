import pytest

from overtun.primitives import Address


@pytest.fixture
def proxy_address():
    return Address.parse("127.0.0.1", 10443)


@pytest.fixture
def egress_address():
    return Address.parse("127.0.0.1", 20443)


@pytest.fixture
def secret_key():
    return b"0123456789ABCDEF0123456789ABCDEF"
