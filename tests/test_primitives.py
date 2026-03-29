from ipaddress import IPv4Address, IPv6Address

import pytest

import overtun.intyperr as tt
from overtun.primitives import Address


def test_address():
    address = Address.parse("127.0.0.1:443")
    assert address == (IPv4Address("127.0.0.1"), 443)
    assert isinstance(address, tt.Address)
    assert address == Address.parse("127.0.0.1", 443)

    address = Address.parse("[::1]:80")
    assert address == (IPv6Address("::1"), 80)
    assert isinstance(address, tt.Address)
    assert address == Address.parse("::1", 80)

    address = Address.parse("youto.be:443")
    assert address == ("youto.be", 443)
    assert isinstance(address, tt.Address)
    assert address == Address.parse("youto.be", 443)

    with pytest.raises(TypeError):
        Address.parse(100500)

    with pytest.raises(ValueError):
        Address.parse("127.0.0.1")

    with pytest.raises(ValueError):
        Address.parse("127.0.0.300:443")

    with pytest.raises(ValueError):
        Address.parse("::443")
