import pytest

from overtun.handlers import proxy_handler, outlet_handler


def test_proxy_handler(chromium_preamble):
    result = proxy_handler(chromium_preamble, None)
    assert result
    address, preamble = result
    assert address.host == "www.google.com"
    assert chromium_preamble == preamble


@pytest.fixture(scope="module")
def bag():
    yield list()


def test_tunnel_handler(chromium_preamble, bag):
    result = proxy_handler(chromium_preamble)
    assert result
    address, preamble = result
    assert address.host == "www.google.com"
    assert chromium_preamble == preamble
    bag.append(preamble)


def test_outlet_handler(chromium_preamble, secret_key, bag):
    if len(bag) == 0:
        test_tunnel_handler(chromium_preamble, bag)
    encoded_preamble = bag[0]
    result = outlet_handler(encoded_preamble, secret_key)
    assert result
    address, preamble = result
    assert address.host == "www.google.com"
    assert chromium_preamble == preamble
