import typing as t
from overtun.intyperr import Address
from overtun.utils.registers import AddressInfoRegister


class AddressInfo(t.NamedTuple):
    address: Address
    payload: t.Any


def test_address_info_register():
    register = AddressInfoRegister(
        [
            AddressInfo(Address(host, port), payload)
            for host, port, payload in [
                ("youtobe.com", 0, 7),
                ("*.youtobe.com", 0, 100),
                ("python.org", 443, 500),
                ("149.8.8.8", 0, 700),
                ("149.154.167.*", 0, 900),
                ("149.154.168.20", 80, "OK"),
            ]
        ]
    )

    assert register(Address("youtobe.com", 443)).payload == 7
    assert register(Address("ee.youtobe.com", 80)).payload == 100
    assert register(Address("python.org", 443)).payload == 500
    assert register(Address("python.org", 80)) is None
    assert register(Address("8.8.8.8", 53)) is None
    assert register(Address("149.154.167.2", 80)).payload == 900
    assert register(Address("149.154.167.200", 443)).payload == 900
    assert register(Address("149.154.168.200", 443)) is None
    assert register(Address("149.154.168.20", 443)) is None
    assert register(Address("149.154.168.20", 80)).payload == "OK"
