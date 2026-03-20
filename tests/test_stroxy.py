import asyncio
import typing as t
from _asyncio import Task

import httpx
import pytest

from overtun.intyperr import Address
from overtun.protocols.proxy import IncomingProtocol, OutcomingProtocol

from overtun.protocols.selective import SelectiveProtocol
from overtun.utils.extractors import sni_extractor
from overtun.utils.registers import AddressInfoRegister


class AddressAllow(t.NamedTuple):
    address: Address
    allow: bool


@pytest.fixture(scope="module")
def bag():
    yield list()


async def test_sni_selective_transparent_proxy(bag):
    # Для этого теста/примера надо включить перенаправление исходящего трафика с 8443 на 10443
    # sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to-destination 127.0.0.1:10443

    address_info_register = AddressInfoRegister[AddressAllow](
        [
            AddressAllow(Address(host, 443), allow)
            for host, allow in [
                ("python.org", True),
                ("reclame.com", False),
            ]
        ]
    )

    proxy_address = Address("127.0.0.1", 10443)
    outlet_address = Address("127.0.0.1", 20443)

    loop = asyncio.get_event_loop()

    # Сборка и запуск тестовых серверов

    class OutletProtocol(IncomingProtocol):
        def create_target_connection(self, target: Address) -> Task[OutcomingProtocol] | None:
            bag.append(("outlet", target))
            return super().create_target_connection(target)

    outlet_server = await loop.create_server(
        lambda: OutletProtocol(lambda data: sni_extractor(data, 443)), *outlet_address
    )

    class ProxyProtocol(SelectiveProtocol):
        def create_target_connection(self, target: Address) -> Task[OutcomingProtocol] | None:
            bag.append(("proxy", target))
            return super().create_target_connection(target)

    proxy_server = await loop.create_server(
        lambda: ProxyProtocol(lambda data: sni_extractor(data, 443), address_info_register, outlet_address),
        *proxy_address,
    )

    async with proxy_server:
        async with outlet_server:
            await proxy_server.start_serving()
            await outlet_server.start_serving()

            # Тестовые запросы

            # Идет через туннель
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://python.org:8443/index.html")
                assert resp.status_code == 301

            # Идет минуя туннель
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://www.opennet.ru:8443/index.html")
                assert resp.status_code == 200

    assert bag == [
        ("proxy", Address(host="python.org", port=443)),
        ("outlet", Address(host="python.org", port=443)),
        ("proxy", Address(host="www.opennet.ru", port=443)),
    ]
