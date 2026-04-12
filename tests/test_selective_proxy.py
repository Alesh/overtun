import contextlib
import logging
import typing as t
from ipaddress import IPv4Address

import httpx
import pytest

from overtun.servers import create_proxy, create_outlet
from overtun.handlers import outlet_handler, proxy_handler
from overtun.primitives import Address, TargetDesc, TrafficRule
from tests.utils import requirements_note, TEST_TRANSPARENT_REQUIREMENTS


@pytest.fixture
async def selective_proxy(proxy_address, outlet_address):

    def target_registry(address: Address) -> TargetDesc | None:
        match address:
            case Address("mail.ru", 443):
                return TargetDesc(address, TrafficRule.TUNNEL)
            case Address("ok.ru", 443):
                return TargetDesc(address, TrafficRule.DROP)

    @contextlib.asynccontextmanager
    async def selective_proxy_context(secret_key: bytes, bag: list[t.Any] | None = None):

        class Handlers[A]:
            @staticmethod
            def outlet_handler(*args, **kwargs):
                if result := outlet_handler(*args, **kwargs):
                    address, data = result
                    bag.append((outlet_address, address))
                    return address, data
                return None

            @staticmethod
            def proxy_handler(*args, **kwargs):
                if result := proxy_handler(*args, **kwargs):
                    address, data = result
                    bag.append((proxy_address, address))
                    return address, data
                return None

        outlet_server = await create_outlet(outlet_address, secret_key, Handlers())
        proxy_server = await create_proxy(
            proxy_address, outlet_address, secret_key, target_registry, handlers=Handlers()
        )
        async with outlet_server:
            await outlet_server.start_serving()
            async with proxy_server:
                await proxy_server.start_serving()
                yield proxy_address

    return selective_proxy_context


async def test_selective_server(selective_proxy, secret_key, caplog):
    bag = list()
    caplog.set_level(logging.WARNING)

    async with selective_proxy(secret_key, bag) as address:
        # HTTP CONNECT PROXY
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("https://mail.ru")
            assert resp.status_code == 302

        with pytest.raises(httpx.ConnectError):
            async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
                resp = await client.get("https://ok.ru")
                assert resp.status_code == 200

        # Transparent HTTPS Proxy
        with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_REQUIREMENTS):
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://vk.ru:8443")
                assert resp.status_code == 302

    assert bag == [
        (Address(IPv4Address("127.0.0.1"), 10443), Address("mail.ru", 443)),
        (Address(IPv4Address("127.0.0.1"), 20443), Address("mail.ru", 443)),
        (Address(IPv4Address("127.0.0.1"), 10443), Address("ok.ru", 443)),
        (Address(IPv4Address("127.0.0.1"), 10443), Address("vk.ru", 443)),
    ]
    assert all("ok.ru:443 banned by rule" in s[2] for s in caplog.record_tuples)
