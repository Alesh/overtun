import asyncio
import contextlib
import logging
import typing as t

import httpx
import pytest

from overtun.primitives import Address, TargetRule
from overtun.protocols.special import EgressProtocol, ProxyProtocol
from overtun.utils import default_logger

default_logger.setLevel(logging.WARNING)


@pytest.fixture
def rule_register():
    return {
        Address("ok.ru", 443): (TargetRule.DROP, None),
        Address("vk.ru", 443): (TargetRule.TUNNEL, None),
    }


@pytest.fixture
def accum():
    return []


@pytest.fixture
async def start_special_proxy(proxy_address, egress_address, secret_key, rule_register):
    """Returns a context with a running selective tunneling proxy server.
    The context variable contains the address of this server.
    """

    def mocks_protocol(protocol, accum):
        orig_method = protocol.create_outgoing_connection

        async def create_outgoing_connection(address: Address):
            try:
                result = await orig_method(address)
                accum.append((protocol.transport.get_extra_info("sockname"), address, True))
                return result
            except Exception as exc:
                accum.append((protocol.transport.get_extra_info("sockname"), address, type(exc)))
                raise

        protocol.create_outgoing_connection = create_outgoing_connection
        return protocol

    @contextlib.asynccontextmanager
    async def server_context(accum: list[t.Any]):
        loop = asyncio.get_event_loop()
        address, port = proxy_address
        proxy_server = await loop.create_server(
            lambda: mocks_protocol(
                ProxyProtocol(
                    rule_register=rule_register, egress_address=egress_address, secret_key=secret_key
                ),
                accum,
            ),
            str(address),
            port,
        )
        async with proxy_server:
            address, port = egress_address
            egress_server = await loop.create_server(
                lambda: mocks_protocol(EgressProtocol(secret_key), accum), str(address), port
            )
            async with egress_server:
                await proxy_server.start_serving()
                await egress_server.start_serving()
                yield proxy_address

    return server_context


async def test_special_proxy(start_special_proxy, accum):
    async with start_special_proxy(accum) as address:
        #
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("https://mail.ru")
            assert resp.status_code == 302

        with pytest.raises(httpx.ConnectError):
            async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
                resp = await client.get("https://ok.ru")
                assert resp.status_code == 200

        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("https://vk.ru")
            assert resp.status_code == 302

    assert accum == [
        (("127.0.0.1", 10443), Address("mail.ru", 443), True),
        (("127.0.0.1", 10443), Address("ok.ru", 443), ConnectionResetError),
        (("127.0.0.1", 10443), Address("vk.ru", 443), True),
        (("127.0.0.1", 20443), Address("vk.ru", 443), True),
    ]
