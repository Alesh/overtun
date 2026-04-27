import asyncio
import contextlib
import logging
import typing as t
from collections.abc import Callable
from ipaddress import IPv4Address

import httpx
import pytest

from overtun.primitives import Address, TargetRule
from overtun.protocols.special import EgressProtocol, ProxyProtocol
from overtun.utils import default_logger
from tests.samples import Tunnel

default_logger.setLevel(logging.DEBUG)


@pytest.fixture
def rule_register():
    return {
        Address("ok.ru", 443): (TargetRule.DROP, None),
        Address("vk.ru", 443): (TargetRule.TUNNEL, 0),
        Address("ya.ru", 443): (TargetRule.TUNNEL, 1),
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
        orig_write: Callable[[bytes], None] | None = None
        preamble = True

        def outgoing_write(remote_address, host, data):
            nonlocal orig_write, preamble
            if data[0] == 0x16 and preamble:
                if IPv4Address(remote_address[0]).is_global:
                    remote_address = host, remote_address[1]
                accum.append((remote_address, "found" if host.encode() in data else "masked", host))
                preamble = False
            if orig_write is not None:
                orig_write(data)

        async def create_outgoing_connection(address: Address):
            nonlocal orig_write
            try:
                outgoing_transport = await orig_method(address)
                local_address = protocol.transport.get_extra_info("sockname")
                remote_address = outgoing_transport.get_extra_info("peername")
                accum.append((local_address, address, True))
                orig_write = outgoing_transport.write
                outgoing_transport.write = lambda data: outgoing_write(remote_address, address.host, data)
                return outgoing_transport
            except Exception as exc:
                accum.append((protocol.transport.get_extra_info("sockname"), address, type(exc)))
                raise

        protocol.create_outgoing_connection = create_outgoing_connection
        return protocol

    tunnel = Tunnel(egress_address, secret_key)

    @contextlib.asynccontextmanager
    async def server_context(accum: list[t.Any]):
        loop = asyncio.get_event_loop()
        address, port = proxy_address
        proxy_server = await loop.create_server(
            lambda: mocks_protocol(
                ProxyProtocol(rule_register=rule_register, tunnel=tunnel),
                accum,
            ),
            str(address),
            port,
        )
        async with proxy_server:
            address, port = egress_address
            egress_server = await loop.create_server(
                lambda: mocks_protocol(EgressProtocol(tunnel), accum), str(address), port
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

        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("https://ya.ru")
            assert resp.status_code == 302

    assert accum == [
        (("127.0.0.1", 10443), Address("mail.ru", 443), True),
        (("mail.ru", 443), "found", "mail.ru"),
        (("127.0.0.1", 10443), Address("ok.ru", 443), ConnectionResetError),
        (("127.0.0.1", 10443), Address("vk.ru", 443), True),
        (("127.0.0.1", 20443), "found", "vk.ru"),
        (("127.0.0.1", 20443), Address("vk.ru", 443), True),
        (("vk.ru", 443), "found", "vk.ru"),
        (("127.0.0.1", 10443), Address("ya.ru", 443), True),
        (("127.0.0.1", 20443), "masked", "ya.ru"),
        (("127.0.0.1", 20443), Address("ya.ru", 443), True),
        (("ya.ru", 443), "found", "ya.ru"),
    ]
