import asyncio
import logging

import httpx
import pytest

from overtun.intyperr import Address
from overtun.protocols import ProxyProtocol, Protocol, OutcomingProtocol
from tests.utils import requirements_note, TEST_TRANSPARENT_REQUIREMENTS


@pytest.fixture
def debug_on():
    logging.getLogger("overtun").setLevel(logging.DEBUG)
    yield
    logging.getLogger("overtun").setLevel(logging.WARNING)


async def test_proxy_protocol(proxy_address, debug_on):
    loop = asyncio.get_event_loop()

    async def outcoming_factory(incoming: Protocol, target: Address) -> OutcomingProtocol:
        _, protocol = await loop.create_connection(lambda: OutcomingProtocol(incoming, incoming.logger), *target)
        return protocol

    proxy_server = await loop.create_server(
        lambda: ProxyProtocol(outcoming_factory),
        *proxy_address,
    )

    async with proxy_server:
        await proxy_server.start_serving()

        # HTTP CONNECT Proxy
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*proxy_address)) as client:
            resp = await client.get("https://mail.ru")
            assert resp.status_code == 302

        # Transparent HTTPS Proxy
        with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_REQUIREMENTS):
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://mail.ru:8443")
                assert resp.status_code == 302


async def test_proxy_tunnel(proxy_address, outlet_address, debug_on):
    accum = list()
    loop = asyncio.get_event_loop()

    # client >> proxy_server >> tunnel >> outlay_server >> target

    async def outcoming_factory(incoming: Protocol, target: Address) -> OutcomingProtocol:
        transport, protocol = await loop.create_connection(
            lambda: OutcomingProtocol(incoming, incoming.logger), *target
        )
        save_write = transport.write

        def write(data):
            accum.append((incoming.transport.get_extra_info("sockname"), len(data)))
            save_write(data)

        transport.write = write
        return protocol

    async def tunnel_factory(incoming: Protocol, _: Address) -> OutcomingProtocol:
        return await outcoming_factory(incoming, outlet_address)

    proxy_server = await loop.create_server(lambda: ProxyProtocol(tunnel_factory), *proxy_address)
    outlet_server = await loop.create_server(lambda: ProxyProtocol(outcoming_factory), *outlet_address)

    async with proxy_server:
        async with outlet_server:
            await proxy_server.start_serving()
            await outlet_server.start_serving()

            # HTTP CONNECT Proxy
            async with httpx.AsyncClient(proxy="http://{}:{}".format(*proxy_address)) as client:
                resp = await client.get("https://mail.ru")
                assert resp.status_code == 302

            assert accum == [
                (("127.0.0.1", 10443), 1529),
                (("127.0.0.1", 20443), 1529),
                (("127.0.0.1", 10443), 93),
                (("127.0.0.1", 20443), 93),
                (("127.0.0.1", 10443), 164),
                (("127.0.0.1", 20443), 164),
            ]

            # Transparent HTTPS Proxy
            with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_REQUIREMENTS):
                async with httpx.AsyncClient() as client:
                    resp = await client.get("https://mail.ru:8443")
                    assert resp.status_code == 302
