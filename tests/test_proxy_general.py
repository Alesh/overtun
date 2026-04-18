import asyncio
import contextlib

import httpx
import pytest

from overtun.protocols.general import IncomingProtocol as ProxyProtocol
from tests.utils import TEST_TRANSPARENT_CONDITIONS, requirements_note


@pytest.fixture
async def start_general_proxy(proxy_address):
    """Return a context with a running general-purpose proxy server.
    The context variable holds the address of this server.
    """

    @contextlib.asynccontextmanager
    async def server_context():
        loop = asyncio.get_event_loop()
        address, port = proxy_address
        proxy_server = await loop.create_server(lambda: ProxyProtocol(), str(address), port)
        async with proxy_server:
            await proxy_server.start_serving()
            yield proxy_address

    return server_context


async def test_general_proxy(start_general_proxy):
    async with start_general_proxy() as address:
        # HTTP Native
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("http://mail.ru")
            assert resp.status_code == 405  # HTTP Native proxy not implemented

        # HTTP CONNECT PROXY
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("https://mail.ru")
            assert resp.status_code == 302

        # Transparent HTTPS Proxy
        with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_CONDITIONS):
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://mail.ru:8443")
                assert resp.status_code == 302
