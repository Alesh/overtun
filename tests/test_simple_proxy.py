import asyncio
import contextlib

import httpx
import pytest

from overtun.servers import create_proxy
from tests.utils import requirements_note, TEST_TRANSPARENT_REQUIREMENTS


@pytest.fixture
async def simple_proxy(proxy_address):
    @contextlib.asynccontextmanager
    async def simple_proxy_context():
        proxy_server = await create_proxy(proxy_address)
        async with proxy_server:
            await proxy_server.start_serving()
            yield proxy_address

    return simple_proxy_context


async def test_simple_server(simple_proxy, debug_on):
    async with simple_proxy() as address:
        # HTTP Native
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("http://mail.ru")
            assert resp.status_code == 405  # HTTP Native прокси не реализован

        # HTTP CONNECT PROXY
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("https://mail.ru")
            assert resp.status_code == 302

        # Transparent HTTPS Proxy
        with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_REQUIREMENTS):
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://mail.ru:8443")
                assert resp.status_code == 302
