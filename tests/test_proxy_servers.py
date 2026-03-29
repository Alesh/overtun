import asyncio

import httpx

import overtun
from tests.utils import requirements_note, TEST_TRANSPARENT_REQUIREMENTS


async def test_simple_server(proxy_address, debug_on):

    proxy_server = await overtun.create_server(proxy_address)
    async with proxy_server:
        await proxy_server.start_serving()

        # HTTP Native
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*proxy_address)) as client:
            resp = await client.get("http://mail.ru")
            assert resp.status_code == 405  # HTTP Native прокси не реализован

        # HTTP CONNECT PROXY
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*proxy_address)) as client:
            resp = await client.get("https://mail.ru")
            assert resp.status_code == 302

        # Transparent HTTPS Proxy
        with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_REQUIREMENTS):
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://mail.ru:8443")
                assert resp.status_code == 302

        await asyncio.sleep(300)
