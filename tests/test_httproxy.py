import asyncio
import random

import httpx
import pytest

from overtun import httproxy
from tests.mock_httproxy import mock_target_connector


async def test_protocol():

    loop = asyncio.get_event_loop()
    port = random.randint(60000, 65000)

    # Компоновка и запуск сервера
    protocol_factory = lambda: httproxy.Protocol(mock_target_connector)
    server = await loop.create_server(protocol_factory, "127.0.0.1", port)
    await server.start_serving()

    # Клиентский HTTP запрос
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        resp = await client.get("http://example.com/somewhere/index.html")
        assert resp.status_code == 200
        result = resp.json()
        assert result["request"]["method"] == "GET"
        assert result["request"]["target"] == "/somewhere/index.html"
        assert ["Host", "example.com"] in result["request"]["headers"]

    # Клиентский HTTPS запрос
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
        with pytest.raises(httpx.ConnectError, match="[SSL] record layer failure"):
            await client.get("https://example.com/somewhere/index.html")
