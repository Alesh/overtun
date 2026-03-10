import asyncio
import logging

import httpx

from overtun import httproxy


async def test_protocol_http(proxy_port):
    loop = asyncio.get_event_loop()
    httproxy.logger.setLevel(logging.DEBUG)

    # Сборка и запуск HTTP Proxy сервера

    class DirectProtocol(asyncio.Protocol):
        """
        Протокол пересылки тунелирования данных client_transport <--> target_transport.
        """

        def __init__(self, client_transport):
            self.client_transport = client_transport

        def data_received(self, data: bytes):
            self.client_transport.write(data)

        def connection_lost(self, exc):
            self.client_transport.close()

    async def target_connector(client_transport: asyncio.Transport, target_host: str, target_port: int):
        target_transport, _ = await loop.create_connection(
            lambda: DirectProtocol(client_transport), target_host, target_port
        )
        return target_transport

    proxy_server = await loop.create_server(lambda: httproxy.Protocol(target_connector), "127.0.0.1", proxy_port)
    await proxy_server.start_serving()

    # Клиентский HTTP запрос
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}") as client:
        resp = await client.get("http://python.com")
        assert resp.status_code == 308
        assert resp.headers["Location"] == "https://python.com/"

    # Клиентский HTTPS запрос
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}") as client:
        resp = await client.get("https://python.com")
        assert resp.status_code == 403
