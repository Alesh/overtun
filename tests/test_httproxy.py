import asyncio
import logging

import httpx

from overtun import httproxy


async def test_http_connect_proxy_protocol(proxy_port):
    loop = asyncio.get_event_loop()
    httproxy.logger.setLevel(logging.WARNING)
    accum = b""

    # Сборка и запуск тестового Proxy сервера
    class DirectProtocol(asyncio.Protocol):
        def __init__(self, client_transport):
            self.client_transport = client_transport

        def data_received(self, data: bytes):
            nonlocal accum
            accum += data
            self.client_transport.write(data)

        def connection_lost(self, exc):
            self.client_transport.close()

    async def direct_target_connector(client_transport: asyncio.Transport, target_host: str, target_port: int):
        loop = asyncio.get_event_loop()
        target_transport, _ = await loop.create_connection(
            lambda: DirectProtocol(client_transport), target_host, target_port
        )
        return target_transport

    proxy_server = await loop.create_server(lambda: httproxy.Protocol(direct_target_connector), "127.0.0.1", proxy_port)
    await proxy_server.start_serving()

    # Клиентский HTTP запрос
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}") as client:
        resp = await client.get("http://www.python.org")
        assert resp.status_code == 405

    # Клиентский HTTPS запрос
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}") as client:
        resp = await client.get("https://www.python.org")
        assert resp.status_code == 200

    assert (
        accum[:3] == b"\x16\x03\x03" and accum[5:6] == b"\x02" and accum[9:11] == b"\x03\x03",
        "TLS Server Hello not found",
    )
