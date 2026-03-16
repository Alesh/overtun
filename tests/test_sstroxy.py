import asyncio
import typing as t
from asyncio import Transport

import httpx
import pytest

import overtun.base
from overtun.base import Target
from overtun.utils.tlsex import TLSRecord, TLSMessage
from overtun.utils.tlsex.extensions import TLSExtension, ServerName


def sni_extractor(data: bytes, port: int = 433) -> Target | None:
    if record := TLSRecord.load(data):
        if record.message.type != TLSMessage.Type.ClientHello:
            raise ValueError("Not a TLS Client Hello")
        if TLSExtension.Type.ServerName in record.message.extensions:
            sni = t.cast(ServerName, record.message.extensions[TLSExtension.Type.ServerName])
            return Target(sni.hostname, port)
        raise LookupError("SNI extension not found in TLS Handshake")
    return None


async def create_endpoint(bag: list, endpoint_port: int) -> asyncio.Server:
    loop = asyncio.get_running_loop()

    async def target_connector(transport: Transport, target: Target) -> Transport:
        bag.append(("endpoint", target))
        target_transport, _ = await loop.create_connection(lambda: overtun.base.BridgeProtocol(transport), *target)
        return target_transport

    class Protocol(overtun.base.DispatcherProtocol):
        def __init__(self, port: int = 443):
            super().__init__(lambda data: sni_extractor(data, port), target_connector)

    return await loop.create_server(Protocol, "127.0.0.1", endpoint_port)


async def create_proxy(bag: list, proxy_port: int, endpoint: Target) -> asyncio.Server:
    loop = asyncio.get_running_loop()

    async def target_connector(transport: Transport, target: Target) -> Transport:
        if target.host in ("python.org",):
            # Через тунель
            bag.append(("tunnel", target))
            target_transport, _ = await loop.create_connection(
                lambda: overtun.base.BridgeProtocol(transport), *endpoint
            )
        else:
            # Напрямую
            bag.append(("direct", target))
            target_transport, _ = await loop.create_connection(lambda: overtun.base.BridgeProtocol(transport), *target)
        return target_transport

    class Protocol(overtun.base.DispatcherProtocol):
        def __init__(self, port: int = 443):
            super().__init__(lambda data: sni_extractor(data, port), target_connector)

    return await loop.create_server(Protocol, "127.0.0.1", proxy_port)


@pytest.fixture(scope="module")
def bag():
    yield list()


async def test_sni_selective_transparent_proxy(bag):
    # Для этого теста/примера надо включить перенаправление исходящего трафика с 8443 на 10443
    # sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to-destination 127.0.0.1:10443

    # Сборка и запуск тестовых серверов
    proxy_server = await create_proxy(bag, 10443, Target("127.0.0.1", 20443))
    endpoint_server = await create_endpoint(bag, 20443)  # Выход туннеля
    async with proxy_server:
        async with endpoint_server:
            await proxy_server.start_serving()
            await endpoint_server.start_serving()

            # Тестовые запросы

            # Идет через туннель
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://python.org:8443/index.html")
                assert resp.status_code == 301

            # Идет минуя туннель
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://www.opennet.ru:8443/index.html")
                assert resp.status_code == 200

    assert bag == [
        ("tunnel", Target("python.org", 443)),
        ("endpoint", Target("python.org", 443)),
        ("direct", Target("www.opennet.ru", 443)),
    ]
