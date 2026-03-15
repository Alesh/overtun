import asyncio
import struct
from asyncio import Transport

import httpx
import pytest

import overtun.base
from overtun.base import Target, TargetDecoder


class SNIDecoder(TargetDecoder):
    def __init__(self, port: int):
        self._port = port

    def __call__(self, data: bytes) -> Target | None:
        """
        Разбирает пакет TLS Client Hello. Извлекает SNI. Соответствует интерфейсу `overtun.decoders.Decoder`.
        """
        if len(data) < 5:
            return None
        elif data[0] != 0x16:
            raise ValueError("Not a TLS Handshake (Not HTTPS)")

        record_len = struct.unpack("!H", data[3:5])[0]
        if len(data) < record_len + 5:
            return None
        elif data[5] != 0x01:
            raise ValueError("Not a TLS Client Hello")

        # Пропускаем TSL Head (5), Handshake Header (4), Version (2), Random (32)
        ptr = 5 + 4 + 2 + 32

        # Session ID
        if len(data) < ptr + 1:
            return None
        session_id_len = data[ptr]
        ptr += 1 + session_id_len

        # Cipher Suites
        if len(data) < ptr + 2:
            return None
        cipher_suites_len = struct.unpack("!H", data[ptr : ptr + 2])[0]
        ptr += 2 + cipher_suites_len

        # Compression Methods
        if len(data) < ptr + 1:
            return None
        compression_len = data[ptr]
        ptr += 1 + compression_len

        # Extensions
        if len(data) < ptr + 2:
            # Если пакет закончился здесь, значит расширений (и SNI) нет
            raise LookupError("No extensions found (No SNI)")

        extensions_len = struct.unpack("!H", data[ptr : ptr + 2])[0]
        ptr += 2

        end_ptr = ptr + extensions_len
        if len(data) < end_ptr:
            return None

        while ptr + 4 <= end_ptr:
            ext_type, ext_len = struct.unpack("!HH", data[ptr : ptr + 4])
            ptr += 4

            if ext_type == 0:  # SNI Extension
                # Структура: SNI List Len(2), Type(1), Name Len(2)
                ptr += 2 + 1
                name_len = struct.unpack("!H", data[ptr : ptr + 2])[0]
                ptr += 2
                host = data[ptr : ptr + name_len].decode("utf-8")
                return Target(host, self._port)

            ptr += ext_len

        raise LookupError("SNI extension not found in TLS Handshake")


async def create_endpoint(bag: list, endpoint_port: int) -> asyncio.Server:
    loop = asyncio.get_running_loop()

    async def target_connector(transport: Transport, target: Target) -> Transport:
        bag.append(("endpoint", target))
        target_transport, _ = await loop.create_connection(lambda: overtun.base.BridgeProtocol(transport), *target)
        return target_transport

    class Protocol(overtun.base.DispatcherProtocol):
        def __init__(self, port: int = 443):
            super().__init__(SNIDecoder(port), target_connector)

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
            super().__init__(SNIDecoder(port), target_connector)

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
