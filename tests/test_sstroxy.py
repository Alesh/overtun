import asyncio
import struct
from asyncio import Transport

import httpx
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


async def test_sni_selective_transparent_proxy():
    # Для этого теста/примера надо включить перенаправление исходящего трафика с 8443 на 10443
    # sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to-destination 127.0.0.1:10443

    # Сборка и запуск тестового сервера
    loop = asyncio.get_running_loop()

    async def target_connector(transport: Transport, target: Target) -> Transport:
        loop = asyncio.get_event_loop()
        target_transport, _ = await loop.create_connection(lambda: overtun.base.BridgeProtocol(transport), *target)
        return target_transport

    class Protocol(overtun.base.DispatcherProtocol):
        def __init__(self, port: int = 443):
            super().__init__(SNIDecoder(port), target_connector)

    proxy_server = await loop.create_server(Protocol, "127.0.0.1", 10443)
    async with proxy_server:
        await proxy_server.start_serving()

        async with httpx.AsyncClient() as client:
            resp = await client.get("https://python.org:8443/index.html")
            assert resp.status_code == 301
