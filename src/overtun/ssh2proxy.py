import asyncio
import typing as t
from asyncio import Transport

import asyncssh
from asyncssh import SSHClientConnection, SSHTCPChannel, DataType
from . import httproxy


class TargetSession(asyncssh.SSHTCPSession):
    """
    Протокол пересылки тунелирования данных client_transport <--> target_transport.
    """

    def __init__(self, client_transport: Transport):
        self._client_transport = client_transport
        self._chan: SSHTCPChannel[bytes] | None = None

    def connection_made(self, chan: SSHTCPChannel[bytes]) -> None:
        httproxy.logger.debug(f"Tunnel established; {chan.get_extra_info('remote_peername', ())}")
        self._chan = chan

    def data_received(self, data: bytes, datatype: DataType) -> None:
        self._client_transport.write(data)

    def connection_lost(self, exc: Exception):
        httproxy.logger.debug(f"Tunnel closed; {self._chan.get_extra_info('remote_peername', ())}")
        self._client_transport.close()


async def create_server(ssh_client_connection: SSHClientConnection, proxy_host: str, proxy_port: int):
    """
    Создает HTTP Proxy сервер, которые туннелирует клиентские подключения к целевым серверам,
    через SSH подключение к SSH серверу.

    Args:
        ssh_client_connection: Подключение к SSH серверу.
        proxy_host: Адрес хоста на котором поднимается HTTP Proxy сервер.
        proxy_port: Порт поднимаемого HTTP Proxy сервера.

    Returns:
        Экземпляр `asyncio.Server` HTTP Proxy сервера.
    """
    loop = asyncio.get_running_loop()

    async def target_connector(proxy_transport: Transport, target_host: str, target_port: int):
        try:
            channel, session = await ssh_client_connection.create_connection(
                lambda: TargetSession(proxy_transport), target_host, target_port
            )
            return t.cast(Transport, t.cast(object, channel))
        except Exception as exc:
            raise ConnectionError(f"Failed to create tunnel to {target_host}:{target_port}; {exc}")

    return await loop.create_server(lambda: httproxy.Protocol(target_connector), proxy_host, proxy_port)
