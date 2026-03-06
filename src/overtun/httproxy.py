import asyncio
import logging
import typing as t
from asyncio import Protocol, Transport
from collections.abc import Callable
from typing import Coroutine

import asyncssh
import h11
from asyncssh import DataType, SSHClientConnection, SSHTCPChannel

logger = logging.getLogger(":".join(__name__.split(".")))
logger.setLevel(logging.DEBUG)


class ProxyProtocol(Protocol):
    """
    HTTP CONNECT Proxy protocol for the client side.
    """

    def __init__(self, target_connect: Callable[[Transport, str, int], Coroutine[t.Any, t.Any, SSHTCPChannel]]):
        """
        Constructor

        Args:
            target_connect: Target session factory.
        """
        self._target_connect = target_connect
        self._tasks: set[asyncio.Task] = set()
        self._h11_conn = h11.Connection(our_role=h11.SERVER)
        self._target_channel: SSHTCPChannel | None = None
        self._transport: Transport | None = None

    def connection_made(self, transport: Transport):
        """`asyncio.Protocol` Connection has been made."""
        self._transport = transport

    def data_received(self, data: bytes):
        """`asyncio.Protocol` Data has been received."""
        if self._target_channel is not None:
            self._target_channel.write(data)
        else:
            self._h11_conn.receive_data(data)
            self._process_events()

    def target_connection_success(self, target_channel: SSHTCPChannel):
        """Target connection has been successfully established."""
        self._target_channel = target_channel

    def target_connection_failed(self, exc: Exception):
        """Target connection has been failed."""
        message = f"Cannot connect to target server; {exc}"
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception(message, exc_info=exc)
        else:
            logger.error(message)
        if self._transport is not None:
            self._transport.abort()

    def connection_lost(self, exc: Exception):
        """`asyncio.Protocol` Connection has been lost."""
        if self._target_channel is not None:
            self._target_channel.close()

    def _process_events(self):
        request = None
        seen_end = False
        while not seen_end:
            event = self._h11_conn.next_event()
            if event is h11.NEED_DATA:
                break
            elif event is h11.PAUSED:
                self._transport.pause_reading()
                break
            elif isinstance(event, h11.Request):
                request = event
            elif isinstance(event, h11.EndOfMessage):
                seen_end = True

        def done_callback(task: asyncio.Task):
            try:
                self.target_connection_success(task.result())
                resp = h11.Response(
                    headers=[("Proxy-agent", "OverTun/httproxy")], status_code=200, reason=b"Connection established"
                )
                self._transport.write(self._h11_conn.send(resp))
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                self.target_connection_failed(exc)
            finally:
                self._tasks.remove(task)

        if seen_end and request:
            if request.method == b"CONNECT":
                path = request.target.strip(b"/").decode("ascii")
                if ":" in path:
                    target_host, target_port = path.split(":", 1)
                    target_port = int(target_port)
                else:
                    target_host = path
                    target_port = 443
                task = asyncio.create_task(self._target_connect(self._transport, target_host, target_port))
                task.add_done_callback(done_callback)
                self._tasks.add(task)
            else:
                resp = h11.Response(headers=[("connection", "close")], status_code=405)
                self._transport.write(self._h11_conn.send(resp))
                self._transport.write(self._h11_conn.send(h11.EndOfMessage()))
                self._transport.close()


class TargetSession(asyncssh.SSHTCPSession):
    """
    SSH Direct TCP session for the target side.
    """

    def __init__(self, proxy_transport: Transport):
        self._proxy_transport = proxy_transport
        self._chan: SSHTCPChannel[bytes] | None = None

    def connection_made(self, chan: SSHTCPChannel[bytes]) -> None:
        logger.debug(f"Tunnel established; {chan.get_extra_info('remote_peername', ())}")
        self._chan = chan

    def data_received(self, data: bytes, datatype: DataType) -> None:
        """Data has been received."""
        self._proxy_transport.write(data)

    def connection_lost(self, exc: Exception):
        """Connection has been lost."""
        logger.debug(f"Tunnel closed; {self._chan.get_extra_info('remote_peername', ())}")
        self._proxy_transport.close()


async def create_server(cc: SSHClientConnection, proxy_host: str, proxy_port: int) -> asyncio.Server:
    """
    Creates the HTTP CONNECT proxy server that provides connection
    to a network resource via a SSH2 direct TCP connection.

    Args:
        cc: SSHClientConnection object.
        proxy_host: The hostname of the proxy server.
        proxy_port: The port of the proxy server.
    """
    loop = asyncio.get_running_loop()

    async def target_connector(proxy_transport: Transport, target_host: str, target_port: int):
        try:
            channel, session = await cc.create_connection(
                lambda: TargetSession(proxy_transport), target_host, target_port
            )
            return channel
        except Exception as exc:
            raise ConnectionError(f"Failed to create tunnel to {target_host}:{target_port}; {exc}")

    logger.info(f"Creating HTTP CONNECT proxy server on: {proxy_host}:{proxy_port}")
    return await loop.create_server(
        lambda: ProxyProtocol(target_connector),
        proxy_host,
        proxy_port,
    )
