import asyncio
import logging
import typing as t
from asyncio import Protocol, Transport
from collections.abc import Callable
from typing import Coroutine

import h11

type Socks5Connect = Callable[[Transport, str, int], Coroutine[t.Any, t.Any, Transport]]

logger = logging.getLogger("overtun:socks5http")
logger.setLevel(logging.INFO)


class ProxyProtocol(Protocol):
    """
    HTTP proxy protocol
    """

    def __init__(self, socks5_connect: Socks5Connect):
        """
        Constructor

        Args:
            socks5_connect: SOCKS5 asyncore connection factory.
        """
        self._socks5_connect = socks5_connect
        self._tasks: set[asyncio.Task] = set()
        self._h11_conn = h11.Connection(our_role=h11.SERVER)
        self._socks5_transport: Transport | None = None
        self._transport: Transport | None = None

    def connection_made(self, transport: Transport):
        """`asyncio.Protocol` Connection has been made."""
        self._transport = transport

    def data_received(self, data: bytes):
        """`asyncio.Protocol` Data has been received."""
        if self._socks5_transport is not None:
            self._socks5_transport.write(data)
        else:
            self._h11_conn.receive_data(data)
            self._process_events()

    def socks5_success(self, socks5_transport: Transport):
        """SOCKS5 connection has been successfully established."""
        self._socks5_transport = socks5_transport

    def socks5_failed(self, exc: Exception):
        """SOCKS5 connection has been failed."""
        message = f"Cannot connect to SOCKS5 server; {exc}"
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception(message, exc_info=exc)
        else:
            logger.error(message)
        if self._transport is not None:
            self._transport.abort()

    def connection_lost(self, exc: Exception):
        """`asyncio.Protocol` Connection has been lost."""
        if self._socks5_transport is not None:
            self._socks5_transport.close()

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
                self.socks5_success(task.result())
                resp = h11.Response(
                    headers=[("Proxy-agent", "OverTun/socks5http")], status_code=200, reason=b"Connection established"
                )
                self._transport.write(self._h11_conn.send(resp))
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                self.socks5_failed(exc)
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
                task = asyncio.create_task(self._socks5_connect(self._transport, target_host, target_port))
                task.add_done_callback(done_callback)
                self._tasks.add(task)
            else:
                resp = h11.Response(headers=[("connection", "close")], status_code=405)
                self._transport.write(self._h11_conn.send(resp))
                self._transport.write(self._h11_conn.send(h11.EndOfMessage()))
                self._transport.close()
