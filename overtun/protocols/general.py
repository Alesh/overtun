import asyncio
import contextlib
import logging
from asyncio import Task, Transport
from logging import Logger

from overtun.primitives import Address, Error
from overtun.utils import get_peer_address, default_logger
from tlsex import TLSRecord
from tlsex.extensions import ServerName
from tlsex.messages import ClientHello


class ProtocolError(Error):
    """Protocol error."""


class BaseProtocol(asyncio.Protocol):
    """
    Base class for protocols.

    Args:
        logger: Logger instance.
    """

    def __init__(self, *, logger: Logger | None = None) -> None:
        self.__logger = logger or default_logger
        self.__transport: Transport | None = None

    @property
    def logger(self) -> Logger:
        """Logger."""
        return self.__logger

    @property
    def transport(self) -> Transport:
        """Associated transport."""
        if not self.__transport:
            msg = "Transport isn't connected."
            raise ConnectionError(msg)
        return self.__transport

    def connection_made(self, transport: Transport) -> None:
        """Transport connected."""
        self.__transport = transport


class OutgoingProtocol(BaseProtocol):
    """
    Base protocol for outgoing connections.

    Args:
        incoming_transport: Incoming connection transport.
        logger: Logger instance.
    """

    def __init__(self, incoming_transport: Transport, *, logger: Logger | None = None, **kwargs) -> None:
        super().__init__(logger=logger)
        self.__incoming = incoming_transport

    @property
    def incoming(self) -> Transport:
        """Associated incoming transport."""
        return self.__incoming

    def connection_made(self, transport: Transport) -> None:
        """Outgoing transport connected."""
        super().connection_made(transport)
        self.incoming.resume_reading()

    def pause_writing(self) -> None:
        """Outgoing buffer is full."""
        self.incoming.pause_reading()

    def resume_writing(self) -> None:
        """Outgoing buffer has been drained."""
        self.incoming.resume_reading()

    def data_received(self, data: bytes) -> None:
        """Data received from the outgoing connection."""
        self.incoming.write(data)

    def connection_lost(self, _exc: Exception | None) -> None:
        """Outgoing connection lost."""
        if not self.incoming.is_closing():
            self.incoming.close()


class IncomingProtocol(BaseProtocol):
    """
    Base protocol for incoming connections.

    Args:
        logger: Logger instance.
    """

    def __init__(self, *, logger: Logger | None = None) -> None:
        super().__init__(logger=logger)
        self.__outgoing: Transport | None = None
        self._target_address: Address | None = None
        self._buffer = b""

    @property
    def outgoing(self) -> Transport:
        """Associated outgoing transport."""
        if self.__outgoing is None:
            msg = "Transport isn't connected."
            raise ConnectionError(msg)
        return self.__outgoing

    @property
    def connected(self) -> bool:
        """True if the connection is established."""
        return self.__outgoing is not None

    def data_received(self, data: bytes) -> None:
        """Data received from the incoming connection."""
        try:
            if self.connected:
                self.outgoing.write(data)
            else:
                self._buffer += data
                if self._buffer[0] == 0x16:  # TLS Handshake signature ??
                    self.tls_session_started(self._buffer)
                elif (parts := self._buffer.split(b" ", 2)) and len(parts) == 3:
                    if parts[0] == b"CONNECT" and self._buffer.find(b"\r\n\r\n") + 1:
                        self.http_connect_handler(self._buffer)
                        self._buffer = b""
                    else:
                        # HTTP Native and HTTP Transparent proxy not implemented
                        self.transport.write(b"HTTP/1.0 405 Method Not Allowed\r\n\r\n")
                        self.transport.close()
        except ConnectionError as exc:
            local_address = get_peer_address(self.transport)
            msg = f"Connection from {local_address} to {self._target_address} failed; {exc}"
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.exception(msg)
            else:
                self.logger.warning(msg)
            self.transport.write_eof()

    def http_connect_handler(self, preamble: bytes) -> None:
        """Handle an HTTP CONNECT request."""
        parts = preamble[8:].split(b" ", 1)
        with contextlib.suppress(ValueError):
            self._target_address = Address.parse(parts[0].decode("ascii"))
        # Switch protocol to TLS traffic
        self.transport.write(b"HTTP/1.0 200 OK\r\n\r\n")

    def tls_session_started(self, preamble: bytes) -> None:
        """TLS session started."""
        try:
            message = TLSRecord(preamble).message
            if isinstance(message, ClientHello):
                if found := [ex for ex in message.extensions if isinstance(ex, ServerName)]:
                    self._target_address = Address.parse(found[0].hostname, 443)
                if self._target_address is None:
                    msg = "target address isn't set"
                    raise ValueError(msg)
            else:
                msg = "wrong TLS handshake"
                raise ValueError(msg)
            self.__create_outgoing_connection(self._target_address)
        except ValueError as exc:
            msg = f"TLS connection failed; {exc}"
            raise ConnectionError(msg) from exc
        except BufferError:
            pass

    def connection_lost(self, _exc: Exception | None) -> None:
        """Transport disconnected."""
        if self.connected and not self.outgoing.is_closing():
            self.outgoing.close()

    async def create_outgoing_connection(self, address: Address) -> Transport:
        """Asynchronous task that establishes and returns the outgoing connection."""
        host, port = address
        loop = asyncio.get_running_loop()
        outgoing_transport, _ = await loop.create_connection(
            lambda: OutgoingProtocol(self.transport, logger=self.logger),
            str(host),
            port,
        )
        return outgoing_transport

    def __create_outgoing_connection(self, target_address: Address):
        """Creates a task that establishes and returns the outgoing connection."""
        self._outgoing_task = asyncio.create_task(self.create_outgoing_connection(target_address))
        self._outgoing_task.add_done_callback(lambda task: self.__create_outgoing_done(task, target_address))

    def __create_outgoing_done(self, task: Task[Transport], target_address: Address) -> None:
        """A callback function that is executed when the outgoing connection creation task completes."""
        local_address = get_peer_address(self.transport)
        try:
            self.__outgoing = task.result()
            if self._buffer:
                self._buffer, buffer = b"", self._buffer
                self._send_preamble(buffer)
            remote_address = get_peer_address(self.outgoing)
            msg = f"Connection from {local_address} to {target_address} established"
            if target_address != remote_address:
                msg = f"{msg}; via {remote_address}"
            self.logger.info(msg)
        except Exception as exc:
            msg = f"Connection from {local_address} to {target_address} failed; {exc}"
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.exception(msg)
            else:
                self.logger.warning(msg)
            self.transport.write_eof()

    def _send_preamble(self, preamble: bytes):
        self.outgoing.write(preamble)
