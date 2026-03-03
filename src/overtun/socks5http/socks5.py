import asyncio
import socket
import struct
from asyncio import Transport
from enum import IntEnum


class Socks5Error(Exception):
    """SOCKS5 Error."""


class Socks5Command(IntEnum):
    """SOCKS5 commands."""

    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class Socks5AddressType(IntEnum):
    """SOCKS5 address type enum."""

    IPv4 = 0x01
    DOMAIN = 0x03
    IPv6 = 0x04


class Socks5Protocol(asyncio.Protocol):
    """
    SOCKS5 protocol
    """

    def __init__(self, proxy_transport: Transport, target_host: str, target_port: int):
        """
        Constructor

        Args:
            proxy_transport: `asyncio.Transport` of the proxy protocol.
            target_host: Target resource hostname.
            target_port: Target resource port.
        """
        self._transport: Transport | None = None
        self._handshaking_fut = asyncio.Future()
        self._connecting_fut = asyncio.Future()
        self._proxy_transport = proxy_transport
        self._started = False

        def handshaking_done(fut: asyncio.Future):
            if fut.done() and not (fut.cancelled() or fut.exception()):
                self._send_connect(target_host, target_port)

        def connecting_done(fut: asyncio.Future):
            if fut.done() and not (fut.cancelled() or fut.exception()):
                self._started = True

        self._handshaking_fut.add_done_callback(handshaking_done)
        self._connecting_fut.add_done_callback(connecting_done)

    @property
    def handshaking(self) -> asyncio.Future:
        """Future refers to completing the handshake."""
        return self._handshaking_fut

    @property
    def connecting(self) -> asyncio.Future:
        """Future refers to completing the connection to the target resource."""
        return self._connecting_fut

    def connection_made(self, transport: Transport):
        """`asyncio.Protocol` Connection has been made."""
        self._transport = transport
        self._send_handshake()

    def data_received(self, data: bytes):
        """`asyncio.Protocol` Data has been received."""
        if not self._started:
            if not self._handshaking_fut.done():
                self._recv_handshake(data)
            elif not self._connecting_fut.done():
                self._recv_connected(data)
            else:
                raise RuntimeError
        else:
            self._proxy_transport.write(data)

    def connection_lost(self, exc: Exception):
        """`asyncio.Protocol` Connection has been lost."""
        self._proxy_transport.close()

    NO_AUTH = 0x00
    VERSION = 0x05

    def _send_handshake(self):
        # VER | NMETHODS | METHODS
        request = struct.pack("BBB", self.VERSION, 1, self.NO_AUTH)
        self._transport.write(request)

    def _recv_handshake(self, data: bytes):
        try:
            version, method = struct.unpack("BB", data[:2])
            if version != self.VERSION:
                raise Socks5Error(f"Invalid SOCKS5 version: {version}")
            if method != self.NO_AUTH:
                raise Socks5Error(f"Requires authentication (method: {method})")
            self._handshaking_fut.set_result(True)
        except Exception as exc:
            self._handshaking_fut.set_exception(exc)

    def _send_connect(self, target_host: str, target_port: int):
        try:
            # check if IPv4
            target_address = socket.inet_pton(socket.AF_INET, target_host)
            target_address_type = Socks5AddressType.IPv4
        except socket.error:
            try:
                # check if IPv6
                target_address = socket.inet_pton(socket.AF_INET6, target_host)
                target_address_type = Socks5AddressType.IPv6
            except socket.error:
                # domain
                target_address_type = Socks5AddressType.DOMAIN
                target_address = struct.pack("B", len(target_host)) + target_host.encode("ascii")

        # VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        request = (
            struct.pack("BBBB", self.VERSION, Socks5Command.CONNECT, 0x00, target_address_type)
            + target_address
            + struct.pack(">H", target_port)
        )
        self._transport.write(request)

    def _recv_connected(self, data: bytes):
        try:
            version, reply, reserved, address_type_response = struct.unpack("BBBB", data[:4])
            if version != self.VERSION:
                raise Socks5Error(f"Invalid SOCKS5 response version: {version}")
            if reply != 0x00:
                raise Socks5Error(f"Target connection failed with reply code: {reply}")
            self._connecting_fut.set_result(True)
        except Exception as exc:
            self._connecting_fut.set_exception(exc)
