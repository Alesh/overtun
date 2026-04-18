import functools
import struct
import typing as t
from collections.abc import Sequence, Buffer
from enum import Enum

from tlsex.entities import Cipher, _Entity, Extension
from tlsex.extensions import TLSExtension


class TLSMessage(_Entity):
    """TLS message."""

    class Version(bytes, Enum):
        """TLS protocol version."""

        TLS12 = b"\x03\x03"
        TLS13 = b"\x03\x04"

    class Type(bytes, Enum):
        """TLS message types."""

        HelloRequest = b"\x00"
        ClientHello = b"\x01"
        ServerHello = b"\x02"
        HelloVerifyRequest = b"\x03"
        NewSessionTicket = b"\x04"
        Certificate = b"\x0b"
        ServerKeyExchange = b"\x0c"
        CertificateRequest = b"\x0d"
        ServerDone = b"\x0e"
        CertificateVerify = b"\x0f"
        ClientKeyExchange = b"\x10"
        Finished = b"\x14"
        CertificateStatus = b"\x16"

    @functools.cached_property
    def type(self) -> Type:
        """Message type."""
        return TLSMessage.Type(self._mv[0:1])

    @functools.cached_property
    def version(self) -> Version:
        """Protocol version."""
        return TLSMessage.Version(self._mv[4:6])

    @functools.cached_property
    def nonce(self) -> bytes:
        """Random 32 bytes (client/server random)."""
        return bytes(self._mv[6:38])

    @classmethod
    def make_collections(cls, buffer: Buffer, /) -> tuple[t.Self, ...]:
        """Build a collection of TLSMessage objects from a buffer."""
        ptr = 0
        messages = []
        mv = memoryview(buffer).toreadonly()
        while ptr < len(mv):
            if mv[ptr : ptr + 1] in TLSMessage.Type:
                (length,) = struct.unpack("!L", b"\0" + bytes(mv[ptr + 1 : ptr + 4]))
                match TLSMessage.Type(mv[ptr : ptr + 1]):
                    case TLSMessage.Type.ClientHello:
                        messages.append(ClientHello(mv[ptr : ptr + length + 4]))
                    case _:
                        messages.append(TLSMessage(mv[ptr : ptr + length + 4]))
                ptr += length + 4
        return tuple(messages)


class ClientHello(TLSMessage):
    """Client Hello message."""

    def __init__(self, mv: memoryview) -> None:
        super().__init__(mv)
        # (SessionID offset) + (SessionID length field) + (SessionID size)
        ptr = 38 + 1 + mv[38]  # Offset past SessionID
        (cs_length,) = struct.unpack("!H", mv[ptr : ptr + 2])
        self.__ciphers = Cipher.make_collections(self._mv[ptr + 2 : ptr + 2 + cs_length])
        # + (Cipher Suites length field) + (Cipher Suites size) + CompressionMethods
        ptr = ptr + 2 + cs_length + 2  # Offset past Cipher Suites and CompressionMethods
        (ex_length,) = struct.unpack("!H", mv[ptr : ptr + 2])
        self.__extensions = TLSExtension.make_collections(self._mv[ptr + 2 : ptr + 2 + ex_length])

    @functools.cached_property
    def _cipher_suites(self) -> Sequence[Cipher]:
        return self.__ciphers

    @functools.cached_property
    def _extensions(self) -> Sequence[Extension]:
        return self.__extensions

    @property
    def cipher_suites(self) -> Sequence[Cipher]:
        """Supported/selected cipher suite identifiers (GREASE-filtered)."""
        return tuple(cs for cs in self._cipher_suites if (cs.number & 0x0F0F) != 0x0A0A)

    @property
    def extensions(self) -> Sequence[TLSExtension]:
        """Offered TLS extensions (recognized only)."""
        return tuple(ex for ex in self._extensions if isinstance(ex, TLSExtension))
