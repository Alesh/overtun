import functools
import struct
from collections.abc import Sequence
from enum import Enum

from tlsex.entities import _Entity
from tlsex.extensions import TLSExtension
from tlsex.messages import TLSMessage

__all__ = ["TLSExtension", "TLSMessage", "TLSRecord"]


class TLSRecord(_Entity):
    """A TLS record."""

    class Type(bytes, Enum):
        """TLS record content types."""

        ChangeCipherSpec = b"\x14"
        Alert = b"\x15"
        Handshake = b"\x16"
        ApplicationData = b"\x17"
        Heartbeat = b"\x18"

    def __init__(self, buffer: bytes) -> None:
        if len(buffer) >= 5:
            if not (bytes(buffer[0:1]) in self.Type and buffer[5:6] in TLSMessage.Type):
                msg = "Not a TLS record"
                raise ValueError(msg)
            (length,) = struct.unpack("!H", buffer[3:5])
            if len(buffer) == length + 5:
                super().__init__(memoryview(buffer).toreadonly())
                self.__messages = TLSMessage.make_collections(self._mv[5:])
                return
        msg = "Buffer is not complete"
        raise BufferError(msg)

    @functools.cached_property
    def type(self) -> Type:
        """Record content type."""
        return TLSRecord.Type(self._mv[0:1])

    @property
    def message(self) -> TLSMessage:
        """First message in the record."""
        return self._messages[0]

    @property
    def _messages(self) -> Sequence[TLSMessage]:
        """All messages in the record."""
        return tuple(self.__messages)
