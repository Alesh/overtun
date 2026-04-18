import functools
import inspect
import struct
import typing as t
from collections.abc import Buffer, Sized
from enum import Enum

from .extensions import TLSExtension
from .messages import TLSMessage

all = ["TLSRecord", "TLSMessage", "TLSExtension"]


class TLSRecord(Buffer, Sized):
    """
    TLS Запись
    """

    class Type(bytes, Enum):
        """
        Типы TLS записей
        """

        ChangeCipherSpec = b"\x14"
        Alert = b"\x15"
        Handshake = b"\x16"
        ApplicationData = b"\x17"
        Heartbeat = b"\x18"

    _mv: memoryview

    def __buffer__(self, flags, /):
        if flags & inspect.BufferFlags.WRITABLE:
            raise BufferError("This is readonly buffer")
        return self._mv

    def __bytes__(self):
        return self._mv.tobytes()

    def __len__(self):
        return len(self._mv)

    @functools.cached_property
    def type(self):
        """Тип записи."""
        return TLSRecord.Type(self._mv[0:1])

    @functools.cached_property
    def message(self) -> TLSMessage:
        """Сообщение содержащееся в записи."""
        return TLSMessage.load(self._mv)

    @classmethod
    def load(cls, buffer: bytes | bytearray | memoryview) -> t.Self | None:
        """Загружает TLS запись и создает экземпляр класса."""
        if len(buffer) < 5:
            return None
        message_length = struct.unpack("!H", buffer[3:5])[0]
        if len(buffer) < message_length + 5:
            return None
        if not (bytes(buffer[0:1]) in cls.Type and buffer[5:6] in TLSMessage.Type):
            raise ValueError("Not a TLS record")
        inst = cls()
        if isinstance(buffer, memoryview):
            inst._mv = buffer
        else:
            inst._mv = memoryview(buffer)
        if not inst._mv.readonly:
            inst._mv = inst._mv.toreadonly()
        return inst
