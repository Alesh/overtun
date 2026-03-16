import struct
import typing as t
from enum import Enum

from .messages import TLSMessage


class TLSRecord(bytes):
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

    @property
    def type(self):
        """Тип записи."""
        return TLSRecord.Type(memoryview(self)[0:1])

    @property
    def message(self):
        """Вложенное сообщение"""
        return TLSMessage.select(memoryview(self))

    @classmethod
    def load(cls, data: bytes) -> t.Self | None:
        """
        Если данных достаточно для загрузки записи, создается и возвращается экземпляр класса.

        Args:
             data: Данные для загрузки записи.

        Returns:
            Экземпляр класса TLS записи
            `None` если данных не хватает

        Raises:
            ValueError: если данные не являются TLS записью.
        """
        if len(data) < 5:
            return None
        elif data[0:1] not in cls.Type:
            raise ValueError("Not a TLS record")
        message_len = struct.unpack("!H", data[3:5])[0]
        if len(data) < message_len + 5:
            return None
        return cls(data)
