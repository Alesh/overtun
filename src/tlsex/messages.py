import struct
from collections.abc import Buffer
from enum import Enum

from .extensions import TLSExtension


class TLSMessage:
    """
    TLS Сообщение
    """

    class Type(bytes, Enum):
        """
        Типы TLS сообщений
        """

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

    def __init__(self, mv: memoryview):
        self._mv = mv

    @property
    def type(self):
        """Тип сообщения."""
        return TLSMessage.Type(self._mv[0:1])

    @property
    def nonce(self) -> Buffer:
        """Случайные 32 байта"""
        return self._mv[6:38]

    @staticmethod
    def select(mv: memoryview) -> "TLSMessage":
        """На основе данных создает экземпляр класса сообщения."""
        message_type = TLSMessage.Type(mv[5:6])
        match message_type:
            case TLSMessage.Type.ClientHello:
                return ClientHello(mv[5:])
            case _:
                return TLSMessage(mv[5:])


class ClientHello(TLSMessage):
    """
    Сообщение Client Hello
    """

    def __init__(self, mv: memoryview):
        ptr = 38 + 1 + mv[38]
        length = struct.unpack("!H", mv[ptr : ptr + 2])[0]
        self.__cipher_suites = (ptr + 2, ptr + 2 + length)
        ptr = ptr + 2 + length + 2
        self.__extensions = dict()
        length = struct.unpack("!H", mv[ptr : ptr + 2])[0]
        ptr = ptr + 2
        end_ptr = ptr + length
        while ptr + 4 <= end_ptr:
            key = TLSExtension.Type(mv[ptr : ptr + 2]) if mv[ptr : ptr + 2] in TLSExtension.Type else int.from_bytes(mv[ptr : ptr + 2])
            length = struct.unpack("!H", mv[ptr + 2 : ptr + 4])[0]
            self.__extensions[key] = TLSExtension.select(mv[ptr : ptr + 4 + length])
            ptr += 4 + length
        super().__init__(mv)

    @property
    def cipher_suites(self) -> Buffer:
        a, b = self.__cipher_suites
        return self._mv[a:b]

    @property
    def extensions(self) -> dict[TLSExtension.Type | Buffer, Buffer]:
        """Словарь расширений."""
        return self.__extensions
