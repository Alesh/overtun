import functools
import struct
import typing as t
from collections.abc import Sequence
from enum import Enum
import hashlib
from multiprocessing.spawn import prepare

from tlsex.extensions import (
    TLSExtension,
    ExTuple,
    SupportedGroups,
    EcPointFormats,
    SupportedVersions,
)


class TLSMessage:
    """
    TLS сообщение
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

    _mv: memoryview

    @functools.cached_property
    def type(self):
        """Тип сообщения."""
        return TLSMessage.Type(self._mv[0:1])

    @functools.cached_property
    def nonce(self) -> bytes:
        """Случайные 32 байта"""
        return bytes(self._mv[6:38])

    @classmethod
    def load(cls, mv: memoryview) -> t.Self:
        """Загружает TLS сообщение и создает экземпляр класса."""
        mv = mv[5:]
        if mv[0:1] in TLSMessage.Type:
            inst = cls()
            match TLSMessage.Type(mv[0:1]):
                case TLSMessage.Type.ClientHello:
                    inst = ClientHello(mv)
                case _:
                    pass
            inst._mv = mv
            return inst
        raise ValueError("Not a TLS record")


class CommonHello(TLSMessage):
    """
    Базовый класс для Hello сообщений.
    """

    _cs: tuple[int, int]
    _ex: tuple[int, int]

    @functools.cached_property
    def cipher_suites(self) -> tuple[int, ...]:
        """Идентификаторы поддерживаемых/выбранного алгоритма шифрования."""
        a, b = self._cs
        return tuple(
            struct.unpack("!H", self._mv[a + n : a + 2 + n])[0] for n in range(0, b - a, 2)
        )

    @functools.cached_property
    def extensions(self) -> ExTuple:
        """Предлагаемые/согласованные TLS расширения."""
        result = []
        ptr, end_ptr = self._ex
        while ptr < end_ptr:
            ext = TLSExtension.load(self._mv[ptr:])
            result.append(ext)
            ptr += len(ext)
        return ExTuple(result)


class ClientHello(CommonHello):
    """
    Клиентское сообщение Hello.
    """

    def __init__(self, mv: memoryview):
        # (Смещение до SessionID) + (Поле размера SessionID) + (Размер SessionID)
        ptr = 38 + 1 + mv[38]  # Смещение после SessionID
        (cs_length,) = struct.unpack("!H", mv[ptr : ptr + 2])
        self._cs = (ptr + 2, ptr + 2 + cs_length)
        # + (Поле размера Cipher Suites) + (Размер Cipher Suites) + CompressionMethods
        ptr = ptr + 2 + cs_length + 2  # Смешение после Cipher Suites и CompressionMethods
        (ex_length,) = struct.unpack("!H", mv[ptr : ptr + 2])
        self._ex = (ptr + 2, ptr + 2 + ex_length)

    def _ja3(self) -> Sequence[Sequence[int]]:
        result = []
        result.append(list(struct.unpack("!H", self._mv[4:6])))
        result.append(self.cipher_suites)
        result.append(sum(tuple(struct.unpack("!H", ex._mv[0:2]) for ex in self.extensions), ()))
        result.append([])
        if sg := t.cast(SupportedGroups, self.extensions.get(TLSExtension.Type.SupportedGroups)):
            result[-1].extend(sg.curves)
        result.append([])
        if ecf := t.cast(EcPointFormats, self.extensions.get(TLSExtension.Type.EcPointFormats)):
            result[-1].extend(ecf.formats)
        return result

    def ja3n(self):
        """Рассчитывает цифровой отпечаток JA3N."""
        parts = self._ja3()
        if sv := t.cast(
            SupportedVersions, self.extensions.get(TLSExtension.Type.SupportedVersions)
        ):
            parts[0] = [sorted(v for v in sv.versions if (v & 0x0F0F) != 0x0A0A)[-1]]
        return hashlib.md5(
            ",".join(
                "-".join(map(str, item)) for item in [
                    parts[0],
                    [v for v in parts[1] if (v & 0x0F0F) != 0x0A0A],
                    [v for v in sorted(parts[2]) if (v & 0x0F0F) != 0x0A0A],
                    [v for v in parts[3] if (v & 0x0F0F) != 0x0A0A],
                    parts[4],
                ]
            ).encode("ascii")
        ).hexdigest()  # fmt: off
