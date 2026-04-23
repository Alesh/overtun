import functools
import hashlib
import struct
import typing as t
from collections.abc import Sequence, Buffer
from enum import Enum

from tlsex.extensions import (
    TLSExtension,
    ExTuple,
    SupportedGroups,
    EcPointFormats,
    SupportedVersions,
    UnknownExtension,
)


class TLSMessage:
    """
    TLS сообщение
    """

    class Version(bytes, Enum):
        """
        TSL Версия
        """

        TSL12 = b"\x03\x03"
        TSL13 = b"\x03\x04"

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

    def __init__(self, buffer: Buffer):
        self._mv = memoryview(buffer)

    def __bytes__(self):
        return bytes(self._mv.obj)

    @functools.cached_property
    def type(self):
        """Тип сообщения."""
        return TLSMessage.Type(self._mv[0:1])

    @functools.cached_property
    def version(self):
        """Версия"""
        return TLSMessage.Version(self._mv[4:6])

    @functools.cached_property
    def nonce(self) -> bytes:
        """Случайные 32 байта"""
        return bytes(self._mv[6:38])

    @staticmethod
    def load(mv: memoryview) -> "TLSMessage":
        """Загружает TLS сообщение и создает экземпляр класса."""
        mv = mv[5:]
        if mv[0:1] in TLSMessage.Type:
            match TLSMessage.Type(mv[0:1]):
                case TLSMessage.Type.ClientHello:
                    return ClientHello(mv)
                case _:
                    return TLSMessage(mv)
        raise ValueError("Not a TLS record")


class CommonHello(TLSMessage):
    """
    Базовый класс для Hello сообщений.
    """

    _cs: tuple[int, int]
    _ex: tuple[int, int]

    @functools.cached_property
    def _cipher_suites(self) -> tuple[int, ...]:
        a, b = self._cs
        return tuple(
            struct.unpack("!H", self._mv[a + n : a + 2 + n])[0] for n in range(0, b - a, 2)
        )

    @functools.cached_property
    def cipher_suites(self) -> tuple[int, ...]:
        """Идентификаторы поддерживаемых/выбранного алгоритма шифрования."""
        return tuple(cs for cs in self._cipher_suites if (cs & 0x0F0F) != 0x0A0A)

    @functools.cached_property
    def _extensions(self) -> tuple[UnknownExtension, ...]:
        result = []
        ptr, end_ptr = self._ex
        while ptr < end_ptr:
            ext = TLSExtension.load(self._mv[ptr:])
            result.append(ext)
            ptr += len(ext)
        return tuple(result)

    @functools.cached_property
    def extensions(self) -> ExTuple:
        """Предлагаемые/согласованные TLS расширения."""
        return ExTuple(ex for ex in self._extensions if isinstance(ex, TLSExtension))

    def rebuild_with_extensions(self, extensions: Sequence[UnknownExtension]) -> t.Self:
        """Пересобирает сообщение с новым набором расширений."""
        ptr = self._ex[0] - 2
        # extensions = []
        body = b"".join([bytes(extension) for extension in extensions])
        body = struct.pack("!H", len(body)) + body
        new = self.__class__.load(memoryview(bytes(self)[0 : ptr + 5] + body))
        return new


class ClientHello(CommonHello):
    """
    Клиентское сообщение Hello.
    """

    def __init__(self, mv: memoryview):
        super().__init__(mv)
        # (Смещение до SessionID) + (Поле размера SessionID) + (Размер SessionID)
        ptr = 38 + 1 + mv[38]  # Смещение после SessionID
        (cs_length,) = struct.unpack("!H", mv[ptr : ptr + 2])
        self._cs = (ptr + 2, ptr + 2 + cs_length)
        # + (Поле размера Cipher Suites) + (Размер Cipher Suites) + CompressionMethods
        ptr = ptr + 2 + cs_length + 2  # Смешение после Cipher Suites и CompressionMethods
        (ex_length,) = struct.unpack("!H", mv[ptr : ptr + 2])
        self._ex = (ptr + 2, ptr + 2 + ex_length)

    @functools.cached_property
    def version(self):
        """Версия"""
        if sv := t.cast(
            SupportedVersions, self.extensions.get(TLSExtension.Type.SupportedVersions)
        ):
            return TLSMessage.Version(sorted(sv.versions)[-1])
        return super().version

    def _ja3(self) -> Sequence[Sequence[int]]:
        result = []
        result.append(list(struct.unpack("!H", self._mv[4:6])))
        result.append(self._cipher_suites)
        result.append(sum(tuple(struct.unpack("!H", ex._mv[0:2]) for ex in self._extensions), ()))
        result.append([])
        if sg := t.cast(SupportedGroups, self.extensions.get(TLSExtension.Type.SupportedGroups)):
            result[-1].extend(sg._curves)
        result.append([])
        if ecf := t.cast(EcPointFormats, self.extensions.get(TLSExtension.Type.EcPointFormats)):
            result[-1].extend(ecf.formats)
        return result

    def ja3n(self):
        """Рассчитывает цифровой отпечаток JA3N."""
        parts = self._ja3()
        return hashlib.md5(
            ",".join(
                "-".join(map(str, item)) for item in [
                    [struct.unpack("!H", self.version)[0]],
                    [v for v in parts[1] if (v & 0x0F0F) != 0x0A0A],
                    [v for v in sorted(parts[2]) if (v & 0x0F0F) != 0x0A0A],
                    [v for v in parts[3] if (v & 0x0F0F) != 0x0A0A],
                    parts[4],
                ]
            ).encode("ascii")
        ).hexdigest()  # fmt: off
