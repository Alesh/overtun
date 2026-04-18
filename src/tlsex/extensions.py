import functools
import inspect
import struct
import typing as t
from collections.abc import Buffer, Sized
from enum import Enum


class UnknownExtension(Buffer, Sized):
    """
    Неопознанное расширение
    """

    _mv: memoryview

    def __init__(self, buffer: Buffer):
        mv = memoryview(buffer).toreadonly()
        (length,) = struct.unpack("!H", mv[2:4])
        self._mv = mv[: 4 + length]

    def __str__(self):
        return f"U/E[{''.join([f'{ch:02X}' for ch in self._mv[0:2]])}]"

    def __bytes__(self):
        return bytes(self._mv)

    def __buffer__(self, flags, /):
        if flags & inspect.BufferFlags.WRITABLE:
            raise BufferError("This is readonly buffer")
        return self._mv

    def __len__(self):
        return len(self._mv)


class Grease(UnknownExtension):
    """
    GREASE https://datatracker.ietf.org/doc/html/rfc8701
    """

    def __new__(cls, value: memoryview):
        if (struct.unpack("!H", value[0:2])[0] & 0x0F0F) != 0x0A0A:
            return super().__new__(cls)
        return UnknownExtension(value)

    def __str__(self):
        return f"GREASE{super().__str__()[3:]}"


class TLSExtension(UnknownExtension):
    """
    TLS Расширение
    """

    class Type(bytes, Enum):
        """
        Типы TLS расширений

        Определены только рекомендованные сообщения.
        https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
        """

        ServerName = b"\x00\x00"
        MaxFragmentLength = b"\x00\x01"
        ClientCertificateUrl = b"\x00\x02"
        TrustedCaKeys = b"\x00\x03"
        TruncatedHmac = b"\x00\x04"
        StatusRequest = b"\x00\x05"
        UserMapping = b"\x00\x06"
        ClientAuthz = b"\x00\x07"
        ServerAuthz = b"\x00\x08"
        CertType = b"\x00\x09"
        SupportedGroups = b"\x00\x0a"  # ранее "EllipticCurves"
        EcPointFormats = b"\x00\x0b"
        Srp = b"\x00\x0c"
        SignatureAlgorithms = b"\x00\x0d"
        UseSrtp = b"\x00\x0e"
        Heartbeat = b"\x00\x0f"
        ApplicationLayerProtocolNegotiation = b"\x00\x10"
        StatusRequestV2 = b"\x00\x11"
        SignedCertificateTimestamp = b"\x00\x12"
        ClientCertificateType = b"\x00\x13"
        ServerCertificateType = b"\x00\x14"
        Padding = b"\x00\x15"
        EncryptThenMac = b"\x00\x16"
        ExtendedMainSecret = b"\x00\x17"
        TokenBinding = b"\x00\x18"
        CachedInfo = b"\x00\x19"
        TlsLts = b"\x00\x1a"
        CompressCertificate = b"\x00\x1b"
        RecordSizeLimit = b"\x00\x1c"
        PwdProtect = b"\x00\x1d"
        PwdClear = b"\x00\x1e"
        PasswordSalt = b"\x00\x1f"
        TicketPinning = b"\x00\x20"
        TlsCertWithExternPsk = b"\x00\x21"
        DelegatedCredential = b"\x00\x22"
        SessionTicket = b"\x00\x23"  # ранее "SessionTicket TLS"
        Tlmsp = b"\x00\x24"
        TlmspProxying = b"\x00\x25"
        TlmspDelegate = b"\x00\x26"
        SupportedEktCiphers = b"\x00\x27"
        # Value 0x28 (40) - Reserved
        PreSharedKey = b"\x00\x29"
        EarlyData = b"\x00\x2a"
        SupportedVersions = b"\x00\x2b"
        Cookie = b"\x00\x2c"
        PskKeyExchangeModes = b"\x00\x2d"
        # Value 0x2e (46) - Reserved
        CertificateAuthorities = b"\x00\x2f"
        OidFilters = b"\x00\x30"
        PostHandshakeAuth = b"\x00\x31"
        SignatureAlgorithmsCert = b"\x00\x32"
        KeyShare = b"\x00\x33"
        TransparencyInfo = b"\x00\x34"
        ConnectionIdDeprecated = b"\x00\x35"  # deprecated
        ConnectionId = b"\x00\x36"
        ExternalIdHash = b"\x00\x37"
        ExternalSessionId = b"\x00\x38"
        QuicTransportParameters = b"\x00\x39"
        TicketRequest = b"\x00\x3a"
        DnssecChain = b"\x00\x3b"
        SequenceNumberEncryptionAlgorithms = b"\x00\x3c"
        Rrc = b"\x00\x3d"
        TlsFlags = b"\x00\x3e"
        EchOuterExtensions = b"\xfd\x00"
        EncryptedClientHello = b"\xfe\x0d"
        RenegotiationInfo = b"\xff\x01"

        @property
        def number(self):
            return struct.unpack("!H", self)[0]

    def __str__(self):
        return f"{self.type.name}{super().__str__()[3:]}"

    @functools.cached_property
    def type(self) -> Type:
        """Тип расширения."""
        return TLSExtension.Type(self._mv[0:2])

    @staticmethod
    def load(mv: memoryview) -> UnknownExtension:
        """Загружает TLS расширение и создает экземпляр класса."""
        if mv[0:2] in TLSExtension.Type:
            match TLSExtension.Type(mv[0:2]):
                case TLSExtension.Type.ServerName:
                    return ServerName(mv)
                case TLSExtension.Type.SupportedGroups:
                    return SupportedGroups(mv)
                case TLSExtension.Type.EcPointFormats:
                    return EcPointFormats(mv)
                case TLSExtension.Type.SupportedVersions:
                    return SupportedVersions(mv)
                case _:
                    return TLSExtension(mv)
        return Grease(mv)


class ExTuple(tuple[TLSExtension | Grease | UnknownExtension]):
    """
    Список расширений
    """

    def get(self, key: TLSExtension.Type) -> TLSExtension | None:
        """Возвращает расширение заданного типа или `None` Если не найденное"""
        if isinstance(key, TLSExtension.Type):
            if found := [e for e in self if isinstance(e, TLSExtension) and e.type == key]:
                return found[0]
        return None


class ServerName(TLSExtension):
    """
    SNI Расширение содержит имя целевого хоста
    """

    def __init__(self, mv: memoryview):
        super().__init__(mv)
        ptr = 4  # Смещение после заголовка (тип, длина)
        # По факту передается только одно имя и одного типа `hostname`
        ptr += 3
        (length,) = struct.unpack("!H", mv[ptr : ptr + 2])
        self.__hostname = (ptr + 2, ptr + 2 + length)

    @functools.cached_property
    def hostname(self) -> str:
        """Имя хоста."""
        a, b = self.__hostname
        return bytes(self._mv[a:b]).decode("utf8")

    @classmethod
    def create(cls, hostname: str) -> t.Self:
        hostname = str(hostname).encode("utf8")
        body = b"\0" + struct.pack("!H", len(hostname)) + hostname
        body = struct.pack("!H", len(body)) + body
        return ServerName(
            memoryview(TLSExtension.Type.ServerName + struct.pack("!H", len(body)) + body)
        )


class SupportedGroups(TLSExtension):
    @functools.cached_property
    def _curves(self) -> tuple[int, ...]:
        return sum(
            tuple(struct.unpack("!H", self._mv[n : n + 2]) for n in range(6, len(self), 2)), ()
        )

    @functools.cached_property
    def curves(self) -> tuple[int, ...]:
        return tuple(cv for cv in self._curves if (cv & 0x0F0F) != 0x0A0A)


class EcPointFormats(TLSExtension):
    @functools.cached_property
    def formats(self) -> tuple[int, ...]:
        return tuple(self._mv[n] for n in range(5, len(self)))


class SupportedVersions(TLSExtension):
    @functools.cached_property
    def versions(self) -> tuple[bytes, ...]:
        values = tuple(struct.unpack("!H", self._mv[n : n + 2])[0] for n in range(5, len(self), 2))
        return tuple(struct.pack("!H", v) for v in values if (v & 0x0F0F) != 0x0A0A)
