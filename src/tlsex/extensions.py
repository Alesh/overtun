import struct
from enum import Enum


class TLSExtension:
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
        ClientCertificateUrl = b"\x00\x02"
        TrustedCaKeys = b"\x00\x03"
        StatusRequest = b"\x00\x05"
        UserMapping = b"\x00\x06"
        SupportedGroups = b"\x00\n"
        EcPointFormats = b"\x00\x0b"
        SignatureAlgorithms = b"\x00\r"
        UseSrtp = b"\x00\x0e"
        Heartbeat = b"\x00\x0f"
        ApplicationLayerProtocolNegotiation = b"\x00\x10"
        StatusRequestV2 = b"\x00\x11"
        ClientCertificateType = b"\x00\x13"
        ServerCertificateType = b"\x00\x14"
        Padding = b"\x00\x15"
        EncryptThenMac = b"\x00\x16"
        ExtendedMainSecret = b"\x00\x17"
        TokenBinding = b"\x00\x18"
        CachedInfo = b"\x00\x19"
        CompressCertificate = b"\x00\x1b"
        RecordSizeLimit = b"\x00\x1c"
        DelegatedCredential = b'\x00"'
        SessionTicket = b"\x00#"
        SupportedEktCiphers = b"\x00'"
        PreSharedKey = b"\x00)"
        EarlyData = b"\x00*"
        SupportedVersions = b"\x00+"
        Cookie = b"\x00,"
        PskKeyExchangeModes = b"\x00-"
        CertificateAuthorities = b"\x00/"
        OidFilters = b"\x000"
        PostHandshakeAuth = b"\x001"
        SignatureAlgorithmsCert = b"\x002"
        KeyShare = b"\x003"
        TransparencyInfo = b"\x004"
        ExternalIdHash = b"\x007"
        ExternalSessionId = b"\x008"
        QuicTransportParameters = b"\x009"
        TicketRequest = b"\x00:"
        EchOuterExtensions = b"\xfd\x00"
        EncryptedClientHello = b"\xfe\x0d"
        RenegotiationInfo = b"\xff\x01"

    def __init__(self, mv: memoryview):
        self._mv = mv

    @property
    def type(self):
        """Тип сообщения."""
        return TLSExtension.Type(self._mv[0:2])

    @staticmethod
    def select(mv: memoryview) -> "TLSExtension":
        """На основе данных создает экземпляр класса расширения."""
        message_type = TLSExtension.Type(mv[0:2])
        match message_type:
            case TLSExtension.Type.ServerName:
                return ServerName(mv)
            case _:
                return TLSExtension(mv)


class ServerName(TLSExtension):
    """
    SNI Расширение содержит имя целевого хоста
    """

    def __init__(self, mv: memoryview):
        # SNI List Len(2), Type(1), Name Len(2)
        ptr = 4
        self.__names = list()
        list_length = struct.unpack("!H", mv[ptr : ptr + 2])[0]
        ptr += 2
        while ptr + 6 < list_length:
            # type = mv[ptr : ptr + 1]
            length = struct.unpack("!H", mv[ptr + 1 : ptr + 3])[0]
            self.__names.append(mv[ptr + 3 : ptr + 3 + length])
            ptr += 3 + length
        super().__init__(mv)

    @property
    def hostname(self) -> str | None:
        """Имена сервера"""
        return bytes(self.__names[0]).decode("ascii") if self.__names else None
