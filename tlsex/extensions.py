import functools
import struct
from collections.abc import Sequence, Buffer
from enum import Enum

from tlsex.entities import Extension


class TLSExtension(Extension):
    """TLS extension."""

    class Type(bytes, Enum):
        """TLS extension type codes.
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
        SupportedGroups = b"\x00\x0a"  # formerly "EllipticCurves"
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
        SessionTicket = b"\x00\x23"  # formerly "SessionTicket TLS"
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

    def __str__(self) -> str:
        return f"{self.type.name}{super().__str__()[-6:]}"

    @functools.cached_property
    def type(self) -> Type:
        """Extension type."""
        return TLSExtension.Type(self._mv[0:2])

    @classmethod
    def make_collections(cls, buffer: Buffer, /) -> tuple[Extension, ...]:
        """Build a collections of Extension objects from a buffer."""
        ptr = 0
        extensions = []
        mv = memoryview(buffer).toreadonly()
        while ptr < len(mv):
            type_ = bytes(mv[ptr : ptr + 2])
            (length,) = struct.unpack("!H", bytes(mv[ptr + 2 : ptr + 4]))
            if type_ in TLSExtension.Type:
                match TLSExtension.Type(type_):
                    case TLSExtension.Type.ServerName:
                        extensions.append(ServerName(mv[ptr : ptr + length + 4]))
                    case _:
                        extensions.append(TLSExtension(mv[ptr : ptr + length + 4]))
            else:
                extensions.append(Extension(mv[ptr : ptr + length + 4]))
            ptr += length + 4
        return tuple(extensions)


class ServerName(TLSExtension):
    """SNI extension containing the target hostname."""

    def __init__(self, mv: memoryview) -> None:
        super().__init__(mv)
        ptr = 4  # Offset past the header (type, length)
        self.__hostnames = []
        (length,) = struct.unpack("!H", mv[ptr : ptr + 2])
        ptr += 2
        end_ptr = ptr + length
        while ptr < end_ptr:
            # assert mv[ptr] == 0, " name type != 0 (host_name)"
            ptr += 1
            (length,) = struct.unpack("!H", mv[ptr : ptr + 2])
            self.__hostnames.append((ptr + 2, ptr + 2 + length))
            ptr += 2 + length
        if not self.__hostnames:
            raise ValueError("Not found any hostname in extensions")

    @functools.cached_property
    def _hostnames(self) -> Sequence[str]:
        return tuple(bytes(self._mv[a:b]).decode("utf8") for a, b in self.__hostnames)

    @functools.cached_property
    def hostname(self) -> str:
        """Target hostname."""
        return self._hostnames[0]
