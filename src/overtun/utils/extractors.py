import typing as t

from overtun.intyperr import Address
from tlsex import TLSRecord, TLSMessage, TLSExtension
from tlsex.extensions import ServerName


def sni_extractor(data: bytes, port: int = 433) -> Address | None:
    """
    Извлекает SNI из TLS сообщения Client Hello.
    Отвечает интерфейсу `overtun.base.TargetDecoder`
    """
    if record := TLSRecord.load(data):
        if record.message.type != TLSMessage.Type.ClientHello:
            raise ValueError("Not a TLS Client Hello")
        if TLSExtension.Type.ServerName in record.message.extensions:
            sni = t.cast(ServerName, record.message.extensions[TLSExtension.Type.ServerName])
            return Address(sni.hostname, port)
        raise LookupError("SNI extension not found in TLS Handshake")
    return None
