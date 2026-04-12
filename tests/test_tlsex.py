import typing as t
from tlsex import TLSRecord, TLSMessage, TLSExtension
from tlsex.messages import ClientHello


def test_tls_record(chromium_preamble):
    record = TLSRecord.load(chromium_preamble)
    assert record.type == TLSRecord.Type.Handshake
    assert record.message.type == TLSMessage.Type.ClientHello
    assert record.message.cipher_suites
    assert record.message.extensions.get(TLSExtension.Type.ServerName).hostname == "www.google.com"
    assert t.cast(ClientHello, record.message).ja3n() == "dcefaf3f0e71d260d19dc1d0749c9278"
