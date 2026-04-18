import typing as t
from tlsex import TLSRecord, TLSMessage, TLSExtension
from tlsex.extensions import ServerName, UnknownExtension
from tlsex.messages import ClientHello


def test_chromium_tls_record(chromium_preamble):
    record = TLSRecord.load(chromium_preamble)
    assert record.type == TLSRecord.Type.Handshake
    assert record.message.type == TLSMessage.Type.ClientHello
    assert bytes(record.message) == bytes(record)
    assert record.message.version == TLSMessage.Version.TSL13
    assert record.message.cipher_suites
    assert record.message.extensions.get(TLSExtension.Type.ServerName).hostname == "www.google.com"
    assert t.cast(ClientHello, record.message).ja3n() == "dcefaf3f0e71d260d19dc1d0749c9278"


def test_yandex_tls_record(yandex_preamble):
    record = TLSRecord.load(yandex_preamble)
    assert record.type == TLSRecord.Type.Handshake
    assert record.message.type == TLSMessage.Type.ClientHello
    assert t.cast(ClientHello, record.message).ja3n() == "dcefaf3f0e71d260d19dc1d0749c9278"


def test_chrome_tls_record(chrome_preamble):
    record = TLSRecord.load(chrome_preamble)
    assert record.type == TLSRecord.Type.Handshake
    assert record.message.type == TLSMessage.Type.ClientHello
    assert t.cast(ClientHello, record.message).ja3n() == "dcefaf3f0e71d260d19dc1d0749c9278"


def test_httpx_tls_record(httpx_preamble):
    record = TLSRecord.load(httpx_preamble)
    assert record.type == TLSRecord.Type.Handshake
    assert record.message.type == TLSMessage.Type.ClientHello
    assert record.message.version == TLSMessage.Version.TSL13
    assert t.cast(ClientHello, record.message).ja3n() == "3ff5fd1bd2637a180e8531a9d3fd51ce"


def test_tls12_tls_record(tls12_preamble):
    record = TLSRecord.load(tls12_preamble)
    assert record.type == TLSRecord.Type.Handshake
    assert record.message.type == TLSMessage.Type.ClientHello
    assert record.message.version == TLSMessage.Version.TSL12
    assert t.cast(ClientHello, record.message).ja3n() == "050df79362a524f556e761ce0eb9f1d5"


def test_create_ServerName(chromium_preamble):
    record = TLSRecord.load(chromium_preamble)
    server_name = record.message.extensions.get(TLSExtension.Type.ServerName)
    assert bytes(server_name) == bytes(ServerName.create("www.google.com"))

def test_rebuild_ClientHello(chromium_preamble):
    record = TLSRecord.load(chromium_preamble)
    if record.type == TLSRecord.Type.Handshake and record.message.type == TLSMessage.Type.ClientHello:
        client_hello = t.cast(ClientHello, record.message)
    else:
        assert False
    extensions = [UnknownExtension(bytes(ex)) for ex in client_hello._extensions]
    rebuilt_client_hello = client_hello.rebuild_with_extensions(extensions)
    assert rebuilt_client_hello.cipher_suites == client_hello.cipher_suites
    assert bytes(rebuilt_client_hello) == bytes(client_hello)
