import pytest

from tlsex import TLSRecord
from tlsex.entities import Extension
from tlsex.extensions import ServerName
from tlsex.messages import ClientHello, replace_extension, delete_extensions
from .samples_tls import CHROMIUM_PREAMBLE


@pytest.fixture
def chromium_preamble():
    return CHROMIUM_PREAMBLE


def test_message_rebuild_with_some(chromium_preamble):
    record = TLSRecord(chromium_preamble)
    assert record.type == TLSRecord.Type.Handshake

    if (client_hello := record.message) and isinstance(client_hello, ClientHello):
        if found := [e for e in client_hello.extensions if isinstance(e, ServerName)]:
            hostname = found[0].hostname
            extensions, poss = replace_extension(client_hello, ServerName.create(hostname))
            assert len(poss) == 1 and poss[0] >= 0
            rb_client_hello = client_hello.rebuild_with_extensions(extensions)
            rb_record = record.rebuild_with_message([rb_client_hello])
            assert bytes(rb_record) == bytes(record)
            assert rb_record.type == TLSRecord.Type.Handshake
            if (m_client_hello := rb_record.message) and isinstance(m_client_hello, ClientHello):
                assert bytes(m_client_hello) == bytes(rb_client_hello)
                return
    assert False


def test_message_rebuild_with_other(chromium_preamble):
    record = TLSRecord(chromium_preamble)
    assert record.type == TLSRecord.Type.Handshake

    if (client_hello := record.message) and isinstance(client_hello, ClientHello):
        extensions, poss = replace_extension(client_hello, ServerName.create("www.yandex.com"))
        assert len(poss) == 1 and poss[0] >= 0
        rb_client_hello = client_hello.rebuild_with_extensions(extensions)
        rb_record = record.rebuild_with_message([rb_client_hello])
        assert bytes(rb_record) != bytes(record)
        assert rb_record.type == TLSRecord.Type.Handshake

        if (m_client_hello := rb_record.message) and isinstance(m_client_hello, ClientHello):
            if found := [e for e in m_client_hello.extensions if isinstance(e, ServerName)]:
                assert found[0].hostname == "www.yandex.com"
                return
    assert False


def test_message_rebuild_with_fake(chromium_preamble):
    record = TLSRecord(chromium_preamble)
    assert record.type == TLSRecord.Type.Handshake

    if (client_hello := record.message) and isinstance(client_hello, ClientHello):
        if found := [e for e in client_hello.extensions if isinstance(e, ServerName)]:
            hostname = found[0].hostname
            extensions, poss = replace_extension(client_hello, ServerName.create(hostname))
            assert len(poss) == 1 and poss[0] >= 0
            rb_client_hello = client_hello.rebuild_with_extensions(
                [*extensions, Extension(memoryview(b"\xff\xff\x00\x00"))]
            )
            rb_record = record.rebuild_with_message([rb_client_hello])
            assert bytes(rb_record) != bytes(record)
            extensions, poss = delete_extensions(rb_client_hello, b"\xff\xff")
            assert len(poss) == 1 and poss[0] == len(extensions)
            rb_client_hello = rb_client_hello.rebuild_with_extensions(extensions)
            rb_record = record.rebuild_with_message([rb_client_hello])
            assert bytes(rb_record) == bytes(record)
