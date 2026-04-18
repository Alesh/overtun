import typing as t

import pytest

from tlsex import TLSMessage, TLSRecord
from tlsex.extensions import ServerName
from tlsex.messages import ClientHello
from .samples_tls import CHROMIUM_PREAMBLE


@pytest.fixture
def chromium_preamble():
    return CHROMIUM_PREAMBLE


def test_chromium_tls_record(chromium_preamble):
    record = TLSRecord(chromium_preamble)
    assert record.type == TLSRecord.Type.Handshake
    assert record.message.type == TLSMessage.Type.ClientHello
    assert record.message.version == TLSMessage.Version.TLS12  # TODO: switch to TLSMessage.Version.TLS13

    client_hello = t.cast("ClientHello", record.message)
    assert len(client_hello.cipher_suites) == 15 and len(client_hello._cipher_suites) == 16
    assert len(client_hello.extensions) == 15 and len(client_hello._extensions) == 18
    if found := [ex for ex in client_hello.extensions if isinstance(ex, ServerName)]:
        server_name_ex = found[0]
        assert server_name_ex.hostname == "www.google.com"
    assert found
