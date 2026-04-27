import struct

import overtun.primitives
from tlsex import TLSRecord, TLSExtension
from tlsex.extensions import ServerName
from tlsex.messages import ClientHello, replace_extension, delete_extensions


def put_to_extension(extype: TLSExtension.Type, data: bytes) -> TLSExtension:
    return TLSExtension(memoryview(extype + struct.pack("!H", len(data)) + data))


def get_from_extension(ex: TLSExtension) -> bytes:
    return bytes(ex)[4:]


class Tunnel(overtun.primitives.Tunnel[int | None]):
    """Sample masked tunnel."""

    def seal_traffic_preamble(self, preamble: bytes, extra: int | None = None) -> bytes | None:
        if extra == 1:
            if tls_record := TLSRecord(preamble):
                if (client_hello := tls_record.message) and isinstance(client_hello, ClientHello):
                    if found := [ex for ex in client_hello.extensions if isinstance(ex, ServerName)]:
                        masked_host = self._encode_payload(
                            found[0].hostname.encode(), tls_record.message.nonce
                        )
                        extensions, _ = replace_extension(
                            client_hello, ServerName.create(str(self.egress_address.host))
                        )
                        new_record = tls_record.rebuild_with_message(
                            [
                                client_hello.rebuild_with_extensions(
                                    [
                                        *extensions,
                                        put_to_extension(
                                            TLSExtension.Type.ConnectionIdDeprecated, masked_host
                                        ),
                                    ]
                                )
                            ]
                        )
                        return super().seal_traffic_preamble(bytes(new_record))
            raise ValueError("Wrong TLS record")
        return super().seal_traffic_preamble(preamble)

    def unseal_traffic_preamble(self, preamble: bytes) -> bytes | None:
        if tls_record := TLSRecord(preamble):
            if (client_hello := tls_record.message) and isinstance(client_hello, ClientHello):
                if found := [
                    ex
                    for ex in client_hello.extensions
                    if ex.type == TLSExtension.Type.ConnectionIdDeprecated
                ]:
                    masked_host = get_from_extension(found[0])
                    host = self._decode_payload(masked_host, client_hello.nonce).decode()
                    extensions, _ = replace_extension(client_hello, ServerName.create(host))
                    client_hello = client_hello.rebuild_with_extensions(extensions)
                    extensions, _ = delete_extensions(client_hello, TLSExtension.Type.ConnectionIdDeprecated)
                    client_hello = client_hello.rebuild_with_extensions(extensions)
                    new_record = tls_record.rebuild_with_message([client_hello])
                    return super().unseal_traffic_preamble(bytes(new_record))
            return super().unseal_traffic_preamble(preamble)
        raise ValueError("Wrong TLS record")

    def _encode_payload(self, payload: bytes, nonce: bytes) -> bytes:
        payload += b"ZZZ!"
        assert len(nonce) == len(self.secret_key) == 32
        size = len(payload)
        secret_key = (self.secret_key * (size // len(self.secret_key) + 1))[:size]
        nonce = (nonce * (size // len(nonce) + 1))[:size]
        return bytes(a ^ b ^ c for a, b, c in zip(secret_key, nonce, payload))

    def _decode_payload(self, packed_payload: bytes, nonce: bytes) -> bytes:
        assert len(nonce) == len(self.secret_key) == 32
        size = len(packed_payload)
        secret_key = (self.secret_key * (size // len(self.secret_key) + 1))[:size]
        nonce = (nonce * (size // len(nonce) + 1))[:size]
        payload = bytes(a ^ b ^ c for a, b, c in zip(secret_key, nonce, packed_payload))
        if payload.endswith(b"ZZZ!"):
            return payload[:-4]
        raise ValueError("Wrong payload")
