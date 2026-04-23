import typing as t

from tlsex.utils import intrude_payload, extrude_payload
from overtun.handlers import if_tls_handshake, if_client_hello
from overtun.primitives import Address
from tlsex import TLSExtension
from tlsex.extensions import ServerName
from tlsex.messages import ClientHello


def outlet_handler(
    preamble: bytes, secret_key: bytes, _=None
) -> tuple[Address | None, bytes] | None:
    """
    Обработчик преамбула входящего подключения к аутлету.

    Args:
        preamble: Данные преамбулы.
        secret_key: Секретный ключ связывающий стороны туннеля.

    Returns:
        `None` если полученных данных недостаточно для принятия решения.
        Кортеж из найденного адреса и данных преамбулы, которые могли быть модифицированы.
    """
    if tls_record := if_tls_handshake(preamble):
        if client_hello := if_client_hello(tls_record):
            hostname, client_hello = _extrude_hostname(client_hello, secret_key)
            return Address.parse(hostname, 443), bytes(client_hello)
        raise TypeError(f"Unexpected TLS message type: {tls_record.message.type}")
    return None


def proxy_handler(
    preamble: bytes, outlet_address: Address = None, secret_key: bytes = None, _=None
) -> tuple[Address | None, bytes] | None:
    """
    Обработчик преамбула входящего подключения к прокси серверу.

    Args:
        preamble: Данные преамбулы.
        outlet_address: Адрес аутлета, включает режим туннелирования.
        secret_key: Секретный ключ связывающий стороны туннеля.

    Returns:
        `None` если полученных данных недостаточно для принятия решения.
        Кортеж из найденного адреса и данных преамбулы, которые могли быть модифицированы.
    """
    if tls_record := if_tls_handshake(preamble):
        if client_hello := if_client_hello(tls_record):
            if sn := t.cast(ServerName, client_hello.extensions.get(TLSExtension.Type.ServerName)):
                address = Address.parse(sn.hostname, 443)
                if outlet_address and secret_key:
                    return address, bytes(
                        _intrude_hostname(
                            sn.hostname, outlet_address.host, client_hello, secret_key
                        )
                    )
                return address, preamble
        raise TypeError(f"Unexpected TLS message type: {tls_record.message.type}")
    return None


def _get_biggest_extension(client_hello: ClientHello) -> TLSExtension.Type:
    sizes = dict()
    for extension in client_hello._extensions:
        if isinstance(extension, TLSExtension):
            if (size := len(extension) - 4) and extension.type != TLSExtension.Type.ServerName:
                sizes[extension.type] = size
    if found := sorted(sizes.items(), key=lambda a: a[1], reverse=True):
        return found[0][0]
    raise ValueError("TLS message has wrong extension list")


def _extrude_hostname(client_hello: ClientHello, secret_key: bytes) -> tuple[str, ClientHello]:
    hostname = b""
    modified = list()
    biggest_extension_type = _get_biggest_extension(client_hello)
    for extension in client_hello._extensions:
        if isinstance(extension, TLSExtension):
            if extension.type == biggest_extension_type:
                hostname, extension = extrude_payload(
                    extension,
                    lambda payload: _encode_payload(payload, secret_key, client_hello.nonce),
                )
                modified.append(extension)
                continue
            elif extension.type == TLSExtension.Type.ServerName:
                modified.append(None)
                continue
        modified.append(extension)
    if hostname:
        hostname = hostname.decode("utf8")
        index = modified.index(None)
        modified[index] = ServerName.create(hostname)
        return hostname, client_hello.rebuild_with_extensions(modified)
    raise ValueError("TLS message has wrong extension list")


def _intrude_hostname(
    hidden_name: str, fake_name: str, client_hello: ClientHello, secret_key: bytes
) -> ClientHello:
    modified = list()
    biggest_extension_type = _get_biggest_extension(client_hello)
    for extension in client_hello._extensions:
        if isinstance(extension, TLSExtension):
            if extension.type == biggest_extension_type:
                modified.append(
                    intrude_payload(
                        extension,
                        hidden_name.encode("utf8"),
                        lambda payload: _decode_payload(payload, secret_key, client_hello.nonce),
                    )
                )
                continue
            elif extension.type == TLSExtension.Type.ServerName:
                modified.append(ServerName.create(fake_name))
                continue
        modified.append(extension)
    return client_hello.rebuild_with_extensions(modified)


def _encode_payload(payload: bytes, secret_key: bytes, nonce: bytes) -> bytes:
    payload += b"ZZZ!"
    assert len(nonce) == len(secret_key) == 32
    size = len(payload)
    secret_key = (secret_key * (size // len(secret_key) + 1))[:size]
    nonce = (nonce * (size // len(nonce) + 1))[:size]
    return bytes(a ^ b ^ c for a, b, c in zip(secret_key, nonce, payload))


def _decode_payload(packed_payload: bytes, secret_key: bytes, nonce: bytes) -> bytes:
    assert len(nonce) == len(secret_key) == 32
    size = len(packed_payload)
    secret_key = (secret_key * (size // len(secret_key) + 1))[:size]
    nonce = (nonce * (size // len(nonce) + 1))[:size]
    payload = bytes(a ^ b ^ c for a, b, c in zip(secret_key, nonce, packed_payload))
    if payload.endswith(b"ZZZ!"):
        return payload[:-4]
    raise ValueError("Wrong payload")
