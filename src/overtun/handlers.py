import typing as t

from overtun.primitives import Address
from tlsex import TLSRecord, TLSMessage, TLSExtension
from tlsex.extensions import ServerName
from tlsex.messages import ClientHello


class HandlersModule[A](t.Protocol):
    """
    Интерфейс модуля обработчиков преамбулы.
    """

    @staticmethod
    def outlet_handler(
        preamble: bytes, secret_key: bytes, extra_args: A | None = None
    ) -> tuple[Address | None, bytes] | None:
        """
        Обработчик преамбула входящего подключения к аутлету.

        Args:
            preamble: Данные преамбулы.
            secret_key: Секретный ключ связывающий стороны туннеля.
            extra_args: Дополнительные данные для обработки преамбулы.

        Returns:
            `None` если полученных данных недостаточно для принятия решения.
            Кортеж из найденного адреса (`None` если не найден) и данных преамбулы, которые могли быть модифицированы.
        """

    @staticmethod
    def proxy_handler(
        preamble: bytes,
        outlet_address: Address | None = None,
        secret_key: bytes | None = None,
        extra_args: A | None = None,
    ) -> tuple[Address | None, bytes] | None:
        """
        Обработчик преамбула входящего подключения к прокси.

        Args:
            preamble: Данные преамбулы.
            outlet_address: Адрес аутлета, включает режим туннелирования.
            secret_key: Секретный ключ связывающий стороны туннеля.
            extra_args: Дополнительные данные для обработки преамбулы.

        Returns:
            `None` если полученных данных недостаточно для принятия решения.
            Кортеж из найденного адреса (`None` если не найден) и данных преамбулы, которые могли быть модифицированы.
        """


def if_tls_handshake(preamble: bytes) -> TLSRecord | None:
    if (tls_record := TLSRecord.load(preamble)) and tls_record.type == TLSRecord.Type.Handshake:
        return tls_record
    return None


def if_client_hello(tls_record: TLSRecord) -> ClientHello | None:
    if tls_record.message.type == TLSMessage.Type.ClientHello:
        return t.cast(ClientHello, tls_record.message)
    raise RuntimeError(f"Unexpected TLS message: {tls_record.message}")


def outlet_handler(
    preamble: bytes, _secret_key: bytes, _extra_args=None
) -> tuple[Address | None, bytes] | None:
    """
    Обработчик преамбула входящего подключения к аутлету.

    Args:
        preamble: Данные преамбулы.

    Returns:
        `None` если полученных данных недостаточно для принятия решения.
        Кортеж из найденного адреса и данных преамбулы, которые могли быть модифицированы.
    """
    if tls_record := if_tls_handshake(preamble):
        if client_hello := if_client_hello(tls_record):
            if sn := t.cast(ServerName, client_hello.extensions.get(TLSExtension.Type.ServerName)):
                address = Address.parse(sn.hostname, 443)
                return address, bytes(tls_record)
        raise TypeError(f"Unexpected TLS message type: {tls_record.message.type}")
    return None


def proxy_handler(
    preamble: bytes, _outlet_address=None, _secret_key=None, _extra_args=None
) -> tuple[Address | None, bytes] | None:
    """
    Обработчик преамбула входящего подключения к прокси серверу.

    Args:
        preamble: Данные преамбулы.

    Returns:
        `None` если полученных данных недостаточно для принятия решения.
        Кортеж из найденного адреса и данных преамбулы, которые могли быть модифицированы.
    """
    if tls_record := if_tls_handshake(preamble):
        if client_hello := if_client_hello(tls_record):
            if sn := t.cast(ServerName, client_hello.extensions.get(TLSExtension.Type.ServerName)):
                address = Address.parse(sn.hostname, 443)
                return address, preamble
        raise TypeError(f"Unexpected TLS message type: {tls_record.message.type}")
    return None
