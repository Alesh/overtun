import typing as t

from overtun.primitives import Address
from tlsex import TLSRecord, TLSMessage, TLSExtension
from tlsex.extensions import ServerName


class HandlersModule[A](t.Protocol):
    """
    Интерфейс модуля обработчиков преабулы.
    """

    @staticmethod
    def outlet_handler(
        preamble: bytes, extra_args: A | None = None
    ) -> tuple[Address | None, bytes] | None:
        """
        Обработчик преамбула входящего подключения к аутлету.

        Args:
            preamble: Данные преамбулы
            extra_args: Дополнительные данные для обработки преамбулы.

        Returns:
            `None` если полученных данных недостаточно для принятия решения.
            Кортеж из найденного адреса (`None` если не найден) и данных преамбулы, которые могли быть модифицированы.
        """

    @staticmethod
    def proxy_handler(
        preamble: bytes, extra_args: A | None = None
    ) -> tuple[Address | None, bytes] | None:
        """
        Обработчик преамбула входящего подключения к прокси.

        Args:
            preamble: Данные преамбулы
            extra_args: Дополнительные данные для обработки преамбулы.

        Returns:
            `None` если полученных данных недостаточно для принятия решения.
            Кортеж из найденного адреса (`None` если не найден) и данных преамбулы, которые могли быть модифицированы.
        """


def common_handler(preamble: bytes, _=None) -> tuple[Address | None, bytes] | None:
    """
    Обработчик преамбула входящего подключения к аутлету и прокси.

    Args:
        preamble: Данные преамбулы
        _: Дополнительных параметров для этой реализациинет

    Returns:
        `None` если полученных данных недостаточно для принятия решения.
        Кортеж из найденного адреса и данных преамбулы, которые могли быть модифицированы.
    """
    try:
        if (
            (tls := TLSRecord.load(preamble))
            and tls.type == TLSRecord.Type.Handshake
            and tls.message.type == TLSMessage.Type.ClientHello
        ):
            address = None
            if TLSExtension.Type.ServerName in tls.message.extensions:
                sni = t.cast(ServerName, tls.message.extensions[TLSExtension.Type.ServerName])
                address = Address.parse(sni.hostname, 443)
            return address, preamble
    except ValueError:
        return None


outlet_handler = common_handler
proxy_handler = common_handler
