import asyncio
import typing as t
from collections.abc import Coroutine, Buffer
from ipaddress import IPv4Address, IPv6Address

from .primitives import Address


type Hostname = str | IPv4Address | IPv6Address


class Error(Exception):
    """Базовая ошибка пакета."""


class ProtocolError(Error):
    """Ошибка протокола."""


type OutcomingTransport = asyncio.Transport


class OutcomingFactory(t.Protocol):
    """
    Интерфейс функции или вызываемого объекта предназначенного для создания исходящего соединения.
    Если для заданного целевого адреса запрещено исходящее подключение, короутина должна вернуть `None`
    """

    def __call__(
        self, incoming_transport: asyncio.Transport, target_address: Address
    ) -> Coroutine[t.Any, t.Any, OutcomingTransport | None]:
        """
        Фабрика исходящего соединения.

        Args:
            incoming_transport: Транспорт входящего соединения.
            target_address: Целевой сетевой адрес.

        Returns:
            Короутина возвращающая транспорт исходящего соединения, или None.
        """


class OutcomingForwarder(t.Protocol):
    """
    Интерфейс функции или вызываемого объекта предназначенного для пересылки исходящего соединения.
    Может быть использована для можификации исходящих данных.
    """

    def __call__(self, outcoming_transport: asyncio.Transport, data: Buffer) -> None:
        """
        Пересылает данные в исходящее соединение.

        Args:
            outcoming_transport: Транспорт исходящего соединения.
            data: Блок данных
        """


class TargetResolver(t.Protocol):
    """
    Интерфейс функции или вызываемого объекта предназначенного для определения целевого адреса из
    данных преамбулы TLS трафика. Реализация также может быть применена для модификации преамбулы.
    """

    def __call__(self, preamble: Buffer, port: int = 443) -> tuple[Address, Buffer | None]:
        """
        Определяет целевой адрес, может поменять преамбулы TLS трафика.

        Args:
              preamble: Блок данных преамбулы TLS трафика.
              port: Порт по умолчанию для SNI.

        Returns:
            `None` если полученных данных недостаточно для принятия решения.
            Кортеж из найденного адреса и данных TLS преамбулы.
        """
