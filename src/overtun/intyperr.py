import asyncio
import typing as t
from collections.abc import Coroutine
from ipaddress import IPv4Address, IPv6Address

type Hostname = str | IPv4Address | IPv6Address


class Error(Exception):
    """Базовая ошибка пакета."""


class ProtocolError(Error):
    """Ошибка протокола."""


@t.runtime_checkable
class Address(t.Protocol):
    """
    Интерфейс объект содержащего сетевой адрес.
    """

    host: Hostname
    port: int

    def __str__(self) -> str:
        return (
            f"[{self.host}]:{self.port}"
            if isinstance(self.host, IPv6Address)
            else f"{self.host}:{self.port}"
        )


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
