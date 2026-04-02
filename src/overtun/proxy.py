import asyncio
import typing as t
from asyncio import Server, Event
from collections.abc import Awaitable
from contextlib import AbstractAsyncContextManager
from enum import Enum

import overtun.utils.registers
from overtun.intyperr import Address
from overtun.protocols import ProxyProtocol, Protocol, OutcomingProtocol


class ConnectionRule(int, Enum):
    """
    Правила обработки клиентского запроса:

    Attributes:
        Reset: Клиентское соединение закрывается без обработки.
        Direct: Подключение к целевому адресу производится с прокси сервера.
        Tunnel: Подключение к целевому адресу производится через удаленный узел (outlet).
    """

    Reset = 0
    Direct = 1
    Tunnel = 2


class TargetRule(t.NamedTuple):
    """
    Правила подключения к целевому адресу
    """

    target: Address
    connection_rule: ConnectionRule


assert isinstance(TargetRule(Address("127.0.0.1", 443), ConnectionRule.Reset), overtun.utils.registers.AddressInfo)


class TargetsRegister[T: TargetRule](overtun.utils.registers.AddressInfoRegister):
    pass


class ProxyServer(AbstractAsyncContextManager[t.Self, None], Awaitable[None]):
    """
    Прокси-сервер
    """

    ProxyProtocol = ProxyProtocol
    OutcomingProtocol = OutcomingProtocol

    def __init__(
        self,
        address: Address,
        *addresses: Address,
        outlet: Address | None = None,
        register: TargetsRegister | None = None,
        connection_rule: ConnectionRule = ConnectionRule.Direct,
    ):
        """
        Конструктор

        Args:
            address: основной адрес для клиентских подключений.
            *addresses: дополнительные адреса для клиентских подключений.

            outlet:
                Адрес "выхода" из туннеля.
                Если задано, реализуется функционал туннелирующего прокси сервера.

            register:
                Регистр с информацией и правилами обработки подключения к целевым хостам.
                Если задано, реализуется функционал селективного прокси сервера.

            connection_rule: Правила обработки подключения к целевым хостам по умолчанию.

        """
        self._servers: list[Server] = list()
        self._closed: Event | None = None
        self._addresses = (address, *addresses)
        self._outlet = outlet
        self._register = register
        self._connection_rule = connection_rule

    async def __aenter__(self) -> t.Self:
        await self.start()
        return self

    def __await__(self):
        if self._closed is not None:
            return self._closed.wait().__await__()
        return None

    async def __aexit__(self, exc_type, exc_value, traceback, /):
        await self.stop()

    @property
    def active(self):
        """Истинно если сервер запущен."""
        return self._servers is not None

    async def start(self):
        """Запускает сервер."""
        if not self._servers:
            self._closed = asyncio.Event()
            loop = asyncio.get_event_loop()
            for address in self._addresses:
                server = await loop.create_server(lambda: self.ProxyProtocol(self._outcoming_factory), *address)
                await server.start_serving()
                self._servers.append(server)

    async def stop(self):
        """Останавливает сервер."""
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()
        self._closed.set()

    async def _outcoming_factory(self, incoming: Protocol, target: Address) -> OutcomingProtocol | None:
        loop = asyncio.get_event_loop()
        rule = self._connection_rule
        if self._register is not None:
            if tr := self._register(target):
                rule = tr.connection_rule
        if rule != ConnectionRule.Reset:
            target = self._outlet if self._outlet and rule == ConnectionRule.Tunnel else target
            _, protocol = await loop.create_connection(
                lambda: self.OutcomingProtocol(incoming, incoming.logger), *target
            )
            return protocol
        return None
