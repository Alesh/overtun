import asyncio
import typing as t
from logging import Logger

from overtun.intyperr import TargetExtractor, AddressInfo, AddressInfoRegister, Address
from overtun.protocols import proxy
from overtun.protocols.proxy import OutcomingProtocol


class AddressAllow(AddressInfo, t.Protocol):
    """
    Интерфейс объекта содержащий информацию о сетевом адресе для селектирования соединений.

    Attributes:
        allow:
            Если `True` соединения до этого адреса должны быть туннелированы.
            Если `False` соединения до этого адреса не обрабатываются и должны быть сброшены.
    """

    allow: bool


class SelectiveProtocol(proxy.IncomingProtocol):
    """
    Базовый протокол обработки подключения к селективному туннелирующему прокси.

    Протокол анализирует входящие данные и на основе результата выполняется одно из действий:
      * Трафик туннелируется на аутлет и там пробрасывается на целевого адреса.
      * Соединение пробрасывается до целевого адреса на месте.
      * Соединение сбрасывается.
    """

    def __init__(
        self,
        target_extractor: TargetExtractor,
        address_register: AddressInfoRegister[AddressAllow],
        outlet_address: Address,
        buffer_size: int = 64 * 1024,
        logger: Logger = None,
    ):
        super().__init__(target_extractor, buffer_size, logger)
        self._outlet_address = outlet_address
        self._address_register = address_register
        self._connection_task = None

    def create_target_connection(self, target: Address) -> asyncio.Task[OutcomingProtocol] | None:
        """
        Создает соединение к целевому адресу на основе информации об этом адресе в регистре.

        Args:
            target: Целевой адрес.

        Returns:
            Протокол исходящего соединения, или `None` если соединение не создано.
        """
        if ai := self._address_register(target):
            if ai.allow:  # проксирование через туннель
                return self.create_tunnel_connection(self._outlet_address, target)
        else:  # проксирование на месте
            return super().create_target_connection(target)
        return None

    def create_tunnel_connection(self, outlet: Address, target: Address) -> asyncio.Task[OutcomingProtocol]:
        """
        Создает туннельное соединение к целевому адресу.

        Args:
            outlet: Адрес аутлет сервера.
            target: Целевой адрес.

        Returns:
            Протокол исходящего соединения.
        """
        return super().create_target_connection(outlet)
