import typing as t
from collections.abc import AsyncIterator

from typing_extensions import Buffer

from .intyperr import IncomingType
from .primitives import Address


class PreambleResult(t.NamedTuple):
    """
    Результат вызова `PreambleHandler`

    Attributes:
        incoming_type: Тип входящего соединения с прокси-сервером, определённый в ходе анализа трафика.
        target_address: Целевой сетевой адрес, куда/откуда следует пересылать трафик с/на входящего подключения.
        data: Исходные или преобразованные данные преамбулы, в виде асинхронного итератора.
    """

    incoming_type: IncomingType
    target_address: Address
    data: AsyncIterator[Buffer]


class PreambleHandler:
    """
    Базовый класс анализирующий преамбулу байтового потока входящего соединения прокси-сервера.
    """

    def __call__(self, data: Buffer) -> PreambleResult | None:
        # Определение типа подключения
        if data[0:8] == b"CONNECT " and data[-4:] == b"\r\n\r\n":
            return self.http_connect(data)  # HTTPS CONNECT
        return None

    def http_connect(self, buff: Buffer) -> PreambleResult:
        """Обработчик входящего подключения типа HTTP CONNECT."""
        data = bytes(buff)
        address = Address.parse(
            [a.decode("ascii") for a in data.split(b"\r\n") if a][0].split(" ")[1]
        )

        async def data_ait():
            yield data

        return PreambleResult(
            incoming_type=IncomingType.HTTP_CONNECT,
            target_address=address,
            data=data_ait(),
        )
