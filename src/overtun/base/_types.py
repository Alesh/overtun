import asyncio
import typing as t
from collections.abc import Coroutine


class Decoder[T](t.Protocol):
    """
    Интерфейс декодера сетевых данных.
    """

    def __init__(self, *args, **kwargs) -> None: ...

    def __call__(self, data: bytes) -> T | None:
        """
        Декодирует поступающие данные, и извлекает из них некоторые данные,
        либо просто возвращает `True` в случае успеха.

        Args:
            Байтовая строка данные в которой следует попытаться декодировать.

        Returns:
             Возвращает результат декодирования `T`, или прошло успешно.
             Возвращает `None` если количество данных не достаточно для принятия решения.

        Raises:
             ValueError: Если данные не соответствуют ожиданиям, например, не тот формат.
             LookupError: Если данные соответствуют формату, но данных для извлечения нет.
        """


class Target(t.NamedTuple):
    """Целевой адрес."""

    host: str
    port: int


class TargetConnector(t.Protocol):
    """
    Интерфейс фабрики целевого подключения.
    """

    def __call__(self, transport: asyncio.Transport, target: Target) -> Coroutine[t.Any, t.Any, asyncio.Transport]:
        """
        Принимает параметры для создания целевого подключения. Протокол целевого подключения должен пересылать
        поступающие данные в транспорт (инициатора) клиентта.

        Args:
            transport: транспорт клиентского подключения (инициатора).
            target: Целевой адрес

        Returns:
            Асинхронная функция создающая целевое подключение и возвращающая его проинициализированный транспорт.
        """


class TargetDecoder(Decoder[Target], t.Protocol):
    """
    Интерфейс декодера сетевых данных извлекающий адрес целевого подключения.
    """

    def __call__(self, data: bytes) -> Target | None: ...
