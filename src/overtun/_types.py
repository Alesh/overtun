import asyncio
import typing as t
from collections.abc import Coroutine


class TargetConnector(t.Protocol):
    """
    Интерфейс фабрики целевого подключения.
    """

    def __call__(
        self, client_transport: asyncio.Transport, target_host: str, target_port: int
    ) -> Coroutine[t.Any, t.Any, asyncio.Transport]:
        """
        Принимает параметры для создания целевого подключения. Протокол целевого подключения должен пересылать
        поступающие данные в транспорт (инициатора) клиентста.

        Args:
            client_transport: транспорт клиентского подключения (инициатора).
            target_host: Целевой домен или IP адрес
            target_port: Порт целевого подключения

        Returns:
            Асинхронная функция создающая целевое подключение и возвращающая его проинициализированный транспорт.
        """
