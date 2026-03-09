import asyncio
import typing as t
from collections.abc import Coroutine


class TargetConnector(t.Protocol):
    """
    Интерфейс фабрики целевого подключения.
    """

    def __call__(
        self, source_transport: asyncio.Transport, target_host: str, target_port: int
    ) -> Coroutine[t.Any, t.Any, asyncio.Transport]:
        """Принимает параметры для создания целевого подключения.

        Args:
            source_transport: транспорт исходного подключения (инициатора).
            target_host: Целевой домен или IP адрес
            target_port: Порт целевого подключения

        Returns:
            Асинхронная функция реализующая целевое подключение и возвращающая его проинициализированный транспорт.
        """
