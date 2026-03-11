import asyncio
import typing as t
from collections.abc import Coroutine
from http import HTTPStatus


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


class HTTPError(Exception):
    """Ошибка HTTP протокола."""

    args: tuple[HTTPStatus, Exception]

    def __init__(self, status: HTTPStatus, exc_or_message: Exception | str | None = None):
        super().__init__(status, exc_or_message)
        if isinstance(exc_or_message, Exception):
            self.__cause__ = exc_or_message
