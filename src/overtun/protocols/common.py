import asyncio
import logging
from asyncio import Transport
from collections.abc import Buffer
from logging import Logger

from overtun.intyperr import Error

default_logger = Logger(__name__.split(".")[:-1])
default_logger.setLevel(logging.DEBUG)


class ProtocolError(Error):
    """
    Класс исключений возникших в компонентах протокола.
    """


class DataError(ProtocolError):
    """
    Класс исключений некорректности данных.
    """

    def __init__(self, message: str, sample: Buffer | None = None):
        super().__init__(f"{message}{f': {" ".join([f"{b:02X}" for b in sample[:16]])}' if sample else '.'}")


class Protocol(asyncio.Protocol):
    """
    Базовая часть протоколов.

    Attributes:
        logger: Логгер, по умолчанию будет использован логгер с именем "overtun".
        transport: Связанный транспорт или `None` если транспорт еще не подключен.
    """

    def __init__(self, logger: Logger = None):
        self.logger = logger or default_logger
        self.transport: Transport | None = None

    def connection_made(self, transport: Transport):
        """Транспорт подключен."""
        self.transport = transport
