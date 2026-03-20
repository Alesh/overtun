import asyncio
import logging
from asyncio import Transport, Task
from collections.abc import Buffer
from logging import Logger

from overtun.intyperr import TargetExtractor, Address
from overtun.protocols.common import Protocol, DataError


class OutcomingProtocol(Protocol):
    """
    Прокси протокол исходящего соединения.

    Attributes:
        incoming: Протокол входящего соединения.
    """

    def __init__(self, incoming: Protocol, logger: Logger = None):
        super().__init__(logger)
        self.incoming = incoming

    def connection_made(self, transport: Transport):
        """Исходящий транспорт подключен."""
        super().connection_made(transport)
        self.incoming.transport.resume_reading()

    def pause_writing(self):
        """Исходящий буфер переполнен."""
        self.incoming.transport.pause_reading()

    def resume_writing(self):
        """Исходящий буфер опустошен."""
        self.incoming.transport.resume_reading()

    def data_received(self, data: bytes):
        """Поступили данные из исходящего подключения."""
        self.incoming.transport.write(data)

    def connection_lost(self, exc):
        """Исходящее подключение разорвано."""
        if self.incoming.transport and not self.incoming.transport.is_closing():
            self.incoming.transport.close()


class IncomingProtocol(Protocol):
    """
    Прокси протокол входящего соединения.

    Attributes:
        outcoming: Протокол исходящего соединения или `None` если соединение еще не создано.
    """

    _connection_task: Task[OutcomingProtocol] | None

    def __init__(self, target_extractor: TargetExtractor, buffer_size: int = 64 * 1024, logger: Logger = None):
        super().__init__(logger)
        self.outcoming: Protocol | None = None
        self._target_extractor = target_extractor
        self.__buffer_size = buffer_size
        self._buffer = b""

    def pause_writing(self):
        """Входящий буфер переполнен."""
        if self.outcoming and self.outcoming.transport:
            self.outcoming.transport.pause_reading()

    def resume_writing(self):
        """Входящий буфер опустошен."""
        if self.outcoming and self.outcoming.transport:
            self.outcoming.transport.resume_reading()

    def data_received(self, data: bytes):
        """Поступили данные из входящего подключения"""
        try:
            if self.outcoming:
                if self.outcoming.transport:
                    self.outcoming.transport.write(data)
                    return
                else:
                    self.transport.pause_reading()
            self._buffer += data
            if len(self._buffer) >= self.__buffer_size:
                self.transport.pause_reading()
            if self.outcoming is None:
                self.outcoming_required(memoryview(self._buffer))
        except Exception as exc:
            self._handle_error(exc)

    def _handle_error(self, exc):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.exception(exc)
        else:
            self.logger.error(exc)
        self.transport.close()

    def outcoming_required(self, buffer: Buffer):
        """Требуется создание исходящего соединения."""
        try:
            if address := self._target_extractor(buffer):
                self._connection_task = self.create_target_connection(address)
                if self._connection_task:

                    def connection_task_done(task: asyncio.Task[OutcomingProtocol]) -> None:
                        try:
                            self.outcoming = task.result()
                            self.outcoming.transport.write(memoryview(buffer))
                            self._buffer = b""
                        except Exception as exc_:
                            self._handle_error(exc_)

                    self._connection_task.add_done_callback(connection_task_done)

                else:
                    self.logger.debug(f"Connection to {Address} has rejected")
                    self.transport.close()

        except ValueError as exc:
            raise DataError("Cannot extract target", buffer) from exc
        except LookupError as exc:
            raise DataError("Cannot found target", buffer) from exc

    def create_target_connection(self, target: Address) -> Task[OutcomingProtocol] | None:
        """
        Создает соединение к целевому адресу.

        Args:
            target: Целевой адрес.

        Returns:
            Протокол исходящего соединения, или `None` если соединение не создано.
        """

        async def create_direct_connection():
            loop = asyncio.get_event_loop()
            _, protocol = await loop.create_connection(lambda: OutcomingProtocol(self, self.logger), *target)
            return protocol

        return asyncio.create_task(create_direct_connection())

    def eof_received(self):
        self.logger.debug("EOF received")

    def connection_lost(self, exc):
        """Входящее подключение разорвано."""
        if self.outcoming and self.outcoming.transport and not self.outcoming.transport.is_closing():
            self.outcoming.transport.close()
