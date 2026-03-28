import asyncio
import logging
from asyncio import Transport, Task, Future
from collections.abc import Buffer, Callable
from enum import Enum
from logging import Logger
from typing import Coroutine

from overtun.intyperr import Address
from tlsex import TLSRecord, TLSMessage, TLSExtension


class Protocol(asyncio.Protocol):
    """
    Базовая часть протоколов.

    Attributes:
        logger: Логгер, по умолчанию будет использован логгер с именем "overtun".
        transport: Связанный транспорт.
    """

    transport: Transport

    def __init__(self, logger: Logger = None):
        self.logger = logger or logging.getLogger(".".join(__name__.split(".")[:-1]))

    @property
    def connected(self) -> bool:
        """Истинно если транспорт подключен."""
        return not self.transport.is_closing() if hasattr(self, "transport") else False

    def connection_made(self, transport: Transport):
        """Транспорт подключен."""
        self.transport = transport


class OutcomingProtocol(Protocol):
    """
    Базовый протокол контролирующий исходящие подключения.

    Attributes:
        incoming: Протокол входящего соединения.
    """

    def __init__(self, incoming: Protocol, logger: Logger = None):
        super().__init__(logger)
        self.incoming = incoming
        self._buffer = b""

    def __call__(self, data: Buffer):
        """
        Объект этого класса является функцией, принимающий данные которые следует переслать в исходящее соединение.

        Args:
            data: Данные для пересылки.
        """
        if not self.connected:
            self._buffer += data  # Если транспорт не готов, данные накапливаются в буфере
        else:
            if self._buffer:
                self.transport.write(memoryview(self._buffer))
                self._buffer = b""
            if data:
                self.transport.write(memoryview(data))

    def connection_made(self, transport: Transport):
        """Исходящий транспорт подключен."""
        super().connection_made(transport)
        self.incoming.transport.resume_reading()
        if self._buffer:
            self(b"")

    def pause_writing(self):
        """Исходящий буфер переполнен."""
        self.incoming.transport.pause_reading()

    def resume_writing(self):
        """Исходящий буфер опустошен."""
        self.incoming.transport.resume_reading()

    def data_received(self, data: bytes):
        """Поступили данные из исходящего подключения."""
        self.incoming.transport.write(memoryview(data))

    def connection_lost(self, exc):
        """Исходящее подключение разорвано."""
        if self.incoming.connected:
            self.incoming.transport.close()


class ProxyMode(Enum):
    """Режим проксирования"""

    UNDEFINED = 0
    HTTP_CONNECT = 1
    HTTP_PROXY = 2
    HTTP_TRANSPARENT = 3
    HTTPS_TRANSPARENT = 4


class ProxyProtocol(Protocol):
    """
    Протокол прокси-сервера обрабатывающий входящие подключения.
    """

    _outcoming_task: Task[OutcomingProtocol]

    def __init__(
        self,
        outcoming_factory: Callable[[Protocol, Address, ProxyMode], Coroutine[None, None, OutcomingProtocol | None]],
        logger: Logger = None,
    ):
        super().__init__(logger)
        self.mode = ProxyMode.UNDEFINED
        self.outcoming: OutcomingProtocol | None = None
        self._outcoming_factory = outcoming_factory
        self.target: Address | None = None
        self._buffer = b""

    def _outcoming_done(self, task: Task[OutcomingProtocol], mode: ProxyMode):
        try:
            if outcoming := task.result():
                self.outcoming = outcoming
                self.mode = mode
            else:
                raise ConnectionError(f"Taget banned")
        except Exception as exc:
            msg = f"Outcoming connection {self.target} failed; {exc}"
            if not isinstance(exc, ConnectionError) and self.logger.isEnabledFor(logging.DEBUG):
                self.logger.exception(msg)
            else:
                self.logger.debug(msg)

    def data_received(self, data: bytes):
        """Получены данные из входящего подключения."""
        if self.mode != ProxyMode.UNDEFINED:
            if self._buffer != b"":
                self._buffer = b""
            match self.mode:
                case ProxyMode.HTTP_CONNECT | ProxyMode.HTTPS_TRANSPARENT:
                    self.outcoming_data(memoryview(data))
                case _:
                    raise NotImplementedError(f"Proxy mode {self.mode} not yet implemented.")
        else:
            self._buffer += data

            # Определение типа подключения
            if self._buffer.startswith(b"CONNECT ") and self._buffer[-4:] == b"\r\n\r\n":
                # HTTPS CONNECT
                self.target = Address.from_(
                    [a.decode("ascii") for a in self._buffer.split(b"\r\n") if a][0].split(" ")[1]
                )
                self._buffer = b""
                self._outcoming_task = asyncio.create_task(
                    self._outcoming_factory(self, self.target, ProxyMode.HTTP_CONNECT)
                )
                self._outcoming_task.add_done_callback(lambda task: self._outcoming_done(task, ProxyMode.HTTP_CONNECT))
                self._outcoming_task.add_done_callback(lambda _: self.transport.write(b"HTTP/1.0 200 OK\r\n\r\n"))

            elif record := TLSRecord.load(self._buffer):
                # Transparent HTTPS
                if record.message.type == TLSMessage.Type.ClientHello:
                    if TLSExtension.Type.ServerName in record.message.extensions:
                        sni = record.message.extensions[TLSExtension.Type.ServerName].hostname
                        self.target = Address.from_(sni) if ":" in sni else Address.from_(sni, 443)
                        self._outcoming_task = asyncio.create_task(
                            self._outcoming_factory(self, self.target, ProxyMode.HTTPS_TRANSPARENT)
                        )
                        self._outcoming_task.add_done_callback(
                            lambda task: self._outcoming_done(task, ProxyMode.HTTPS_TRANSPARENT)
                        )
                        self._outcoming_task.add_done_callback(lambda _: self.outcoming_data(memoryview(self._buffer)))

    def outcoming_data(self, data: memoryview):
        """Получены данные для пересылки в исходящее соединение."""
        assert self.outcoming is not None, "Outcoming is not present."
        self.outcoming(data)

    def connection_lost(self, exc):
        if self.outcoming and self.outcoming.connected:
            self.outcoming.transport.close()
