import asyncio
import logging
import typing as t
from asyncio import Transport
from enum import Enum
from logging import Logger
from collections.abc import Buffer

from tlsex import TLSRecord, TLSMessage, TLSExtension
from tlsex.extensions import ServerName
from .intyperr import (
    OutcomingFactory,
    OutcomingTransport,
    ProtocolError,
    OutcomingForwarder,
    TargetResolver,
)
from .primitives import Address


class Protocol(asyncio.Protocol):
    """
    Базовая часть протоколов.

    Attributes:
        logger: Логгер, по умолчанию будет использован логгер с именем "overtun".
    """

    def __init__(self, logger: Logger = None):
        self.logger = logger or logging.getLogger(".".join(__name__.split(".")[:-1]))
        self.__transport: Transport | None = None

    @property
    def transport(self) -> Transport:
        "Связанный транспорт."
        if not self.__transport:
            raise ConnectionError("Transport isn't connected.")
        return self.__transport

    def connection_made(self, transport: Transport):
        """Транспорт подключен."""
        self.__transport = transport


class OutcomingProtocol(Protocol):
    """
    Базовый протокол исходящего соединения прокси сервера.
    """

    def __init__(self, incoming: Transport, logger: Logger = None):
        super().__init__(logger)
        self.incoming = incoming

    def connection_made(self, transport: Transport):
        """Исходящий транспорт подключен."""
        super().connection_made(transport)
        self.incoming.resume_reading()

    def pause_writing(self):
        """Исходящий буфер переполнен."""
        self.incoming.pause_reading()

    def resume_writing(self):
        """Исходящий буфер опустошен."""
        self.incoming.resume_reading()

    def data_received(self, data: bytes):
        """Поступили данные из исходящего подключения."""
        self.incoming.write(data)
        # ToDo: Сравнить производительность с вариантом `self._incoming.write(memoryview(data)`)

    def connection_lost(self, exc):
        """Исходящее подключение разорвано."""
        if not self.incoming.is_closing():
            self.incoming.close()


class ProxyMode(int, Enum):
    """
    Режим работы протокола
    """

    UNDEFINED = 0
    HTTP_CONNECT = 1
    HTTPS_TRANSPARENT = 2


class ProxyProtocol(Protocol):
    """
    Протокол входящего соединения прокси сервера.
    """

    _target_address: Address
    _outcoming_task: asyncio.Task

    proxy_mode = ProxyMode.UNDEFINED
    outcoming: OutcomingTransport | None = None

    def __init__(
        self,
        logger: Logger = None,
        target_resolver: TargetResolver | None = None,
        outcoming_factory: OutcomingFactory | None = None,
        outcoming_forwarder: OutcomingForwarder | None = None,
    ) -> None:
        """
        Конструктор
        Args:
            logger:
            target_resolver:
            outcoming_factory: Фабрика исходящего соединения, интерфейс `overtune.intyperr.OutcomingFactory`
            outcoming_forwarder:
        """
        super().__init__(logger)
        self._buffer = b""
        self.__outcoming_factory = outcoming_factory or (
            lambda _, target_address: self._outcoming_factory(target_address)
        )
        self.__outcoming_forwarder = outcoming_forwarder or (
            lambda _, data: self._outcoming_forwarder(data)
        )
        self.__target_resolver = target_resolver or self._target_resolver

    def data_received(self, data: bytes):
        """Получены данные из входящего подключения."""
        if self.outcoming is not None:
            self.__outcoming_forwarder(self.outcoming, data)
        else:
            self._buffer += data
            try:
                # Попытка определение типа входящего соединения
                if (pos := self._buffer.find(b"\r\n")) and pos >= 0:
                    if self._buffer[pos - 8 : pos][:5] == b"HTTP/":
                        if self._buffer[0:8] == b"CONNECT ":
                            self.proxy_mode = ProxyMode.HTTP_CONNECT  # HTTP CONNECT прокси
                            self._target_address = Address.parse(
                                [a for a in self._buffer.split(b"\r\n") if a][0]
                                .split(b" ")[1]
                                .decode("ascii")
                            )
                            # Переключение в ожидание TLS трафика
                            self.transport.write(b"HTTP/1.0 200 OK\r\n\r\n")
                            self._buffer = b""
                        else:
                            # HTTP Native и HTTP Transparent прокси не реализован
                            self.transport.write(b"HTTP/1.0 405 OK\r\n\r\n")
                            self.transport.close()
                elif tls := TLSRecord.load(self._buffer):
                    if (
                        tls.type == TLSRecord.Type.Handshake
                        and tls.message.type == TLSMessage.Type.ClientHello
                    ):
                        if self.proxy_mode != ProxyMode.HTTP_CONNECT:
                            self.proxy_mode = ProxyMode.HTTPS_TRANSPARENT
                        if self.proxy_mode == ProxyMode.HTTPS_TRANSPARENT:
                            target_address, self._buffer = self.__target_resolver(tls, 443)
                        else:
                            target_address = self._target_address
                        self.transport.pause_reading()
                        # Получение входящих данных на паузу, пока не будет создано исходящеее соединение
                        self._outcoming_task = asyncio.create_task(
                            self.__outcoming_factory(self.transport, target_address)
                        )
                        self._outcoming_task.add_done_callback(
                            lambda task: self._outcoming_done(task, target_address)
                        )
            except Exception as exc:
                self._handle_error(exc)

    def connection_lost(self, exc):
        """Транспорт отключен."""
        if self.outcoming is not None and not self.outcoming.is_closing():
            self.outcoming.close()
        self.transport.close()

    @staticmethod
    def _target_resolver(preamble: bytes, port: int = 443) -> tuple[Address, Buffer | None] | None:
        """Определяет целевой адрес по TLS записи."""
        if record := TLSRecord.load(preamble):
            if (
                record.type == TLSRecord.Type.Handshake
                and record.message.type == TLSMessage.Type.ClientHello
            ):
                if TLSExtension.Type.ServerName in record.message.extensions:
                    sni = t.cast(
                        ServerName, record.message.extensions[TLSExtension.Type.ServerName]
                    )
                    return Address.parse(sni.hostname, port), preamble
                else:
                    raise ProtocolError("Cannot get target address")
            else:
                raise ProtocolError("Wrong TLS message type, excepted ClientHello")
        return None

    def _outcoming_forwarder(self, data: bytes):
        """Отправляет данные в исходящее соединение."""
        self.outcoming.write(data)

    async def _outcoming_factory(self, target_address: Address) -> OutcomingTransport:
        """Создает исходящее соединение."""
        host, port = target_address
        loop = asyncio.get_event_loop()
        outcoming_transport, _ = await loop.create_connection(
            lambda: OutcomingProtocol(self.transport), str(host), port
        )
        local_address = Address.parse(*self.transport.get_extra_info("peername")[:2])
        self.logger.info(f"Connection from {local_address} to {target_address} established")
        return outcoming_transport

    def _outcoming_done(
        self, task: asyncio.Task[OutcomingTransport], target_address: Address
    ) -> None:
        try:
            local_address = Address.parse(*self.transport.get_extra_info("peername")[:2])
            try:
                if outcoming := task.result():
                    self.outcoming = outcoming
                    if self._buffer:
                        data, self._buffer = self._buffer, b""
                        self.__outcoming_forwarder(self.outcoming, data)
                    self.transport.resume_reading()
                else:
                    raise ConnectionError(f"Connection to {target_address} banned by rule")
            except Exception as exc:
                raise ConnectionResetError(
                    f"Connection from {local_address} to {target_address} failed; {exc}"
                ) from exc
        except ConnectionError as exc:
            self._handle_error(exc)

    def _handle_error(self, exc: Exception) -> None:
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.exception(str(exc))
        else:
            self.logger.warning(str(exc))
        self.transport.write_eof()
