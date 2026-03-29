import asyncio
import logging
import typing as t
from asyncio import Transport
from enum import Enum
from logging import Logger

from tlsex import TLSRecord, TLSMessage, TLSExtension
from tlsex.extensions import ServerName
from .intyperr import OutcomingFactory, OutcomingTransport, ProtocolError
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
        outcoming_factory: OutcomingFactory | None = None,
        logger: Logger = None,
    ) -> None:
        super().__init__(logger)
        self._buffer = b""

        async def default_outcoming_factory(
            incoming_transport: Transport,
            target_address,
        ) -> OutcomingTransport:
            host, port = target_address
            loop = asyncio.get_event_loop()
            outcoming_transport, _ = await loop.create_connection(
                lambda: OutcomingProtocol(incoming_transport), str(host), port
            )
            return outcoming_transport

        self._outcoming_factory = outcoming_factory or default_outcoming_factory

    def data_received(self, data: bytes):
        """Получены данные из входящего подключения."""
        if self.outcoming is not None:
            self.forward_data(data)
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
                            if TLSExtension.Type.ServerName in tls.message.extensions:
                                sni = t.cast(
                                    ServerName, tls.message.extensions[TLSExtension.Type.ServerName]
                                )
                                target_address = Address.parse(sni.hostname, 443)
                            else:
                                raise ProtocolError("Cannot get target address")
                        else:
                            target_address = self._target_address
                        self.transport.pause_reading()
                        # Получение входящих данных на паузу, пока не будет создано исходящеее соединение
                        self._outcoming_task = asyncio.create_task(
                            self._outcoming_factory(self.transport, target_address)
                        )
                        self._outcoming_task.add_done_callback(
                            lambda task: self._outcoming_done(task, target_address)
                        )
            except Exception as exc:
                self._handle_error(exc)

    def forward_data(self, data: bytes):
        """Отправляет данные в исходящее подключение."""
        self.outcoming.write(data)

    def connection_lost(self, exc):
        """Транспорт отключен."""
        if self.outcoming is not None and not self.outcoming.is_closing():
            self.outcoming.close()
        self.transport.close()

    def _outcoming_done(
        self, task: asyncio.Task[OutcomingTransport], target_address: Address
    ) -> None:
        try:
            try:
                if outcoming := task.result():
                    self.outcoming = outcoming
                    if self._buffer:
                        data, self._buffer = self._buffer, b""
                        self.forward_data(data)
                    self.transport.resume_reading()
                else:
                    raise ConnectionError(f"Taget address: {target_address} banned")
            except Exception as exc:
                raise ConnectionResetError(
                    f"Outcoming connection to {target_address} failed; {exc}"
                ) from exc
        except ConnectionError as exc:
            self._handle_error(exc)

    def _handle_error(self, exc: Exception) -> None:
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.exception(str(exc))
        else:
            self.logger.debug(str(exc))
        self.transport.write_eof()
