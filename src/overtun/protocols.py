import asyncio
import logging
from asyncio import Transport, Task
from collections.abc import Callable
from logging import Logger

from overtun import handlers as default_handlers
from overtun.handlers import HandlersModule
from overtun.primitives import Address, TargetDesc, TrafficRule


class Error(Exception):
    """Базовая ошибка пакета."""


class ProtocolError(Error):
    """Ошибка протокола."""


class BaseProtocol(asyncio.Protocol):
    """Базовая часть протоколов."""

    def __init__(self, logger: Logger = None):
        self._logger = logger or logging.getLogger(".".join(__name__.split(".")[:-1]))
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


class OutcomingProtocol(BaseProtocol):
    """
    Базовый протокол исходящего соединения от прокси сервера.
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

    def connection_lost(self, exc):
        """Исходящее подключение разорвано."""
        if not self.incoming.is_closing():
            self.incoming.close()


class IncomingProtocol[D](BaseProtocol):
    """
    Базовый протокол входящего подключения к прокси серверу.
    """

    _outcoming_task: Task[Transport]

    _outcoming: Transport | None = None
    _buffer: bytes = b""

    def __init__(
        self,
        logger: Logger = None,
    ):
        super().__init__(logger)

    def data_received(self, data: bytes):
        """Получены данные из входящего соединения."""
        if self._outcoming is not None:
            self._outcoming.write(data)
        else:
            self._buffer += data
            try:
                self._buffer = self.preamble_received(self._buffer)
            except Exception as exc:
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.exception(str(exc))
                else:
                    self._logger.warning(str(exc))
                self.transport.write_eof()

    def preamble_received(self, data: bytes) -> bytes:
        """Получена преамбула для разбора."""
        return data

    def connection_lost(self, exc):
        """Транспорт отключен."""
        if self._outcoming is not None and not self._outcoming.is_closing():
            self._outcoming.close()
        self.transport.close()

    def create_outcoming(self, target_address: Address) -> Task[Transport]:
        """Задача создающая и возвращающая исходящее соединете."""

        async def outcoming_factory(remote_address: Address) -> Transport:
            host, port = remote_address
            loop = asyncio.get_event_loop()
            outcoming_transport, _ = await loop.create_connection(
                lambda: OutcomingProtocol(self.transport), str(host), port
            )
            local_address = Address.parse(*self.transport.get_extra_info("peername")[:2])
            self._logger.info(f"Connection from {local_address} to {remote_address} established")
            return outcoming_transport

        def outcoming_done(task: Task[Transport]):
            try:
                self._outcoming = task.result()
            except Exception as exc:
                local_address = Address.parse(*self.transport.get_extra_info("peername")[:2])
                msg = f"Connection from {local_address} to {target_address} failed; {exc}"
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.exception(msg)
                else:
                    self._logger.warning(msg)
                self.transport.write_eof()

        task = asyncio.create_task(outcoming_factory(target_address))
        task.add_done_callback(outcoming_done)
        return task


class OutletProtocol[A](IncomingProtocol):
    """
    Протокол входящего подключения к аутлету.
    """

    def __init__(
        self,
        secret_key: bytes,
        handlers: HandlersModule[A] | None = None,
        extra_args: A | None = None,
        logger: Logger = None,
    ):
        """
        Конструктор:

        Args:
            secret_key: Секретный ключ связывающий стороны тунеля.
            handlers: Обработчики преамбулы.
            extra_args: Дополнительные данные для обработчика преамбулы.
            logger: Логгер
        """
        super().__init__(logger)
        self._secret_key = secret_key
        self._extra_args = extra_args
        self._handlers = handlers or default_handlers

    def preamble_received(self, data: bytes):
        """Получена преамбула для разбора."""
        if result := self._handlers.outlet_handler(data, self._secret_key, self._extra_args):
            target_address, data = result
            if target_address:
                self._outcoming_task = self.create_outcoming(target_address)
                self._outcoming_task.add_done_callback(
                    lambda _: self._outcoming and self._outcoming.write(data)
                )
                return b""
            else:
                raise LookupError("Target address not found.")
        return super().preamble_received(data)


class ProxyProtocol[A, D](IncomingProtocol[D]):
    """
    Протокол входящего подключения к прокси серверу.
    """

    def __init__(
        self,
        outlet_address: Address | None = None,
        secret_key: bytes | None = None,
        target_registry: Callable[[Address], TargetDesc[D] | None] | None = None,
        default_traffic_rule: TrafficRule = TrafficRule.DIRECT,
        handlers: HandlersModule[A] | None = None,
        extra_args: A | None = None,
        logger: Logger = None,
    ):
        """
        Конструктор:

        Args:
            outlet_address: Адрес аутлета, включает режим туннелирования.
            secret_key: Секретный ключ связывающий стороны туннеля.
            target_registry: Регистр дополнительной информации о целевых ресурсах.
            default_traffic_rule: Правило по умолчанию для перенаправления трафика.
            handlers: Обработчики преамбулы.
            extra_args: Дополнительные данные для обработчика преамбулы.
            logger: Логгер
        """
        super().__init__(logger)
        target_registry = target_registry or (
            lambda address: TargetDesc(address, default_traffic_rule)
        )
        self._target_registry = lambda address: (
            target_registry(address) or TargetDesc(address, default_traffic_rule)
        )
        self._traffic_rule = default_traffic_rule
        self._outlet_address = outlet_address
        self._secret_key = secret_key
        self._extra_args = extra_args
        self._handlers = handlers or default_handlers

    def preamble_received(self, data: bytes):
        """Получена преамбула для разбора."""

        if result := self._handlers.proxy_handler(
            data, self._outlet_address, self._secret_key, self._extra_args
        ):
            target_address, encoded_preamble = result
            if target_address:
                remote_address = target_address
                target_desc = self._target_registry(target_address)
                if (
                    target_desc.traffic_rule == TrafficRule.TUNNEL
                    and self._outlet_address is not None
                ):
                    remote_address = self._outlet_address
                    data = encoded_preamble
                elif target_desc.traffic_rule == TrafficRule.DROP:
                    remote_address = None
                if remote_address is not None:
                    self._outcoming_task = self.create_outcoming(remote_address)
                    self._outcoming_task.add_done_callback(
                        lambda task: task.exception() is None and task.result().write(data)
                    )
                    return b""
                else:
                    raise ConnectionError(f"{target_address} banned by rule.")
            else:
                raise LookupError("Target address not found.")

        if (pos := data.find(b"\r\n")) and pos > 0 and data[pos - 8 : pos][:5] == b"HTTP/":
            if data[0:8] == b"CONNECT ":
                target_address = Address.parse(
                    [a for a in data.split(b"\r\n") if a][0].split(b" ")[1].decode("ascii")
                )
                # Переключение протокола на TLS трафик
                self.transport.write(b"HTTP/1.0 200 OK\r\n\r\n")
            else:
                # HTTP Native и HTTP Transparent прокси не реализован
                self.transport.write(b"HTTP/1.0 405 OK\r\n\r\n")
                self.transport.close()
            return b""

        return super().preamble_received(data)
