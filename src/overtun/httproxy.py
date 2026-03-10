import asyncio
import logging
import typing as t
from asyncio import Transport
from collections.abc import Coroutine
from enum import Enum
from http import HTTPStatus

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TargetConnector(t.Protocol):
    """
    Интерфейс фабрики целевого подключения.
    """

    def __call__(
        self, client_transport: asyncio.Transport, target_host: str, target_port: int
    ) -> Coroutine[t.Any, t.Any, asyncio.Transport]:
        """Принимает параметры для создания целевого подключения.

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

    def __init__(self, status: HTTPStatus, exc: Exception | None = None):
        super().__init__(status, exc)


class Protocol(asyncio.Protocol):
    """
    Низкоуровневая реализация асинхронного HTTP Proxy протокола.
    """

    class State(Enum):
        """Состояние протокола."""

        INITIAL = 0
        CONNECT = 1
        PASSTHRU = 2

    def __init__(self, target_connector: TargetConnector) -> None:
        self._buffer = b""
        self._state = Protocol.State.INITIAL
        self._client_transport: Transport | None = None
        self._target_transport: Transport | None = None
        self._target_connector = target_connector

    def connection_made(self, transport: asyncio.Transport):
        """Клиентское подключение установлено."""
        self._client_transport = transport

    def data_received(self, data: bytes):
        """Обработка поступающих данных из клиентского подключения."""
        self._buffer += data
        try:
            match self._state:
                case Protocol.State.INITIAL:
                    if success := self._determine_request():
                        host, port, method, headers = success

                        def target_connector_done(task: asyncio.Task):
                            try:
                                self._target_transport = task.result()
                                if method == "CONNECT":
                                    self._client_transport.write(b"HTTP/1.0 200 OK\r\n\r\n")
                                    self._state = Protocol.State.CONNECT
                                else:
                                    buffer, self._buffer = self._buffer, b""
                                    self._target_transport.write(headers + b"\r\n\r\n")
                                    self._target_transport.write(buffer)
                                    self._state = Protocol.State.PASSTHRU
                            except Exception as exc:
                                raise HTTPError(HTTPStatus.BAD_GATEWAY, exc)

                        task = asyncio.create_task(self._target_connector(self._client_transport, host, port))
                        task.add_done_callback(target_connector_done)
                case Protocol.State.CONNECT:
                    self._target_transport.write(data)
                case Protocol.State.PASSTHRU:
                    if success := self._determine_request():
                        host, port, method, headers = success
                        buffer, self._buffer = self._buffer, b""
                        self._target_transport.write(headers + b"\r\n\r\n")
                        self._target_transport.write(buffer)
                case _:
                    raise RuntimeError(f"Unknown state: {self._state}")
        except Exception as exc:
            if not isinstance(exc, HTTPError):
                exc = HTTPError(HTTPStatus.INTERNAL_SERVER_ERROR, exc)
            status, exc = exc.args
            message = f"Cannot process client request: {status}; {exc}"
            if logger.getEffectiveLevel() == logging.DEBUG:
                logger.exception(message)
            else:
                logger.warning(message)
            self._client_transport.write(f"HTTP/1.0 {status.value} {status.phrase}\r\n\r\n".encode("ascii"))
            self._client_transport.close()

    def connection_lost(self, exc: Exception):
        """Клиентское подключение разорвано."""
        if self._target_transport is not None:
            self._target_transport.close()

    def _determine_request(self) -> tuple[str, int, str, bytes] | None:
        """Выделяет запрос из буфера."""
        if b"\r\n\r\n" in self._buffer:
            try:
                headers, self._buffer = self._buffer.split(b"\r\n\r\n", 1)
                first, *headers = headers.split(b"\r\n")
                method, target, version = first.split(b" ")
                host, port, path = parse_target(target)
                first = b" ".join([method, path.encode("ascii"), version])
                headers = first + b"\r\n" + b"\r\n".join(headers)
                return host, port, method.decode("ascii"), headers
            except ValueError as exc:
                raise HTTPError(HTTPStatus.BAD_REQUEST, exc)
        return None


def parse_target(target: bytes) -> tuple[str, int, str]:
    """Разбирает байтовую строку, содержащую URL целевого ресурса."""
    port = 80
    target = target.decode("ascii")
    if "://" in target:
        _, target = target.split("://", 1)
    host, *path = target.split("/")
    path = "/" + "/".join(path)
    if host:
        if "]:" in host:
            host, port = host[1:].split("]:", 1)
        elif ":" in host:
            host, port = host.split(":", 1)
        return host, int(port), path
    raise ValueError("Invalid target")
