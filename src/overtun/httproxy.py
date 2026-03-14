import asyncio
import logging
from asyncio import Transport
from http import HTTPStatus

from .utils import parse_target
from ._types import TargetConnector

logger = logging.getLogger(":".join(__name__.split(".")))
logger.setLevel(logging.DEBUG)


class HTTPError(Exception):
    """Ошибка HTTP протокола."""

    args: tuple[HTTPStatus, Exception | str | None]

    def __init__(self, status: HTTPStatus, exc_or_message: Exception | str | None = None):
        super().__init__(status, exc_or_message)
        if isinstance(exc_or_message, Exception):
            self.__cause__ = exc_or_message


class Protocol(asyncio.Protocol):
    """
    Низкоуровневая реализация асинхронного HTTP Proxy протокола (только CONNECT!).
    """

    def __init__(self, target_connector: TargetConnector) -> None:
        self._client_transport: Transport | None = None
        self._target_transport: Transport | None = None
        self._target_connector = target_connector
        self._buffer = b""

    def connection_made(self, transport: asyncio.Transport):
        """Клиентское подключение установлено."""
        self._client_transport = transport

    def data_received(self, data: bytes):
        """Обработка поступающих данных из клиентского подключения."""
        try:
            if self._target_transport is None:
                self._buffer = data
                if success := self._extract_request():
                    host, port, method = success

                    def target_connector_done(task: asyncio.Task):
                        try:
                            self._target_transport = task.result()
                            if method == "CONNECT":
                                self._client_transport.write(b"HTTP/1.0 200 OK\r\n\r\n")
                                if self._buffer:
                                    self._target_transport.write(self._buffer)
                                    self._buffer = b""
                            else:
                                raise HTTPError(HTTPStatus.METHOD_NOT_ALLOWED, f"Unsupported method: {method}")
                        except Exception as exc:
                            if not isinstance(exc, HTTPError):
                                exc = HTTPError(HTTPStatus.BAD_GATEWAY, exc)
                            self._handle_error(exc)

                    task = asyncio.create_task(self._target_connector(self._client_transport, host, port))
                    task.add_done_callback(target_connector_done)
            else:
                self._target_transport.write(data)

        except Exception as exc:
            if not isinstance(exc, HTTPError):
                exc = HTTPError(HTTPStatus.INTERNAL_SERVER_ERROR, exc)
            self._handle_error(exc)

    def connection_lost(self, exc: Exception):
        """Клиентское подключение разорвано."""
        if self._target_transport is not None:
            self._target_transport.close()

    def _extract_request(self) -> tuple[str, int, str] | None:
        """Выделяет запрос из буфера и парсит его стартовую строку."""
        if b"\r\n\r\n" in self._buffer:
            try:
                headers, self._buffer = self._buffer.split(b"\r\n\r\n", 1)
                start, *headers = headers.split(b"\r\n")
                method, target, version = start.split(b" ")
                host, port, path = parse_target(target)
                return host, port, method.decode("ascii")
            except ValueError as exc:
                raise HTTPError(HTTPStatus.BAD_REQUEST, exc)
        return None

    def _handle_error(self, exc: HTTPError):
        """Обработка ошибки."""
        status, exc = exc.args
        message = f"Cannot process client request: {status}; {exc}"
        extra = dict(peername=self._client_transport.get_extra_info("peername"))
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.exception(message, extra=extra)
        else:
            logger.warning(message, extra=extra)
        self._client_transport.write(f"HTTP/1.0 {status.value} {status.phrase}\r\n\r\n".encode("ascii"))
        self._client_transport.close()
