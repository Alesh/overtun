import asyncio
import logging
from asyncio import Transport
from dataclasses import asdict

import h11

from overtun._types import TargetConnector
from overtun.utils import parse_target

logger = logging.getLogger(__name__)


class TargetClient:
    """
    Клиент подключения к целевому серверу.
    """

    def __init__(self, target_transport: Transport, timeout=3.0):
        self._target_transport = target_transport
        self._h11_target = h11.Connection(our_role=h11.CLIENT)
        self._timeout = timeout

    async def send_request(self, request: h11.Request, body: bytes) -> tuple[h11.Response, bytes]:
        self._target_transport.write(self._h11_target.send(request))
        if body:
            self._target_transport.write(self._h11_target.send(h11.Data(data=body)))
        self._target_transport.write(self._h11_target.send(h11.EndOfMessage()))
        body = b""
        event = response = None
        async with asyncio.timeout(self._timeout):
            while isinstance(event, h11.EndOfMessage):
                event = self._h11_target.next_event()
                if isinstance(event, h11.Response):
                    response = event
                elif isinstance(event, h11.Data):
                    body += event.data
                elif event is h11.PAUSED:
                    await asyncio.sleep(0.1)
            else:
                return response, body


class Protocol(asyncio.Protocol):
    """
    Низкоуровневая реализация асинхронного HTTP Proxy протокола.
    """

    default_headers = [("Proxy-Agent", "OverTun/httproxy")]

    _source_transport: Transport
    _target_transport: Transport = None
    _target_client: TargetClient = None

    def __init__(self, target_connector: TargetConnector) -> None:
        self._target_connector = target_connector
        self._h11_source = h11.Connection(our_role=h11.SERVER)

    def connection_made(self, transport: asyncio.Transport):
        """Исходное подключение установлено."""
        self._source_transport = transport

    def data_received(self, data: bytes):
        """Обработка поступающих данных из клиентского подключения."""
        if self._h11_source.our_state == h11.SWITCHED_PROTOCOL:
            self._target_transport.write(data)
        else:
            self._h11_source.receive_data(data)
            self._h11_source_events()

    def connection_lost(self, exc: Exception):
        """Исходное подключение разорвано."""
        if self._target_transport is not None:
            self._target_transport.close()

    def _h11_source_events(self):
        """Обработчик событий исходного подключения."""
        body = b""
        event = request = None
        while not isinstance(event, h11.EndOfMessage):
            event = self._h11_source.next_event()
            if event is h11.NEED_DATA:
                self._source_transport.resume_reading()
                break
            elif event is h11.PAUSED:
                self._source_transport.pause_reading()
                break
            elif isinstance(event, h11.Request):
                request = event
            elif isinstance(event, h11.Data):
                body += event.data
        else:
            if self._target_transport is None:
                host, port, path = parse_target(request)
                task = asyncio.create_task(self._target_connector(self._source_transport, host, port))
                task.add_done_callback(lambda task: self._target_connector_done(task, request, body))
            else:
                self._process_request(request, body)

    def _target_connector_done(self, future: asyncio.Task, request: h11.Request, body: bytes):
        """Обработка результата создания целевого подключения."""
        try:
            self._target_transport = future.result()
            if request.method == b"CONNECT":
                # Переключение в режим туннеля до целевого сервера
                self._source_transport.write(
                    self._h11_source.send(
                        h11.Response(status_code=200, reason="Connection established", headers=self.default_headers)
                    )
                )
            else:
                # Создаю клиент для контроля подключения к целевому серверу
                self._target_client = TargetClient(self._target_transport)
                self._process_request(request, body)
        except Exception as exc:
            host, port, path = parse_target(request)
            message = f"Failed to connect target {host}:{port}; {exc}"
            self._send_error(502, "Bad gateway", message)
            logger.warning(message)

    def _process_request(self, request: h11.Request, body: bytes):
        """Пересылка запроса на целевой сервер и получение ответа."""

        def process_request_done(task: asyncio.Task):
            try:
                response, body = task.result()
                self._send_message(response, body)
            except Exception as exc:
                message = f"Failed to process request; {exc}"
                self._send_error(502, "Bad gateway", message)

        host, port, path = parse_target(request)
        request = h11.Request(**dict(asdict(request), target=path))
        task = asyncio.create_task(self._target_client.send_request(request, body))
        task.add_done_callback(process_request_done)

    def _send_error(self, status_code: int, reason: str, message: str | None = None):
        """Отправка сообщения об ошибке в исходное подключение."""
        headers = [*self.default_headers, ("Connection", "close")]
        if message:
            message = message.encode("utf-8")
            headers.extend([("Content-Type", "text/plain"), ("Content-Length", str(len(message)))])
        self._send_message(h11.Response(status_code=status_code, reason=reason, headers=headers), message or b"")
        self._source_transport.close()

    def _send_message(self, event: h11.Event, data: bytes = b""):
        """Отправка сообщения в исходное подключение."""
        self._source_transport.write(self._h11_source.send(event))
        if data:
            self._source_transport.write(self._h11_source.send(h11.Data(data=data)))
        self._source_transport.write(self._h11_source.send(h11.EndOfMessage()))
        if self._h11_source.our_state == h11.MUST_CLOSE:
            self._source_transport.close()
        else:
            self._h11_source.start_next_cycle()
