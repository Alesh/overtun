import asyncio
import logging
from asyncio import Transport
from enum import Enum, auto

from ._errors import DataError
from ._types import TargetDecoder, TargetConnector

logger = logging.getLogger("overtun")
logger.setLevel(logging.DEBUG)


class State(Enum):
    """
    Состояния протокола
    """

    Initializing = auto()
    Connecting = auto()
    Connected = auto()
    Closing = auto()
    Closed = auto()


class Bridge(asyncio.Protocol):
    """
    Простая пересылка данных.
    """

    OUTCOMING_THRESHOLD = 64 * 1024

    def __init__(self, outcoming: Transport | None = None):
        self._incoming: Transport | None = None
        self.__state = State.Initializing
        self._set_outcoming_transport(outcoming)

    def _set_outcoming_transport(self, transport: Transport):
        self.__outcoming = transport
        if self.__outcoming and self._incoming and self.state in (State.Initializing, State.Connecting):
            self._set_state(State.Connected)

    @property
    def state(self) -> State:
        """Состояние протокола."""
        return self.__state

    def _set_state(self, value: State):
        self.__state = value

    def connection_made(self, incoming: Transport):
        """Обрабатывает подключение входящего транспорта."""
        self._incoming = incoming
        self._set_outcoming_transport(self.__outcoming)

    def data_received(self, data: bytes):
        """Получает входящие данные и пересылает, если определен исходящий транспорт."""
        if self.state == State.Connected:
            self.__outcoming.write(data)
            if self.__outcoming.get_write_buffer_size() >= self.OUTCOMING_THRESHOLD:
                self.__outcoming.pause_reading()
        else:
            raise ConnectionError("Outcoming connection is not set")

    def connection_lost(self, exc: Exception):
        """Обрабатывает отключение входящего транспорта."""
        if self.__outcoming is not None:
            self.__outcoming.close()
        self._set_state(State.Closed)

    def _handle_error(self, exc: Exception):
        extra = dict(peername=self._incoming.get_extra_info("peername"))
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.exception(str(exc), extra=extra)
        else:
            logger.warning(str(exc), extra=extra)
        self._incoming.close()


class Dispatcher(Bridge):
    """
    Передает входящие данные на анализ, и на основании результата пересылает из дальше.
    """

    DETERMINING_THRESHOLD = 2 * 1024

    def __init__(self, target_decoder: TargetDecoder, target_connector: TargetConnector):
        self.__buffer = b""
        self.__target_decoder = target_decoder
        self.__target_connector = target_connector
        super().__init__()

    def data_received(self, data: bytes):
        """Получает входящие данные и пересылает, если подобран исходящий транспорт."""
        super_data_received = super().data_received
        if self.state == State.Connected:
            super_data_received(data)
        else:
            try:
                self.__buffer += data
                if self.state == State.Initializing:
                    if target := self.__target_decoder(self.__buffer):
                        self._set_state(State.Connecting)

                        ## Запускаю задачу создания целевого подключения

                        def target_connector_done(task: asyncio.Task):
                            try:
                                self._set_outcoming_transport(task.result())
                                data, self.__buffer = self.__buffer, b""
                                super_data_received(data)
                            except Exception as exc:
                                self._handle_error(exc)

                        task = asyncio.create_task(self.__target_connector(self._incoming, target))
                        task.add_done_callback(target_connector_done)

                    else:
                        if len(self.__buffer) >= self.DETERMINING_THRESHOLD:
                            raise DataError("Incoming traffic is not determined", self.__buffer)
                        return
            except Exception as exc:
                self._handle_error(exc)
