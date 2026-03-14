import asyncio
import ipaddress
import logging
import struct
from asyncio import Transport
from collections.abc import Sequence
from enum import IntEnum, Enum

from overtun._types import TargetConnector

logger = logging.getLogger(":".join(__name__.split(".")))
logger.setLevel(logging.DEBUG)


class Version(bytes, Enum):
    SOCKS5 = b"\x05"


class Auth(bytes, Enum):
    """
    Методы авторизации SOCKS5
    """

    NoNeed = b"\x00"
    NoApplicable = b"\xff"


class Command(bytes, Enum):
    """
    Команды клиента SOCKS5
    """

    Connect = b"\x01"
    Bind = b"\x02"
    AssociateUDP = b"\x03"


class AddrType(bytes, Enum):
    """
    Тип целевого адреса
    """

    IPv4 = b"\x01"
    Domain = b"\x03"
    IPv6 = b"\x04"


class Error(Exception):
    """Ошибка SOCKS5 протокола."""

    args: tuple[bytes, Exception | str | None]

    def __init__(self, resp: bytes, exc_or_message: Exception | str | None = None):
        super().__init__(resp, exc_or_message)
        if isinstance(exc_or_message, Exception):
            self.__cause__ = exc_or_message


class Protocol(asyncio.Protocol):
    """
    Низкоуровневая реализация асинхронного SOCKS5 Proxy протокола (без авторизации!).
    """

    class State(IntEnum):
        Handshake = 0x01
        Authenticate = 0x02
        Connecting = 0x03

    def __init__(self, target_connector: TargetConnector) -> None:
        self._client_transport: Transport | None = None
        # self._target_transport: Transport | None = None
        # self._target_connector = target_connector
        self.__state = Protocol.State.Handshake
        self.__auth_method: Auth | None = None

    @property
    def auth_method(self) -> Auth | None:
        """Согласованный метод аутентификации."""
        return self.__auth_method

    @property
    def state(self) -> State:
        """Состояние КА протокола"""
        return self.__state

    def connection_made(self, transport: asyncio.Transport):
        """Клиентское подключение установлено."""
        self._client_transport = transport

    def data_received(self, data: bytes):
        """Обработка поступающих данных из клиентского подключения."""
        try:
            match self._state:
                case Protocol.State.Handshake:
                    self.handle_handshake(data)
                case Protocol.State.Authenticate:
                    self.handle_authentication(data)
                case Protocol.State.Connecting:
                    self.handle_connecting(data)
                case _:
                    raise ValueError("Unknown state")

        except Exception as exc:
            if not isinstance(exc, Error):
                exc = Error(b"", exc)
            self._handle_error(exc)

    def handle_handshake(self, data: bytes):
        """Обработка "handshake"."""
        if self.state.Handshake:
            if data.startswith(Version.SOCKS5):
                methods = list()
                length = data[1]
                for i in range(length):
                    methods.append(Auth(data[i + 1]))
                self._set_auth_method(self._select_auth_method(methods))
                self._set_state(Protocol.State.Authenticate)
                logger.debug(f"Handshake succeed; auth method: {self.auth_method}")
                return self.handle_authentication(data[length + 2 :])
            raise Error(b"", "SOCKS5 Handshake failed.")
        else:
            raise RuntimeError(f"Handshake, but FSM has other state: {self.state}")

    def handle_authentication(self, data: bytes):
        """Авторизация клиента"""
        if self.state.Authenticate:
            if self.auth_method == Auth.NoNeed:
                self._client_transport.write(Version.SOCKS5 + Auth.NoNeed)
                self._set_state(Protocol.State.Connecting)
            else:
                raise NotImplementedError("SOCKS5 Authentication isn't implemented")
        else:
            raise RuntimeError(f"Authentication, but FSM has other state: {self.state}")

    def handle_connecting(self, data: bytes):
        """Обработка подключения."""
        version, command, _, addr_type = [
            f(v) for f, v in zip((Version, Command, lambda a: a, AddrType), struct.unpack("cccc", data[:4]))
        ]
        match addr_type:
            case AddrType.IPv4:
                addr, data = ipaddress.IPv4Address(data[4:8]), data[8:]
            case AddrType.Domain:
                size = data[4]
                addr, data = data[5:5+size].decode('ascii'), data[5+size:]
            case AddrType.IPv6:
                addr, data = ipaddress.IPv6Address(data[4:20]), data[20:]
            case _:
                raise ValueError(f"Wrong connection request data")
        port, =  struct.unpack(">H", data[:2])
        assert version and command and addr_type and port


    def connection_lost(self, exc: Exception):
        """Клиентское подключение разорвано."""
        if self._target_transport is not None:
            self._target_transport.close()

    def _set_auth_method(self, value: Auth):
        self.__auth_method = value

    def _set_state(self, value: State):
        self.__state = value

    def _handle_error(self, exc: Exception):
        """Обработка ошибки."""
        resp, exc = exc.args
        message = f"Client connection fail: {exc}"
        extra = dict(peername=self._client_transport.get_extra_info("peername"))
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.exception(message, extra=extra)
        else:
            logger.warning(message, extra=extra)
        if resp:
            self._client_transport.write(resp)
        self._client_transport.close()

    def _select_auth_method(self, proposed: Sequence[Auth]) -> Auth:
        """Выбор метода авторизации."""
        if Auth.NoNeed in proposed:
            return Auth.NoNeed
        raise Error(Version.SOCKS5 + Auth.NoApplicable, "All proposed auth methods are not supported")
