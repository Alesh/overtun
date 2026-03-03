import os
import typing as t
from collections.abc import Callable
from contextlib import contextmanager, AbstractContextManager

from paramiko import PKey
from paramiko.client import SSHClient, AutoAddPolicy

from ._types import SSHConnectParams, AllowHostIdentification
from .methods import ensure_connection


__all__ = ["SSHConnection"]


class SSHConnection(AbstractContextManager[t.Self, None]):
    """
    SSH connection context manager
    """

    def __init__(
        self,
        hostname: str,
        *,
        get_pkey: Callable[[str, str], PKey] | None = None,
        get_password: Callable[[str, str], str] | None = None,
        allow_change_host_identification: bool = False,
        allow_create_host_identification: bool = True,
        **kwargs: t.Unpack[SSHConnectParams],
    ):
        username = os.getenv("USER", "root")
        if "@" in hostname:
            username, hostname = hostname.split("@")
        self._hostname = hostname
        self._client: SSHClient | None
        self._allow_host_identification = tuple(
            filter(
                lambda a: a,
                [
                    AllowHostIdentification.CHANGE if allow_change_host_identification else None,
                    AllowHostIdentification.CREATE if allow_create_host_identification else None,
                ],
            )
        )

        self._get_pkey = get_pkey
        if get_pkey is None and ("pkey" in kwargs or "key_filename" in kwargs):
            if "key_filename" in kwargs:
                pkey = PKey.from_path(kwargs.pop("key_filename"), kwargs.pop("passphrase", None))
            else:
                pkey = kwargs.pop("pkey", None)
            self._get_pkey = lambda *args: pkey

        self._get_password = get_password
        if get_password is None and "password" in kwargs:
            password = kwargs.pop("password")
            self._get_password = lambda *args: password

        self._params = dict(
            hostname=hostname,
            username=username,
            port=kwargs.get("port", 22),
            look_for_keys=kwargs.pop("look_for_keys", False),
            allow_agent=kwargs.pop("allow_agent", False),
        )

    def __enter__(self):
        self._client = SSHClient()
        return self

    def __exit__(self, exc_type, exc_value, traceback, /):
        self._client.close()
        self._client = None

    def connect(self, **kwargs: t.Unpack[SSHConnectParams]) -> AbstractContextManager[SSHClient, None]:
        if self._client is None:
            raise ValueError("SSH connection context is required")

        @contextmanager
        def connect_ctx():
            try:
                if params := ensure_connection(
                    get_pkey=self._get_pkey,
                    get_password=self._get_password,
                    allow_host_identification=self._allow_host_identification,
                    **self._params,
                ):
                    if AllowHostIdentification.CREATE in self._allow_host_identification:
                        self._client.set_missing_host_key_policy(AutoAddPolicy())
                    params = dict(**self._params, **kwargs, **params)
                else:
                    raise ValueError("Fail to check SSH connection")
                self._client.connect(self._hostname, **params)
                yield self._client
            except Exception as e:
                yield e

        return connect_ctx()
