import contextlib
import os
from collections.abc import Callable

from paramiko import PKey, RSAKey, ECDSAKey, Ed25519Key
from paramiko.client import SSHClient, AutoAddPolicy

from .methods import ensure_connection
from .opts import SshOpts, make_ssh_opts, extract_ssh_params
from .utils import get_default_key, get_pkey_from_pem

__all__ = ["SSHConnection"]


class SSHConnection(contextlib.AbstractContextManager[SSHClient, None]):
    """
    SSH connection context manager
    """

    def __init__(
        self,
        hostname: str,
        port: int | None = None,
        username: str | None = None,
        get_pkey: Callable[[str, str], PKey | None] | None = None,
        get_password: Callable[[str, str], str | None] | None = None,
        default_key_type: RSAKey | ECDSAKey | Ed25519Key | None = None,
        ssh_opts: SshOpts | None = None,
    ):
        self._hostname = hostname
        self._port = int(port or 22)
        self._username = username or os.getenv("USER")
        self._default_key_type = default_key_type or Ed25519Key
        self._ssh_opts = make_ssh_opts(**(ssh_opts or {}))

        def default_get_pkey(username_, host_) -> PKey | None:
            assert username_ == username and host_ == hostname
            return os.environ.get("PRIVATE_KEY", get_default_key())

        def default_get_password(username_, host_) -> str | None:
            assert username_ == username and host_ == hostname
            return os.environ.get("PASSWORD")

        self._get_pkey = get_pkey or default_get_pkey
        self._get_password = get_password or default_get_password
        self._client: SSHClient | None = None

    def __enter__(self) -> SSHClient:
        if result := ensure_connection(
            self._username,
            self._hostname,
            self._port,
            self._get_pkey,
            self._get_password,
            default_key_type=self._default_key_type,
            ssh_opts=self._ssh_opts,
        ):
            pkey_pem, _ = result
            if pkey := get_pkey_from_pem(pkey_pem):
                self._client = SSHClient()
                self._client.set_missing_host_key_policy(AutoAddPolicy())
                ssh_params = dict(extract_ssh_params(self._ssh_opts), pkey=pkey)
                self._client.connect(hostname=self._hostname, port=self._port, username=self._username, **ssh_params)
                return self._client
        raise RuntimeError("Cannot create SSH connection.")

    def __exit__(self, *exc_info):
        pass
