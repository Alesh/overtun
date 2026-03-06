import logging
import os
import typing as t
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

import asyncssh
from asyncssh import SSHClientConnection, SSHKey, SSHClientConnectionOptions
from typing_extensions import Awaitable

from overtun.utils import _get_result

logger = logging.getLogger(":".join(__name__.split(".")))
logger.setLevel(logging.DEBUG)

type Hostname = str
type Username = str
type Password = str
type GetPassword = Callable[[Username, Hostname], Awaitable[Password | None] | Password | None]
type GetPrivateKey = Callable[[Username, Hostname], Awaitable[SSHKey | None] | SSHKey | None]


def connect(
    hostname: str,
    *,
    port: int = 22,
    username: str | None = None,
    get_password: GetPassword | None = None,
    get_private_key: GetPrivateKey | None = None,
) -> AbstractAsyncContextManager[SSHClientConnection]:
    """
    SSH connection context manager.
    """

    username = None
    if "@" in hostname:
        username, hostname = hostname.split("@")
    if ":" in hostname:
        hostname, port = hostname.split(":")
        port = int(port)
    username = username or os.getenv("USER")

    @asynccontextmanager
    async def ssh2connection_ctx():
        options: dict[str, t.Any] = dict()
        if username:
            options["username"] = username

        if get_password:
            if password := await _get_result(get_password, username, hostname):
                options["password"] = password
        if get_private_key:
            if private_key := await _get_result(get_private_key, username, hostname):
                options["client_keys"] = [private_key]
        try:
            async with asyncssh.connect(hostname, port, options=SSHClientConnectionOptions(**options)) as conn:
                yield conn
        except Exception as exc:
            if not logger.isEnabledFor(logging.DEBUG):
                logger.error(f"Cannot establish SSH connection: {exc}")
            else:
                raise exc

    return ssh2connection_ctx()


async def deploy_public_key(cc: SSHClientConnection, key: SSHKey, suffix: str = None) -> bool:
    line = key.export_public_key().decode("utf8").strip()
    algo, pub, suffix_ = line.split(" ")
    if suffix:
        line = f"{algo} {pub} {suffix}"
    r = await cc.run("cat ~/.ssh/authorized_keys")
    if r.exit_status == 0:
        if pub not in r.stdout:
            return await cc.run(f"echo {line} >> ~/.ssh/authorized_keys") == 0
    else:
        return await cc.run(f"echo {line} > ~/.ssh/authorized_keys") == 0
    return True
