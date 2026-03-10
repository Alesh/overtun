import argparse
import asyncio
import logging
import os
import sys
import typing as t
from getpass import getpass

import asyncssh
from asyncssh import SSHClientConnectionOptions

from overtun import httproxy, ssh2proxy


def proxy_over_ssh():
    """Запускает HTTP proxy использующий SSH туннели."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    httproxy.logger.addHandler(handler)
    handler.setLevel(logging.DEBUG)

    parser = argparse.ArgumentParser(
        description="Creates a minimalistic local HTTP proxy server using an SSH server connection."
    )
    parser.add_argument(
        "remote",
        help="Connection string to a remote SSH server: [user@]host[:port], ex: joe@my-ssh-server.net:2222",
    )
    parser.add_argument("-x", "--proxy-port", default=8000, type=int, help="localhost proxy port")
    args = parser.parse_args()

    def get_password(username, hostname):
        try:
            return getpass(prompt=f"{username}@{hostname}'s password: ")
        except KeyboardInterrupt:
            sys.exit(-2)

    port = 22
    username = None
    hostname = args.remote
    proxy_port = args.proxy_port
    if "@" in hostname:
        username, hostname = hostname.split("@")
    if ":" in hostname:
        hostname, port = hostname.split(":")
        port = int(port)
    username = username or os.getenv("USER")

    options: dict[str, t.Any] = dict()
    if username:
        options["username"] = username
    if get_password:
        options["password"] = lambda: get_password(username, hostname)

    async def async_run():
        async with asyncssh.connect(hostname, port, options=SSHClientConnectionOptions(**options)) as cc:
            server = await ssh2proxy.create_server(cc, "127.0.0.1", proxy_port)
            async with server:
                httproxy.logger.info(f"Established HTTP CONNECT Proxy on 127.0.0.1:{proxy_port}")
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    cc.close()

    asyncio.run(async_run())
