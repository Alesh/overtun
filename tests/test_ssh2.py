import logging

import asyncssh
from asyncssh import SSHClientConnection


from overtun.ssh2 import connect, logger, deploy_public_key


async def test_ssh_connection(hostname, username, password, ppkey):
    logger.setLevel(logging.DEBUG)

    used_password = False
    used_private_key = False

    def get_private_key(username, hostname):
        nonlocal used_private_key
        assert username == username
        assert hostname == hostname
        if ppkey:
            used_private_key = True
            return asyncssh.import_private_key(ppkey)
        return None

    def get_password(username, hostname):
        nonlocal used_password
        assert username == username
        assert hostname == hostname
        used_password = True
        return password

    async with connect(hostname, username=username, get_private_key=get_private_key, get_password=get_password) as conn:
        assert isinstance(conn, SSHClientConnection)
        if used_password:
            if pkey := get_private_key(username, hostname):
                await deploy_public_key(conn, pkey, "overtun_test")
        else:
            assert used_private_key
        r = await conn.run("uname")
        assert r.exit_status == 0
