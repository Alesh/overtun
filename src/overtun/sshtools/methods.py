import socket
from collections.abc import Callable

from paramiko import PKey, SSHException, RejectPolicy, BadHostKeyException, SSHClient, AuthenticationException

from ._types import AllowHostIdentification, SSHConnectParams
from .utils import logger


def ensure_connection(
    hostname: str,
    port: int,
    username: str,
    *,
    get_pkey: Callable[[str, str], PKey] = None,
    get_password: Callable[[str, str], str] = None,
    allow_host_identification: tuple[AllowHostIdentification, ...] = None,
    **kwargs,
) -> SSHConnectParams | None:
    """
    Checks and, if necessary, prepares an SSH connection to a remote host.
    """

    # Load or create keys
    pkey = None
    try:
        if get_pkey:
            pkey = get_pkey(username, hostname)
    except SSHException as e:
        logger.warning(f"Failed to get private key; {e}")
        return None

    class OurPolicy(RejectPolicy):
        def missing_host_key(self, client, hostname, key):
            raise BadHostKeyException(hostname, key, ...)

    # Try to connect
    client = SSHClient()
    client.set_missing_host_key_policy(OurPolicy())
    client.load_system_host_keys()
    try:
        params = dict(kwargs, pkey=pkey)
        while True:
            try:
                client.connect(hostname=hostname, port=port, username=username, **params)
                break  # success
            except BadHostKeyException as e:
                if isinstance(e.expected_key, PKey):
                    expected = f"{e.expected_key.get_name()} {e.expected_key.get_base64()}"
                    message = f"Remote host {hostname} identification changed, expected: {expected}"
                    if AllowHostIdentification.CHANGE in allow_host_identification:
                        logger.warning(f"{message}")
                        raise NotImplementedError(
                            "Automatic key replacement is unavailable. "
                            "If you're sure you need it, please do it manually."
                        )
                else:
                    message = f"Remote host {hostname} identification not found in known_hosts"
                    if AllowHostIdentification.CREATE in allow_host_identification:
                        logger.warning(f"{message}")
                        client._host_keys.add(hostname, e.key.get_name(), e.key)
                        if client._host_keys_filename is not None:
                            client.save_host_keys(client._host_keys_filename)
                        continue
                logger.error(f"{message}")
                return None
            except AuthenticationException:
                if "password" not in params:
                    message = f"Key authentication failed for {username}@{hostname}"
                    if password := get_password(username, hostname):
                        logger.warning(f"{message}; password will be used.")
                        params = dict(kwargs, password=password)
                        continue
                    logger.error(f"{message}, and password isn't defined")
                    return None
                else:
                    logger.error(f"Password authentication failed for {username}@{hostname}")
                    return None
            except (SSHException, socket.error) as e:
                logger.error(f"Failed to connect to {username}@{hostname}; {e}")
                return None
        return SSHConnectParams(**params)
    finally:
        client.close()


def deploy_public_key(client: SSHClient, PKey) -> bool:
    """Deploy a public key to the ~/.ssh/authorized_keys on remote host."""
    raise NotImplementedError
    # if "password" in params:
    #     # Connected with password; public key will be placed in ~/.ssh/authorized_keys on the remote host.
    #     if not deploy_public_key(client, pkey):
    #         logger.error(f"Failed to deploy public key for {username}@{hostname}")
    #         return None
    #     else:
    #         logger.info(f"Added public key for {username}@{hostname} to remote `~/.ssh/authorized_keys`")
