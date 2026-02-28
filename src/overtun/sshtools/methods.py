import socket
from collections.abc import Callable


from paramiko import (
    RSAKey,
    ECDSAKey,
    Ed25519Key,
    SSHException,
    SSHClient,
    AutoAddPolicy,
    BadHostKeyException,
    AuthenticationException,
)
from paramiko.client import RejectPolicy
from paramiko.pkey import PKey

from .utils import logger, generate_key, deploy_public_key, get_pem_from_pkey
from .opts import SshOpts, make_ssh_opts, extract_ssh_params


def ensure_connection(
    username: str,
    hostname: str,
    port: int | None = None,
    get_priv_key: Callable[[str, str], PKey | None] | None = None,
    get_password: Callable[[str, str], str | None] | None = None,
    command: str | None = None,
    default_key_type: RSAKey | ECDSAKey | Ed25519Key | None = None,
    ssh_opts: SshOpts | None = None,
) -> tuple[str, str] | None:
    """
    Verify SSH connection to a remote host.

    Args:
        username: Username for SSH connection.
        hostname: Hostname or IP address.
        port: Connection port, defaults to 22.
        get_priv_key: Callback that returns user's private key for the (user, host) pair if defined.
        get_password: Callback that returns user's password for the (user, host) pair if defined.
        command: Command to execute on the remote host after successful connection.
        default_key_type: Default generated key type, Ed25519Key if not specified.
        ssh_opts: SSH connection parameters.
    Returns:
        Tuple: PEM representation of the private key used for connection, console output result
        of command execution on the remote host.
    """
    port = int(port or 22)
    command = command or "true"
    default_key_type = default_key_type or Ed25519Key
    ssh_opts = make_ssh_opts(**(ssh_opts or {}))

    # Load or create keys
    try:
        if pkey := (get_priv_key and get_priv_key(username, hostname)):
            pass
        else:
            pkey = generate_key(default_key_type)
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
        ssh_params = dict(extract_ssh_params(ssh_opts), pkey=pkey)
        while True:
            try:
                client.connect(hostname=hostname, port=port, username=username, **ssh_params)
                break  # success
            except BadHostKeyException as e:
                if isinstance(e.expected_key, PKey):
                    expected = f"{e.expected_key.get_name()} {e.expected_key.get_base64()}"
                    message = f"Remote host {hostname} identification changed, expected: {expected}"
                    if ssh_opts.get("allow_change_host_identification"):
                        logger.warning(f"{message}")
                        raise NotImplementedError(
                            "Automatic key replacement is unavailable. "
                            "If you're sure you need it, please do it manually."
                        )
                else:
                    message = f"Remote host {hostname} identification not found in known_hosts"
                    if ssh_opts.get("allow_create_host_identification"):
                        logger.warning(f"{message}")
                        client._host_keys.add(hostname, e.key.get_name(), e.key)
                        if client._host_keys_filename is not None:
                            client.save_host_keys(client._host_keys_filename)
                        continue
                logger.error(f"{message}")
                return None
            except AuthenticationException:
                if "password" not in ssh_params:
                    message = f"Key authentication failed for {username}@{hostname}"
                    if password := get_password(username, hostname):
                        logger.warning(f"{message}; password will be used.")
                        ssh_params = dict(extract_ssh_params(ssh_opts), password=password)
                        continue
                    logger.error(f"{message}, and password isn't defined")
                    return None
                else:
                    logger.error(f"Password authentication failed for {username}@{hostname}")
                    return None
            except (SSHException, socket.error) as e:
                logger.error(f"Failed to connect to {username}@{hostname}; {e}")
                return None

        if "password" in ssh_params:
            # Connected with password; public key will be placed in ~/.ssh/authorized_keys on the remote host.
            if not deploy_public_key(client, pkey):
                logger.error(f"Failed to deploy public key for {username}@{hostname}")
                return None
            else:
                logger.info(f"Added public key for {username}@{hostname} to remote `~/.ssh/authorized_keys`")
    finally:
        client.close()

    # Final check
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    ssh_params = dict(extract_ssh_params(ssh_opts), pkey=pkey)
    try:
        client.connect(hostname=hostname, port=port, username=username, **ssh_params)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode("utf-8").strip()
        error = stderr.read().decode("utf-8").strip()
        output = error if error else output
        private_key_pem = get_pem_from_pkey(pkey)
        return private_key_pem, output
    except (SSHException, socket.error) as e:
        logger.error(f"Final check failed for {username}@{hostname}; {e}")
        return None
    finally:
        client.close()
