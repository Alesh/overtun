import logging
from io import StringIO
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from paramiko import SSHException, RSAKey, ECDSAKey, Ed25519Key, PKey
from paramiko.client import SSHClient

logger = logging.getLogger("overtun:ssh")
logger.setLevel(logging.INFO)


# Default names of key files
KEY_TYPES = [
    ("id_rsa", RSAKey),
    ("id_ecdsa", ECDSAKey),
    ("id_ed25519", Ed25519Key),
]


def get_default_key(preferred_type: type[PKey] | None = None) -> PKey | None:
    """Get default private key from `~/.ssh/`."""
    candidate = None
    home = Path.home()
    if home.joinpath(".ssh").exists():
        for filename, key_type in KEY_TYPES:
            filename = home.joinpath(".ssh").joinpath(filename)
            if filename.exists():
                if pkey := get_pkey_from_pem(filename.read_text(encoding="ascii")):
                    candidate = pkey
                    if preferred_type and isinstance(pkey, preferred_type):
                        break
    return candidate


def get_pkey_from_pem(private_key_pem: str) -> PKey:
    """Get private key from PEM format."""
    key_file = StringIO(private_key_pem.strip())
    for _, kt in KEY_TYPES:
        try:
            key_file.seek(0)
            return kt.from_private_key(key_file)
        except SSHException:
            continue
    raise SSHException("Failed to load private key from PEM")


def get_pem_from_pkey(pkey: PKey) -> str:
    """Get private key from PEM format."""
    if isinstance(pkey, Ed25519Key):
        raw_ed25519key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(pkey._signing_key))
        return raw_ed25519key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
    elif isinstance(pkey, (RSAKey, ECDSAKey)):
        io = StringIO()
        pkey.write_private_key(io)
        return io.getvalue()
    raise ValueError("Wrong key type")


def generate_key(key_type: type[PKey]) -> PKey:
    """Generate private key."""
    if key_type == Ed25519Key:
        raw_ed25519key = ed25519.Ed25519PrivateKey.generate()
        raw_ed25519key_pem = raw_ed25519key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return Ed25519Key.from_private_key(StringIO(raw_ed25519key_pem.decode()))
    elif key_type == RSAKey:
        return RSAKey.generate(2048)
    elif key_type == ECDSAKey:
        return ECDSAKey.generate()
    raise ValueError("Wrong key type")


def deploy_public_key(client: SSHClient, pkey: PKey) -> bool:
    """Deploy public key to remote `~/.ssh/authorized_keys`."""
    public_key = f"{pkey.get_name()} {pkey.get_base64()} overtun"
    stdin, stdout, stderr = client.exec_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    stdout.channel.recv_exit_status()  # waiting for completion
    stdin, stdout, stderr = client.exec_command(
        f'echo "{public_key}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
    )
    exit_status = stdout.channel.recv_exit_status()
    return exit_status == 0
