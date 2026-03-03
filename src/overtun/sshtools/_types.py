from collections.abc import Mapping, Iterable
from enum import StrEnum
from socket import socket
import typing as t

from paramiko import PKey, Channel, ProxyCommand
from paramiko.auth_strategy import AuthStrategy

if t.TYPE_CHECKING:
    from paramiko.client import _TransportFactory
else:
    type _TransportFactory = t.Any


class AllowHostIdentification(StrEnum):
    CREATE = "CREATE"
    CHANGE = "CHANGE"


class SSHConnectParams(t.TypedDict, total=False):
    """
    Params for SSH client `connect` method.
    """

    # hostname: str
    port: int
    username: str
    password: str
    pkey: PKey
    key_filename: str
    timeout: float
    allow_agent: bool
    look_for_keys: bool
    compress: bool
    sock: str | tuple[str, int] | socket | Channel | ProxyCommand
    gss_auth: bool
    gss_kex: bool
    gss_deleg_creds: bool
    gss_host: str
    banner_timeout: float
    auth_timeout: float
    channel_timeout: float
    gss_trust_dns: bool
    passphrase: str
    disabled_algorithms: Mapping[str, Iterable[str]]
    transport_factory: _TransportFactory
    auth_strategy: AuthStrategy
