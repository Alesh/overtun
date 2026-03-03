import argparse
import logging
import sys

from overtun.sshtools import SSHConnection
from overtun.sshtools.utils import logger as ssh_logger, get_default_key

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter("%(asctime)s %(name)s\t%(levelname)s\t%(message)s"))


def install(remote_host: str, remote_port: int):
    """Installs the overtun on a remote server"""
    raise NotImplementedError


def http_proxy(remote_host: str, remote_port: int, proxy_port: int):
    """Establish `overtun` HTTP proxy"""
    ssh_logger.addHandler(console_handler)
    pkey = get_default_key()
    if pkey is None:
        raise Exception("No SSH key")
    with SSHConnection(remote_host, port=remote_port, pkey=pkey) as ssh_conn:
        with ssh_conn.connect(timeout=5.0) as ssh:
            assert ssh
            return sys.exit(0)
    return sys.exit(2)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="`overtun` Network tunnels builder")
    parser.add_argument("remote", help="Remote host name or IP address")
    parser.add_argument("-p", "--ssh-port", help="Remote ssh port", default=22)

    subparsers = parser.add_subparsers(dest="command", required=True, help="Commands")

    parser_install = subparsers.add_parser("install", help="Install `overtun` on remote host")
    parser_install.add_argument("module", help="Module name")

    parser_proxy = subparsers.add_parser("http_proxy", help="Establish `overtun` HTTP Proxy")
    parser_proxy.add_argument("-x", "--proxy-port", help="HTTP Proxy port", default=8000)

    args = parser.parse_args()

    match args.command:
        case "install":
            install(args.remote, args.ssh_port)
        case "http_proxy":
            http_proxy(args.remote, args.ssh_port, args.proxy_port)
        case _:
            raise Exception("Unknown command")
