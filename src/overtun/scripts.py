import argparse

from overtun.sshtools import SSHConnection


def install(remote: str, port: int):
    """Installs the overtun on a remote server"""
    with SSHConnection(remote, port) as client:
        assert client
        raise NotImplementedError


def http_proxy(remote: str, port: int, proxy_port: int):
    """Establish `overtun` HTTP proxy"""
    raise NotImplementedError


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="`overtun` Network tunnels builder")
    parser.add_argument("remote", help="Remote host name or IP address")
    parser.add_argument("-p", "--port", help="Remote ssh port", default=22)

    subparsers = parser.add_subparsers(dest="command", required=True, help="Commands")

    parser_install = subparsers.add_parser("install", help="Install `overtun` on remote host")
    parser_install.add_argument("module", help="Module name")

    parser_proxy = subparsers.add_parser("http_proxy", help="Establish `overtun` HTTP proxy")
    parser_proxy.add_argument("-x", "--proxy_port", help="Localhost proxy port", default=8080)

    args = parser.parse_args()

    match args.command:
        case "install":
            install(args.remote, args.port)
        case "http_proxy":
            http_proxy(args.remote, args.port, args.proxy_port)
        case _:
            raise Exception("Unknown command")
