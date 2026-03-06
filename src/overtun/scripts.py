import argparse
import asyncio
import logging
import sys

from . import ssh2, httproxy


def establish_httproxy(remote: str, proxy_port: int):
    """Establish `overtun` HTTP CONNECT Proxy."""

    async def async_main():
        async with ssh2.connect(remote) as conn:
            httproxy_server = await httproxy.create_server(conn, "127.0.0.1", proxy_port)
            async with httproxy_server:
                await httproxy_server.serve_forever()

    asyncio.run(async_main())


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="`overtun` Network tunnels builder")
    parser.add_argument("remote", help="Remote SSH connection: [username@]hostname:[port]")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Commands")

    parser_proxy = subparsers.add_parser("httproxy", help="Establish `overtun` HTTP CONNECT Proxy")
    parser_proxy.add_argument("-x", "--proxy_port", help="Localhost proxy port", default=8000, type=int)

    args = parser.parse_args()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s"))
    ssh2.logger.addHandler(handler)
    httproxy.logger.addHandler(handler)
    handler.setLevel(logging.DEBUG)

    match args.command:
        case "httproxy":
            establish_httproxy(args.remote, args.proxy_port)
        case _:
            raise Exception("Unknown command")
