# /// script
# requires-python = ">=3.12"
# dependencies = ["overtun"]
# [tool.uv.sources]
# overtun = { path = "../", editable = true }
# ///
import argparse
import asyncio
import csv
import hashlib
import typing as t

from overtun.intyperr import Address
from overtun.protocols import ProxyProtocol
from overtun.proxy import ConnectionRule, ProxyServer
from overtun.utils.registers import AddressInfoRegister, AddressInfo


class TargetRule(t.NamedTuple):
    target: Address
    connection_rule: ConnectionRule
    fake_sni: str | None


class OverMoleProtocol(ProxyProtocol):
    pass


class OverMoleServer(ProxyServer):
    ProxyProtocol = OverMoleProtocol

    def __init__(self, *args, secret: bytes = None, **kwargs):
        self._secret = secret
        super().__init__(*args, **kwargs)


def prepare_address_register(
    domains: list[str], fake_sni: str = None, allowed_rule=ConnectionRule.Tunnel
) -> AddressInfoRegister[TargetRule]:
    """
    Register with target connection rule.

    Notes:
        CSV file field names:      domain,allow,fake_sni
        for connecting via tunnel: secret-side.com,Y,something.com
        for reset connection:      bullshit.com,N,
    """
    addresses_info = list()

    def normalize_address(address: str) -> Address:
        if ":" in address:
            host, port = address.split(":")
            return Address(host, int(port))
        return Address(address, 443)

    for domain in domains:
        if domain.startswith("@"):
            with open(domain[1:], "r") as csvfile:
                reader = csv.DictReader(csvfile)
                for domain, allow, fake_sni in reader:
                    addresses_info.append(
                        TargetRule(
                            normalize_address(domain),
                            allowed_rule if allow.upper() in ("1", "Y", "T", "TRUE") else ConnectionRule.Reset,
                            fake_sni or None,
                        )
                    )
        else:
            addresses_info.append(TargetRule(normalize_address(domain), ConnectionRule.Tunnel, fake_sni))
    return AddressInfoRegister[TargetRule](addresses_info)


def async_run_server(server):
    async def async_run():
        async with server:
            await server

    try:
        asyncio.run(async_run())
    except KeyboardInterrupt:
        pass


def outlet(address: Address, secret: bytes):
    outlet_server = OverMoleServer(address, secret=secret)
    async_run_server(outlet_server)


def proxy(
    address: Address,
    register: AddressInfoRegister[TargetRule] | None = None,
    outlet: Address | None = None,
    secret: bytes | None = None,
):
    proxy_server = OverMoleServer(address, outlet=outlet, register=register, secret=secret)
    async_run_server(proxy_server)


###

parser = argparse.ArgumentParser(prog="overmole")


def secret_from(value: str):
    if len(value) < 16:
        parser.error("-s/--secret argument: too short, must be at least 16 characters long")
    return hashlib.sha1(value.encode("utf8")).digest()


parser.add_argument(
    "-a",
    "--address",
    help="The address (host:port) on which the listening is established.",
    default="127.0.0.1:10443",
    type=Address.from_,
)

sub_parser = parser.add_subparsers(title="Launch mode", required=True, dest="mode")

outlet_parser = sub_parser.add_parser("outlet", help="Starts the tunnel outlet node")
outlet_parser.add_argument("-s", "--secret", help="Tunnel negotiation secret.", required=True)

proxy_parser = sub_parser.add_parser("proxy", help="Starts the proxy server")
proxy_parser.add_argument(
    "-o",
    "--outlet",
    help="Address (host:port) of the tunnel outlet, enabled tunneling",
    type=Address.from_,
)
proxy_parser.add_argument(
    "domain",
    nargs="*",
    help=(
        "The domain(s) to tunnel to, or a CSV file with domain rules if the names start with the @;"
        " required for selective tunneling."
    ),
)
proxy_parser.add_argument("-s", "--secret", help="Tunnel negotiation secret, required for tunneling", type=secret_from)
proxy_parser.add_argument("-f", "--fake-sni", help="Default fake SNI, enabled SNI masking")

args = parser.parse_args()

if args.mode == "proxy":
    if args.outlet is not None:
        if args.secret is None:
            parser.error("argument -s/--secret: Required for tunneling")
        if not args.domain:
            parser.error("domain(s): Required for tunneling")
        register = prepare_address_register(args.domain, args.fake_sni)
        proxy(args.address, register, args.outlet, args.secret)
    else:
        if args.domain:
            register = prepare_address_register(args.domain, allowed_rule=ConnectionRule.Direct)
            proxy(args.address, register)
        else:
            proxy(args.address)
else:
    outlet(args.address, args.secret)
