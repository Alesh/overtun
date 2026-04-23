import argparse
import asyncio
import csv
import hashlib
import os
import re
import sys
import pathlib
from asyncio import Server
from collections.abc import Sequence, Callable

from overtun.primitives import Address, TargetDesc
from overtun.servers import create_outlet, create_proxy


async def outlet(
    address: Address,
    secret: bytes,
    handle_params: Sequence[str] = None,
) -> Server:
    return await create_outlet(address, secret, handle_params)


async def proxy(
    address: Address,
    outlet_address: Address | None = None,
    secret: bytes | None = None,
    selective_rules: Sequence[pathlib.Path] | None = None,
    default_rule: str = "direct",
    handle_params: Sequence[str] = None,
):
    # target_registry: Callable[[Address], TargetDesc[str] | None] | None = None,
    pass


def main(args: Sequence[str] | None = None) -> None:
    args = args or sys.argv

    parser = argparse.ArgumentParser(prog=args[0])

    def parse_handle_params(value: str):
        return value
        # parser.error("Loading of handle modules not yet implemented, use default")

    def parse_secret(value: str):
        if len(value) < 16:
            parser.error("-s/--secret argument: too short, must be at least 16 characters long")
        return hashlib.sha1(value.encode("utf8")).digest()

    def parse_selective_rules(value: str):
        filename = pathlib.Path(value)
        if filename.is_file() and filename.exists():
            with open(filename, "r") as f:
                csv_reader = csv.reader(f)
                if tuple(next(csv_reader)) == ("address", "rule", "fake"):
                    return filename
        parser.error(
            "-r/--selective-rules: should be a comma separated csv file with field: address, rule, fake_host"
        )

    parser.add_argument(
        "handle_params",
        metavar="HANDLE_PARAMS",
        help="Handle module and its parameters; default is ordinary processing.",
        nargs="*",
        type=parse_handle_params,
    )
    parser.add_argument(
        "-a",
        "--address",
        metavar="ADDRESS",
        help="The address (host:port) on which the listening is established, default 127.0.0.1:10443.",
        default=os.environ.get("ADDRESS", "127.0.0.1:10443"),
        type=Address.parse,
    )
    parser.add_argument(
        "-s",
        "--secret",
        metavar="SECRET",
        help="Tunnel negotiation secret.",
        default=os.environ.get("SECRET"),
        required=(parser.prog == "overmole-outlet"),
        type=parse_secret,
    )
    match parser.prog:
        case "overmole-proxy":
            parser.description = "Starts the proxy server"
            parser.add_argument(
                "-o",
                "--outlet-address",
                metavar="OUTLET_ADDRESS",
                help="Address (host:port) of the tunnel outlet, enabled tunneling",
                default=os.environ.get("OUTLET_ADDRESS"),
                type=Address.parse,
            )
            parser.add_argument(
                "-r",
                "--selective-rules",
                metavar="SELECTIVE_RULES",
                nargs="*",
                help="CSV files with selective forwarding rules; fields: address, rule, fake_host; comma separated.",
                default=os.environ.get("SELECTIVE_RULES"),
                type=parse_selective_rules,
            )
            parser.add_argument(
                "-d",
                "--default-rule",
                metavar="DEFAULT_RULE",
                choices=["tunnel", "direct", "drop"],
                help="Default selective rule; default 'direct'.",
                default=os.environ.get("DEFAULT_RULE", "direct"),
            )
        case "overmole-outlet":
            parser.description = "Starts the tunnel outlet"
        case _:
            raise RuntimeError("Unrecognized launcher")

    args = parser.parse_args(args[1:])

    if getattr(args, "selective_rules", None) and isinstance(args.selective_rules, str):
        args.selective_rules = re.split(r"[,\s;:]+", args.selective_rules)

    if getattr(args, "outlet_address", None) is not None and getattr(args, "secret", None) is None:
        parser.error("the following arguments are required: -s/--secret")

    async def async_main():
        server = proxy(**vars(args)) if parser.prog == "overmole-proxy" else outlet(**vars(args))
        await server

    asyncio.run(async_main())


if __name__ == "__main__":
    if (
        len(sys.argv) < 2
        or sys.argv[1] not in ["proxy", "outlet"]
        or sys.argv[1] in ["-h", "--help"]
    ):
        print(f"usage: {pathlib.Path(sys.argv[0]).name} proxy|outlet")
        print("\nStarts the selective tunneled proxy server.")
        print("\npositional arguments:")
        print("  LAUNCH_MODE\tProgram can be run in two modes, select one of `proxy` or `outlet`.")
        print("\noptions:")
        print("  -h, --help\tshow this help message and exi")
        sys.exit(1)
    else:
        main([f"overmole-{sys.argv[1]}", *sys.argv[2:]])
