import asyncio
import typing as t
from asyncio import Server, Transport

from .socks5 import Socks5Protocol
from .httproxy import ProxyProtocol, logger


class ServerOpts(t.TypedDict):
    socks5_port: int
    proxy_port: int
    socks5_host: t.NotRequired[str]
    proxy_host: t.NotRequired[str]
    timeout: t.NotRequired[float]


async def create_server(**opts: t.Unpack[ServerOpts]) -> Server:
    """Create and return an instance of the SOCKS5HTTP proxy server."""
    loop = asyncio.get_running_loop()
    socks5_host = opts.get("socks5_host", "127.0.0.1")
    socks5_port = opts["socks5_port"]
    proxy_host = opts.get("proxy_host", "127.0.0.1")
    proxy_port = opts["proxy_port"]

    async def socks5_connect(proxy_transport: Transport, target_host: str, target_port: int) -> Transport:
        transport, protocol = await loop.create_connection(
            lambda: Socks5Protocol(proxy_transport, target_host, target_port),
            socks5_host,
            socks5_port,
        )
        async with asyncio.timeout(opts.get("timeout", 5.0)):
            await protocol.handshaking
            await protocol.connecting
            return transport

    server = await loop.create_server(
        lambda: ProxyProtocol(socks5_connect),
        proxy_host,
        proxy_port,
    )

    logger.info(
        f"Established HTTP Proxy server on {proxy_host}:{proxy_port} "
        f"bind with SOCKS5 server on {socks5_host}:{socks5_port}"
    )
    return server
