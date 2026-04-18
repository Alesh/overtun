import asyncio
import logging

from overtun.primitives import Address

default_logger = logging.getLogger(".".join(__name__.split(".")[:-1]))


def get_peer_address(transport: asyncio.Transport) -> Address | None:
    if value := transport.get_extra_info("peername"):
        return Address.parse(*value[:2])
    return None
