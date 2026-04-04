import logging
import typing as t
from asyncio import Transport
from contextlib import contextmanager

import overtun
from overtun import Address

TEST_TRANSPARENT_REQUIREMENTS = """
For this test/example, you need to enable the forwarding of outgoing traffic from 8443 to 10443, 
ex: `sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to-destination 127.0.0.1:10443`
Make sure that this is done.
"""


@contextmanager
def requirements_note(exc_type, message):
    try:
        yield
    except Exception as exc:
        if isinstance(exc, exc_type):
            logging.error(message)
        raise exc


def make_protocol_factory(*args, bag: list[t.Any] | None = None, **kwargs):
    if bag is None:
        return overtun.make_protocol_factory(*args, **kwargs)

    _protocol_factory = overtun.make_protocol_factory(*args, **kwargs)

    def wrapped_outcoming_factory(original_outcoming_factory):
        async def outcoming_factory(incoming: Transport, target: Address):
            outcoming = await original_outcoming_factory(incoming, target)
            if bag is not None and outcoming is not None:
                local = Address.parse(*incoming.get_extra_info("sockname")[:2])
                bag.append((local, target))
            return outcoming

        return outcoming_factory

    def protocol_factory():
        protocol = _protocol_factory()
        protocol._ProxyProtocol__outcoming_factory = wrapped_outcoming_factory(
            protocol._ProxyProtocol__outcoming_factory
        )
        return protocol

    return protocol_factory
