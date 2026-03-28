import asyncio

import httpx

from overtun.intyperr import Address
from overtun.protocols import ProxyProtocol, Protocol, OutcomingProtocol, ProxyMode


async def test_proxy_protocol():
    loop = asyncio.get_event_loop()
    proxy_address = ("127.0.0.1", 10443)

    async def outcoming_factory(incoming: Protocol, target: Address, _: ProxyMode) -> OutcomingProtocol:
        _, protocol = await loop.create_connection(lambda: OutcomingProtocol(incoming, incoming.logger), *target)
        return protocol

    proxy_server = await loop.create_server(
        lambda: ProxyProtocol(outcoming_factory),
        *proxy_address,
    )

    async with proxy_server:
        await proxy_server.start_serving()

        # # HTTP CONNECT Proxy
        # async with httpx.AsyncClient(proxy="http://{}:{}".format(*proxy_address)) as client:
        #     resp = await client.get("https://mail.ru")
        #     assert resp.status_code == 302

        # Transparent HTTPS Proxy
        # Для этого теста/примера надо включить перенаправление исходящего трафика с 8443 на 10443
        # sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to-destination 127.0.0.1:10443
        async with httpx.AsyncClient() as client:
            resp = await client.get("https://mail.ru:8443")
            assert resp.status_code == 302

