import httpx
import pytest

from overtun.intyperr import Address
from overtun.protocols import ProxyProtocol
from overtun.proxy import ProxyServer, TargetsRegister, TargetRule, ConnectionRule
from tests.utils import requirements_note, TEST_TRANSPARENT_REQUIREMENTS


@pytest.fixture
async def proxy_server(proxy_address):
    proxy_server = ProxyServer(proxy_address)
    async with proxy_server:
        yield proxy_server


@pytest.fixture
async def tunneled():
    accum = list()

    class _ProxyProtocol(ProxyProtocol):
        def outcoming_data(self, data: memoryview):
            accum.append((self.transport.get_extra_info("sockname"), self.target, len(data)))
            super().outcoming_data(data)

    class _ProxyServer(ProxyServer):
        ProxyProtocol = _ProxyProtocol

    yield _ProxyServer, accum


async def test_proxy_server_connect(proxy_address, proxy_server):
    # HTTP CONNECT Proxy
    async with httpx.AsyncClient(proxy="http://{}:{}".format(*proxy_address)) as client:
        resp = await client.get("https://mail.ru")
        assert resp.status_code == 302


async def test_proxy_server_transparent(proxy_address, proxy_server):
    # Transparent HTTPS Proxy
    with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_REQUIREMENTS):
        async with httpx.AsyncClient() as client:
            resp = await client.get("https://mail.ru:8443")
            assert resp.status_code == 302


async def test_proxy_tunneled_server(proxy_address, outlet_address, tunneled):
    ProxyClass, accum = tunneled

    outlet_server = ProxyClass(outlet_address)
    proxy_server = ProxyClass(
        proxy_address,
        outlet=outlet_address,
        register=TargetsRegister(
            [
                TargetRule(Address("mail.ru", 443), ConnectionRule.Direct),
                TargetRule(Address("ok.ru", 443), ConnectionRule.Reset),
            ]
        ),
        connection_rule=ConnectionRule.Tunnel,
    )

    # mail.ru напрямую, ok.ru не надо, остальное через тунель

    async with proxy_server:
        async with outlet_server:
            # HTTP CONNECT Proxy
            async with httpx.AsyncClient(proxy="http://{}:{}".format(*proxy_address)) as client:
                resp = await client.get("https://mail.ru")
                assert resp.status_code == 302

            with pytest.raises(httpx.RemoteProtocolError, match="Server disconnected without sending a response."):
                async with httpx.AsyncClient(proxy="http://{}:{}".format(*proxy_address)) as client:
                    resp = await client.get("https://ok.ru")
                    assert resp.status_code == 200

            # Transparent HTTPS Proxy
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://vk.ru:8443")
                assert resp.status_code == 302

    assert accum == [
        (("127.0.0.1", 10443), Address(host="mail.ru", port=443), 1529),
        (("127.0.0.1", 10443), Address(host="mail.ru", port=443), 93),
        (("127.0.0.1", 10443), Address(host="mail.ru", port=443), 164),
        (("127.0.0.1", 10443), Address(host="vk.ru", port=443), 1527),
        (("127.0.0.1", 20443), Address(host="vk.ru", port=443), 1527),
        (("127.0.0.1", 10443), Address(host="vk.ru", port=443), 80),
        (("127.0.0.1", 20443), Address(host="vk.ru", port=443), 80),
        (("127.0.0.1", 10443), Address(host="vk.ru", port=443), 160),
        (("127.0.0.1", 20443), Address(host="vk.ru", port=443), 160),
    ]
