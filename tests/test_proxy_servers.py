from ipaddress import IPv4Address

import httpx
import pytest
import contextlib
import typing as t

import overtun
from overtun import Address
from tests.utils import (
    requirements_note,
    TEST_TRANSPARENT_REQUIREMENTS,
    make_protocol_factory,
)


@pytest.fixture
async def simple_proxy(proxy_address):
    @contextlib.asynccontextmanager
    async def simple_proxy_context():
        proxy_server = await overtun.create_server(proxy_address)
        async with proxy_server:
            await proxy_server.start_serving()
            yield proxy_address

    return simple_proxy_context


@pytest.fixture
async def tunneled_proxy(proxy_address, outlet_address):
    """
    Создается пара прокси серверов "вход/выход в туннель".
    Может быть передан параметр с козиной сбора информации.
    """

    @contextlib.asynccontextmanager
    async def tunnel_proxy_context(bag: list[t.Any] | None = None):

        outlet_server = await overtun.create_server(outlet_address, make_protocol_factory(bag=bag))
        proxy_server = await overtun.create_server(
            proxy_address, make_protocol_factory(outlet_address, bag=bag)
        )

        await outlet_server.start_serving()
        await proxy_server.start_serving()
        yield proxy_address

    return tunnel_proxy_context


@pytest.fixture
async def selective_proxy(proxy_address, outlet_address):
    """
    Создается пара прокси серверов "вход/выход в туннель", причем вход селективный.
    Может быть передан параметр с козиной сбора информации.
    """


async def test_simple_server(simple_proxy, debug_on):

    async with simple_proxy() as address:
        # HTTP Native
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("http://mail.ru")
            assert resp.status_code == 405  # HTTP Native прокси не реализован

        # HTTP CONNECT PROXY
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("https://mail.ru")
            assert resp.status_code == 302

        # Transparent HTTPS Proxy
        with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_REQUIREMENTS):
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://mail.ru:8443")
                assert resp.status_code == 302


async def test_tunneled_server(tunneled_proxy, debug_on):
    bag = list()
    async with tunneled_proxy(bag) as address:
        # HTTP CONNECT PROXY
        async with httpx.AsyncClient(proxy="http://{}:{}".format(*address)) as client:
            resp = await client.get("https://mail.ru")
            assert resp.status_code == 302

        # Transparent HTTPS Proxy
        with requirements_note(httpx.ConnectTimeout, TEST_TRANSPARENT_REQUIREMENTS):
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://vk.ru:8443")
                assert resp.status_code == 302

    assert bag == [
        (Address(IPv4Address("127.0.0.1"), 10443), Address("mail.ru", 443)),
        (Address(IPv4Address("127.0.0.1"), 20443), Address("mail.ru", 443)),
        (Address(IPv4Address("127.0.0.1"), 10443), Address("vk.ru", 443)),
        (Address(IPv4Address("127.0.0.1"), 20443), Address("vk.ru", 443)),
    ]
