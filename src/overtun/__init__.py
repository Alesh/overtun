import asyncio
import typing as t
from collections.abc import Callable

from .primitives import Address, TargetTraffic, TrafficRule
from .intyperr import OutcomingTransport, TargetRegistry
from .protocols import ProxyProtocol

__all__ = ("Address", "ProxyProtocol")


async def create_server(
    address: Address,
    protocol_factory: Callable[[], ProxyProtocol] | None = None,
    /,
    **kwargs: t.Any,
) -> asyncio.Server:
    """
    Короутина создает протокол-настраиваемый прокси-сервер с интерфейсом `asyncio.Server`.

    Args:
         address: Сетевой адрес к которому привязывается прокси сервер.
         protocol_factory: Фабрика создающая экземпляр `overtun.protocols.ProxyProtocol`.
         kwargs: Остальные именованные параметры, соответствуют параметрам `loop.create_server`.

    See Also:
         Это всего лишь обертка, для более полной информации смотрите описание `loop.create_server`.
    """
    loop = asyncio.get_event_loop()
    protocol_factory = protocol_factory or (lambda: ProxyProtocol())
    return await loop.create_server(protocol_factory, str(address.host), address.port, **kwargs)


## Хелперы для создания специфических прокси серверов


def make_protocol_factory(
    outlet_address: Address | None = None,
    traffic_selector: TargetRegistry[TargetTraffic] | None = None,
) -> Callable[[], ProxyProtocol]:
    """
    Функция возвращает параметр-настроенную фабрику прокси `overtun.ProxyProtocol`.

    Args:
        outlet_address: Адрес выхода туннеля, если задан включает на сервере возможность туннелирования трафика.
        traffic_selector: Регистер правил обработки трафика целевых адресов, если задан включает селектирование трафика.

    Returns:
        Фабрику создающую настроенный по заданным параметрам экземпляр `overtun.ProxyProtocol`.
    """

    class Protocol(ProxyProtocol):
        """
        Адаптивный под параметры запуска сервера прокси-протокол.
        """

        def __init__(self):
            # Интерфейс `overtune.intyperr.OutcomingFactory`
            async def outcoming_factory(_, target_address: Address) -> OutcomingTransport | None:

                def traffic_selector_(address: Address) -> TargetTraffic:
                    if traffic_selector is not None:
                        return traffic_selector(address)
                    else:
                        return TargetTraffic(rule=TrafficRule.TUNNEL)

                traffic = traffic_selector_(target_address)
                if traffic.rule != TrafficRule.DROP:
                    if outlet_address is not None and traffic.rule == TrafficRule.TUNNEL:
                        target_address = outlet_address
                    return await self._outcoming_factory(target_address)
                return None

            super().__init__(outcoming_factory=outcoming_factory)

    return lambda: Protocol()


async def create_outlet_server(
    address: Address,
    **kwargs: t.Any,
) -> asyncio.Server:
    """
    Короутина создает аутлет ("выход из туннеля") прокси-сервер с интерфейсом `asyncio.Server`.

    Args:
         address: Сетевой адрес к которому привязывается прокси сервер.
         kwargs: Остальные именованные параметры, соответствуют параметрам `loop.create_server`.

    See Also:
         Для доп. информации смотрите описание `overtun.create_server`.
    """
    return await create_server(address, make_protocol_factory(), **kwargs)


async def create_proxy_server(
    address: Address,
    outlet_address: Address | None = None,
    target_selector: TargetRegistry[TargetTraffic] | None = None,
    **kwargs: t.Any,
) -> asyncio.Server:
    """
    Короутина создает параметр-настраиваемый прокси-сервер с интерфейсом `asyncio.Server`.

    Args:
         address: Сетевой адрес к которому привязывается прокси сервер.
         outlet_address: Адрес "выхода туннеля", если задан включает на сервере возможность туннелирования трафика.
         target_selector: Регистр правил селектирования целевых адресов, если задан включает селектирование трафика.
         kwargs: Остальные именованные параметры, соответствуют параметрам `loop.create_server`.

    See Also:
         Для доп. информации смотрите описание `overtun.create_server`.
    """
    return await create_server(address, make_protocol_factory(outlet_address, target_selector), **kwargs)
