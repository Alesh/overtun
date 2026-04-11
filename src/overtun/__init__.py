import asyncio
import typing as t
from collections.abc import Callable
from logging import Logger

from .handlers import HandlersModule
from .primitives import Address, TargetDesc, TrafficRule
from .protocols import OutletProtocol, ProxyProtocol

__all__ = ["OutletProtocol", "ProxyProtocol", "Address"]


async def create_outlet[A](
    address: Address,
    handlers: HandlersModule[A] | None = None,
    extra_args: A | None = None,
    logger: Logger = None,
    **kwargs: t.Any,
) -> asyncio.Server:
    """
    Короутина аутлет сервер с интерфейсом `asyncio.Server`.

    Args:
         address: Сетевой адрес к которому привязывается прокси сервер.
         handlers: Обработчики преамбулы.
         extra_args: Дополнительные данные для обработчика преамбулы.
         logger: Логгер
         **kwargs: Остальные именованные параметры, соответствуют параметрам `loop.create_server`.

    See Also:
         Дя более полной информации смотрите описание `loop.create_server`.
    """
    loop = asyncio.get_event_loop()
    return await loop.create_server(
        lambda: OutletProtocol(handlers, extra_args, logger),
        str(address.host),
        address.port,
        **kwargs,
    )


async def create_proxy[A, D](
    address: Address,
    outlet_address: Address | None = None,
    target_registry: Callable[[Address], TargetDesc[D] | None] | None = None,
    default_traffic_rule: TrafficRule = TrafficRule.DIRECT,
    handlers: HandlersModule[A] | None = None,
    extra_args: A | None = None,
    logger: Logger = None,
    **kwargs: t.Any,
) -> asyncio.Server:
    """
    Короутина создает прокси сервер с интерфейсом `asyncio.Server`.

    Args:
         address: Сетевой адрес к которому привязывается прокси сервер.
         outlet_address: Адрес аутлета, включает режим туннелирования.
         target_registry: Регистр дополнительной информации о целевых ресурсах.
         default_traffic_rule: Правило по умолчанию для перенаправления трафика.
         handlers: Обработчики преамбулы.
         extra_args: Дополнительные данные для обработчика преамбулы.
         logger: Логгер
         **kwargs: Остальные именованные параметры, соответствуют параметрам `loop.create_server`.

    See Also:
         Это всего лишь обертка, для более полной информации смотрите описание `loop.create_server`.
    """
    loop = asyncio.get_event_loop()
    return await loop.create_server(
        lambda: ProxyProtocol(
            outlet_address, target_registry, default_traffic_rule, handlers, extra_args, logger
        ),
        str(address.host),
        address.port,
        **kwargs,
    )
