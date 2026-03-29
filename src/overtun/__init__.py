import asyncio
import typing as t

from .intyperr import Address
from .protocols import ProxyProtocol


async def create_server(
    address: Address,
    protocol_factory: t.Callable[[], ProxyProtocol] | None = None,
    **kwargs: t.Any,
) -> asyncio.Server:
    """
    Короутина создающая прокси-сервер с интерфейсом `asyncio.Server`

    Args:
         address: Сетевой адрес к которому привязывается прокси сервер.
         protocol_factory: Фабрика создающая нестандартный экземпляр `overtun.protocols.ProxyProtocol`
         kwargs: Остальные именованные параметры, соответствуют параметрам `loop.create_server`.

    See Also:
         Это всего лишь обертка, для более полной информации смотрите описание `loop.create_server`.
    """
    loop = asyncio.get_event_loop()
    protocol_factory = protocol_factory or (lambda: ProxyProtocol())
    return await loop.create_server(protocol_factory, str(address.host), address.port, **kwargs)
