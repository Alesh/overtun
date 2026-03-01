import asyncio
from collections.abc import Callable, Awaitable


async def _get_result[T, **P](
    cc: Callable[..., Awaitable[T | None] | T | None] | None, *args: P.args, **kwargs: P.kwargs
) -> T | None:
    if cc is not None:
        rv = cc(*args, **kwargs)
        if asyncio.iscoroutine(rv):
            rv = await rv
            return rv
        return rv
    return None
