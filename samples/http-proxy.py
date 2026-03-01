import asyncio
import logging
import sys

from overtun import socks5http
from overtun.socks5http import logger


def main():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s"))
    logger.addHandler(handler)

    async def async_main():
        server = await socks5http.create_server(socks5_port=5000, proxy_port=8000)
        async with server:
            await server.serve_forever()

    asyncio.run(async_main())


if __name__ == "__main__":
    main()
