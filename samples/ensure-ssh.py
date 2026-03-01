import logging
import os
import sys

from overtun.sshtools.utils import logger
from overtun.sshtools.utils import get_default_key
from overtun.sshtools.methods import ensure_connection


def main():
    user = os.environ["USER"]
    host = os.environ["HOST"]

    def get_priv_key(user_, host_):
        assert user_ == user
        assert host_ == host
        return get_default_key()

    def get_password(user_, host_):
        assert user_ == user
        assert host_ == host
        return os.environ["PASSWORD"]

    if result := ensure_connection(user, host, get_priv_key=get_priv_key, get_password=get_password):
        print(result)


if __name__ == "__main__":
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s"))
    logger.addHandler(handler)
    main()
