import logging
import os
from contextlib import contextmanager

TEST_TRANSPARENT_CONDITIONS = """
For this test/example, you need to enable the forwarding of outgoing traffic from 8443 to 10443, 
ex: `sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to-destination 127.0.0.1:10443`
Make sure that this is done or set environ variable `TEST_TRANSPARENT_CONDITIONS=0`.
"""

if os.environ.get("TEST_TRANSPARENT_CONDITIONS", "1").upper() in ("0", "FALSE", "NO"):
    TEST_TRANSPARENT_CONDITIONS = False


@contextmanager
def requirements_note(exc_type, conditions):
    try:
        yield
    except Exception as exc:
        if conditions:
            if isinstance(exc, exc_type):
                logging.exception(conditions)
            raise exc
