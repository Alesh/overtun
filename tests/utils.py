import logging
from contextlib import contextmanager

TEST_TRANSPARENT_REQUIREMENTS = """
For this test/example, you need to enable the forwarding of outgoing traffic from 8443 to 10443, 
ex: `sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to-destination 127.0.0.1:10443`
Make sure that this is done.
"""


@contextmanager
def requirements_note(exc_type, message):
    try:
        yield
    except Exception as exc:
        if isinstance(exc, exc_type):
            logging.error(message)
        raise exc
