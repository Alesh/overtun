from asyncio import Transport
from collections.abc import Mapping
from logging import Logger

from overtun.primitives import Address, TargetRule, Tunnel
from overtun.protocols.general import IncomingProtocol


class EgressProtocol(IncomingProtocol):
    """
    Incoming connection protocol to the egress server (tunnel exit point).

    Handles connections arriving at the egress server from the proxy server.
    Extracts the original TLS ClientHello from the tunnel preamble and
    establishes the actual outbound connection to the target host.

    Args:
        tunnel: Instance of Tunnel interface.
        logger: Logger instance.
    """

    def __init__(self, tunnel: Tunnel, *, logger: Logger | None = None) -> None:
        super().__init__(logger=logger)
        self._tunnel = tunnel

    def http_connect_handler(self, preamble: bytes) -> None:
        """Handle an HTTP CONNECT request."""
        self.transport.write(b"HTTP/1.0 405 Method Not Allowed\r\n\r\n")
        self.transport.close()

    def tls_session_started(self, preamble: bytes) -> None:
        """TLS session started."""
        if preamble := self._tunnel.unseal_traffic_preamble(preamble):
            self._buffer = preamble
            super().tls_session_started(preamble)


class ProxyProtocol[E](IncomingProtocol):
    """
    Incoming connection protocol to the proxy server.

    Controls traffic routing based on the following rules (evaluated in order):
    1. If `rule_register` is provided and contains the target address,
       the corresponding rule and extra data from the register are used.
    2. If `rule_register` is provided but the target address is not found,
       traffic is routed DIRECT (no tunneling).
    3. If `rule_register` is not provided but `egress_address` is set,
       all traffic is tunneled to the egress server (TUNNEL).
    4. Otherwise, traffic goes DIRECT.

    Args:
        rule_register: Optional mapping of target addresses to (rule, extra_data) pairs.
        tunnel: Optional instance of Tunnel interface for tunneling.
        logger: Logger instance.
    """

    def __init__(
        self,
        *,
        rule_register: Mapping[Address, tuple[TargetRule, E]] | None = None,
        tunnel: Tunnel | None = None,
        logger: Logger | None = None,
    ) -> None:
        super().__init__(logger=logger)
        self._rule_register = rule_register
        self._tunnel = tunnel
        self._default_rule = TargetRule.TUNNEL if tunnel is not None else TargetRule.DIRECT
        self._default_rule = TargetRule.DIRECT if rule_register is not None else self._default_rule
        self._extra_rule = None

    async def create_outgoing_connection(self, address: Address) -> Transport:
        """An asynchronous task that establishes and returns an outgoing connection,
        taking into account request forwarding rules."""
        if self._rule_register and address in self._rule_register:
            self._default_rule, self._extra_rule = self._rule_register[address]

        if self._default_rule == TargetRule.TUNNEL:
            address = self._tunnel.egress_address
        elif self._default_rule == TargetRule.DROP:
            raise ConnectionResetError("Connection reset by rule")

        return await super().create_outgoing_connection(address)

    def _send_preamble(self, preamble: bytes):
        if self._default_rule == TargetRule.TUNNEL:
            preamble = self._tunnel.seal_traffic_preamble(preamble, self._extra_rule)
        self.outgoing.write(preamble)
