from asyncio import Transport
from collections.abc import Mapping
from logging import Logger

from overtun.primitives import Address, TargetRule
from overtun.protocols.general import IncomingProtocol, OutgoingProtocol


class EgressProtocol(IncomingProtocol):
    """
    Incoming connection protocol to the egress server (tunnel exit point).

    Handles connections arriving at the egress server from the proxy server.
    Extracts the original TLS ClientHello from the tunnel preamble and
    establishes the actual outbound connection to the target host.

    Args:
        secret_key: Secret key for tunnel negotiation.
        allow_http_connect: If True, allows HTTP CONNECT requests in addition to TLS.
        logger: Logger instance.
    """

    def __init__(
        self, secret_key: bytes, *, allow_http_connect: bool = False, logger: Logger | None = None
    ) -> None:
        super().__init__(logger=logger)
        self._allow_http_connect = allow_http_connect
        self._secret_key = secret_key

    def http_connect_handler(self, preamble: bytes) -> None:
        """Handle an HTTP CONNECT request."""
        if self._allow_http_connect:
            super().http_connect_handler(preamble)
        else:
            self.transport.write(b"HTTP/1.0 405 Method Not Allowed\r\n\r\n")
            self.transport.close()

    def tls_session_started(self, preamble: bytes) -> None:
        """TLS session started."""
        if preamble := self._unseal_tunnel_session(preamble):
            super().tls_session_started(preamble)

    def _unseal_tunnel_session(self, preamble: bytes) -> bytes | None:
        """Unseals the TLS preamble and retrieves the tunnel negotiation and construction parameters."""
        return preamble


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

    When `egress_address` is set, `secret_key` must also be provided.

    Args:
        rule_register: Optional mapping of target addresses to (rule, extra_data) pairs.
                       Addresses not found in the register are routed DIRECT.
        egress_address: Optional egress server address for tunneling.
        secret_key: Secret key for tunnel negotiation. Required if egress_address is set.
        logger: Logger instance.
    """

    def __init__(
        self,
        *,
        rule_register: Mapping[Address, tuple[TargetRule, E]] | None = None,
        egress_address: Address | None = None,
        secret_key: bytes | None = None,
        logger: Logger | None = None,
    ) -> None:
        super().__init__(logger=logger)
        self._rule_register = rule_register
        self._egress_address = egress_address
        if egress_address is not None and secret_key is None:
            raise ValueError("`secret_key` must be provided if egress_address is set")
        self._secret_key = secret_key
        self._default_rule = TargetRule.TUNNEL if self._egress_address is not None else TargetRule.DIRECT
        self._default_rule = TargetRule.DIRECT if self._rule_register is not None else self._default_rule
        self._extra_rule = None

    async def create_outgoing_connection(self, address: Address) -> Transport:
        """An asynchronous task that establishes and returns an outgoing connection,
        taking into account request forwarding rules."""
        if self._rule_register and address in self._rule_register:
            self._default_rule, self._extra_rule = self._rule_register[address]

        if self._default_rule == TargetRule.TUNNEL:
            address = self._egress_address
        elif self._default_rule == TargetRule.DROP:
            raise ConnectionResetError("Connection reset by rule")

        return await super().create_outgoing_connection(address)

    def _send_preamble(self, preamble: bytes):
        if self._default_rule == TargetRule.TUNNEL:
            preamble = self._seal_traffic_tunnel(preamble)
        self.outgoing.write(preamble)

    def _seal_traffic_tunnel(self, preamble: bytes) -> bytes | None:
        """Seals the tunnel negotiation and construction parameters in the TLS preamble."""
        return preamble