import re
import typing as t
from ipaddress import AddressValueError, IPv4Address, IPv6Address

DOMAIN_RE = re.compile(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")


class Error(Exception):
    """Base package error."""


class Address(t.NamedTuple):
    """A network address."""

    host: str | IPv4Address | IPv6Address
    port: int

    def __str__(self) -> str:
        return (
            f"[{self.host}]:{self.port}" if isinstance(self.host, IPv6Address) else f"{self.host}:{self.port}"
        )

    @classmethod
    def parse(cls, s: str, port: int | None = None) -> t.Self:
        """Parse an address from its string representation."""

        def normalize(host: str | IPv4Address | IPv6Address, port: int | str | None) -> Address:
            if port is None:
                msg = "Required port value"
                raise ValueError(msg)
            try:
                port = int(port)
            except ValueError as exc:
                msg = "Wrong port value"
                raise ValueError(msg) from exc
            return Address(host, port)

        host = s
        try:
            if pos := s.rfind("]") + 1:  # IP6
                if pos < len(s) and s[pos] == ":":
                    host, port = s[:pos], s[pos + 1 :]
                return normalize(IPv6Address(host[1:-1]), port)
            if (parts := s.rsplit(":")) and len(parts) == 2:
                host, port = parts
            if re.match(DOMAIN_RE, host):
                return normalize(host, port)
            if ":" in host:
                return normalize(IPv6Address(host), port)
            return normalize(IPv4Address(host), port)
        except (AttributeError, TypeError, AddressValueError) as exc:
            msg = "Wrong host value"
            raise ValueError(msg) from exc
