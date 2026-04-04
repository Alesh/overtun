import re
import typing as t
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, AddressValueError

DOMAIN_RE = re.compile(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")


class Address(t.NamedTuple):
    """
    Сетевой адрес.
    """

    host: str | IPv4Address | IPv6Address
    port: int

    def __str__(self) -> str:
        return (
            f"[{self.host}]:{self.port}"
            if isinstance(self.host, IPv6Address)
            else f"{self.host}:{self.port}"
        )

    @classmethod
    def parse(cls, s: str, port: int = None) -> t.Self:
        """Парсит адрес из строкового представления"""
        try:
            if isinstance(s, str):
                if s.startswith("["):
                    parts = s[1:].split("]", 1)
                    if len(parts) == 2:
                        host, s = parts
                        host = IPv6Address(host)
                        if s.startswith(":"):
                            _, port = s.split(":", 1)
                            return cls(host=host, port=int(port))
                        elif s == "" and port is not None:
                            return cls(host=host, port=int(port))
                elif len(s.split(":")) > 2:
                    return cls(host=IPv6Address(s), port=int(port))
                else:
                    parts = s.split(":", 1)
                    if len(parts) == 2:
                        host, port = parts
                    else:
                        host = parts[0]
                    check = [a.isnumeric() for a in host.split(".")]
                    if len(check) == 4 and all(check):
                        host = IPv4Address(host)
                    elif match := re.match(DOMAIN_RE, s):
                        host = match[0]
                    return cls(host=host, port=int(port))
        except (ValueError, TypeError, AddressValueError) as exc:
            raise ValueError("Wrong value") from exc
        raise TypeError("Wrong type")


class TrafficRule(int, Enum):
    DROP = 0
    DIRECT = 1
    TUNNEL = 2


class TargetTraffic(t.NamedTuple):
    rule: TrafficRule
