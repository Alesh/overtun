import typing as t
from collections.abc import Sequence

from overtun.intyperr import Address


@t.runtime_checkable
class AddressInfo(t.Protocol):
    """
    Интерфейс объекта содержащего информацию о целевом адресе
    """

    target: Address


class AddressInfoRegister[T: AddressInfo]:
    """
    Регистр информации о сетевых адресах.
    """

    def __init__(self, addresses_info: Sequence[T], override: bool = False):
        self._map = dict()
        for address_info in addresses_info:
            if keys := self._make_keys(address_info.target):
                self._insert(self._map, keys, address_info, override)
            else:
                raise ValueError(f"Wrong address info: {address_info}")

    def __call__(self, address: Address) -> T | None:
        """
        Возвращает некую информацию о хосте, или `None` если не найдено.
        Возможны wildcard domain для поля `address.host`, ex: *.example.com; и IP wildcard, ex: 10.1.1.*,
        тогда информация относится ко всем хостам отвечающим шаблону. А значения поля `address.port` == 0
        указывает, что информация относится к адресу с любому номером порта.

        Args:
            address: Сетевой адрес для которого запрашивается информация.
        """
        if keys := self._make_keys(address):
            return self._lookup(self._map, keys)
        return None

    def _make_keys(self, address: Address) -> tuple[t.Any, ...] | None:
        host, port = address
        # Попытка интерпретировать как IP (4 октета, последний может быть *)
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() or p == "*" for p in parts):
            if parts.count("*") <= 1 and (parts[-1] == "*" or "*" not in parts):
                return tuple([*parts, port])
        # Иначе как домен (минимум 2 части, звёздочка только в начале)
        if len(parts) >= 2 and all(p for p in parts):
            if (parts[0] == "*" and parts.count("*") == 1) or "*" not in parts:
                return tuple([*reversed(parts), port])
        return None

    @classmethod
    def _lookup(cls, node: dict, keys: tuple[t.Any, ...]) -> T | None:
        if len(keys) <= 2:
            key, port = keys if len(keys) == 2 else (None, keys[0])
            if key:
                if key in node:
                    node = node[key]
                elif "*" in node:
                    node = node["*"]
            if port in node:
                return node[port]
            elif 0 in node:
                return node[0]
        else:
            key, *keys = keys
            if key in node:
                return cls._lookup(node[key], keys)
        return None

    @classmethod
    def _insert(cls, node: dict, keys: tuple[t.Any, ...], value: T, override: bool = False) -> None:
        key, *keys = keys
        if key in node and not isinstance(node[key], dict) and not override:
            raise ValueError(f"Conflict at key '{key}': value already exists and override=False")
        if keys:
            if key not in node:
                node[key] = dict()
            cls._insert(node[key], keys, value, override)
        else:
            node[key] = value
