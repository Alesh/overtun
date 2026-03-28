import typing as t
from collections.abc import Buffer


class Address(t.NamedTuple):
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"

    @classmethod
    def from_(cls, *values: t.Any) -> t.Self:
        try:
            if len(values) == 1 and isinstance(values[0], str):
                host, port = values[0].split(":")
                return cls(str(host), int(port))
            elif len(values) == 2:
                return cls(str(values[0]), int(values[1]))
            else:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError(f"Invalid address: {values}")


class Error(Exception):
    """
    Базовый класс исключений.
    """


class DataError(Error):
    """
    Класс исключений некорректности данных.
    """

    def __init__(self, message: str, sample: Buffer | None = None):
        super().__init__(f"{message}{f': {" ".join([f"{b:02X}" for b in sample[:16]])}' if sample else '.'}")
