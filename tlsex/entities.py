import inspect
import struct
from collections.abc import Buffer, Sized


class _Entity(Buffer, Sized):
    def __init__(self, mv: memoryview) -> None:
        self._mv = mv.toreadonly()

    def __buffer__(self, flags: int, /) -> memoryview:
        if flags & inspect.BufferFlags.WRITABLE:
            msg = "This is readonly buffer"
            raise BufferError(msg)
        return self._mv

    def __len__(self) -> int:
        return len(self._mv)


class Extension(_Entity):
    """An unrecognized TLS extension."""

    def __str__(self) -> str:
        (number,) = struct.unpack("!H", self._mv[0:2])
        prefix = "GREASE" if (number & 0x0F0F) == 0x0A0A else "EXTENS"
        return f"{prefix}[{number:04X}]"


class Cipher(_Entity):
    """Cipher suite descriptor."""

    def __str__(self) -> str:
        (number,) = struct.unpack("!H", self._mv[0:2])
        prefix = "GREASE" if (number & 0x0F0F) == 0x0A0A else "CIPHER"
        return f"{prefix}[{number:04X}]"

    @property
    def number(self) -> int:
        """Numeric cipher suite identifier."""
        (number,) = struct.unpack("!H", self._mv[0:2])
        return number

    @classmethod
    def make_collections(cls, buffer: Buffer, /) -> tuple["Cipher", ...]:
        """Build a collections of Cipher descriptors from a buffer."""
        mv = memoryview(buffer).toreadonly()
        return tuple(cls(mv[n : n + 2]) for n in range(0, len(mv), 2))
