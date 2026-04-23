import struct
from collections.abc import Callable

from tlsex import TLSExtension
from tlsex.extensions import UnknownExtension


def intrude_payload(
    extension: TLSExtension, payload: bytes, encoder: Callable[[bytes], bytes] | None = None
) -> TLSExtension:
    """
    Внедряет и запечатывает полезную нагрузку в расширение у которых тело может быть переменной длины.
    `payload` маскируется и запечатывается (подписывается) значением `secret_key`.

    Args:
        extension: TLS расширение, которое будет носителем `payload`.
        payload: Байтовая строка содержащая "полезную нагрузку".
        encoder: Функция кодирующая "полезную нагрузку" перед включением ее в расширение.

    Returns:
         TLS расширение, в которое внедрена "полезная нагрузка".

    Raises:
        TypeError: Поднимается если типы параметров не верны.
        ValueError: Поднимается если значения параметров не корректны.
    """
    if not isinstance(extension, TLSExtension):
        raise TypeError(f"`extension` must be TLSExtension")
    if not (isinstance(payload, bytes) and len(payload) >= 2):
        raise TypeError(f"`payload` must be bytes, and cannot be to short")
    encoder = encoder or (lambda b: b)

    original_body = bytes(extension)[2:]  # размер + само оригинальное тело
    extended_body = original_body + encoder(payload)
    if len(extended_body) > 0xFFFF:
        raise ValueError("extended extension body too large")
    return TLSExtension.load(
        memoryview(extension.type + struct.pack("!H", len(extended_body)) + extended_body)
    )


def extrude_payload(
    extension: TLSExtension, decoder: Callable[[bytes], bytes] | None = None
) -> tuple[bytes, UnknownExtension]:
    """
    Проверяет и извлекает полезную нагрузку из расширения приводя его при этом к первоначальному
    виду. Из `extension` извлекается часть содержащая маскированный `payload`. Эта часть
    демаскируется и проверяется с помощью `secret_key`. Если все соответствует, возвращается пара
    демаскированный `payload` и восстановленный исходное расширение.


    Args:
        extension: TLS расширение, которое будет носителем `payload`.
        decoder: Функция декодирующая "полезную нагрузку" после извлечения ее из расширения.

    Returns:
         Байтовая строка содержащая "полезную нагрузку".
         TLS расширение соответствующая исходному, до того как в него была внедрена полезная нагрузка.

    Raises:
        TypeError: Поднимается если типы параметров не верны.
        ValueError: Поднимается если значения параметров не корректны.
    """
    extended_body = bytes(extension)[4:]
    if len(extended_body) < 2:
        raise ValueError("extension body too short")
    if not isinstance(extension, TLSExtension):
        raise TypeError(f"`extension` must be TLSExtension")
    (original_size,) = struct.unpack("!H", extended_body[0:2])
    original_body = extended_body[2 : 2 + original_size]
    packed_payload = extended_body[2 + original_size :]
    payload = decoder(packed_payload)
    return payload, TLSExtension.load(
        memoryview(extension.type + extended_body[0:2] + original_body)
    )
