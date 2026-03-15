class Error(Exception):
    """
    Базовый класс исключений этого модуля.
    """


class ProtocolError(Error):
    """
    Класс исключений возникших в компонентах протокола.
    """


class DataError(ProtocolError):
    """
    Класс исключений некорректности данных.
    """

    def __init__(self, message: str, sample: bytes | None = None):
        super().__init__(f"{message}{f': {" ".join([f"{b:02X}" for b in sample[:16]])}' if sample else '.'}")
