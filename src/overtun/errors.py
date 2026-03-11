from http import HTTPStatus


class HTTPError(Exception):
    """Ошибка HTTP протокола."""

    args: tuple[HTTPStatus, Exception]

    def __init__(self, status: HTTPStatus, exc_or_message: Exception | str | None = None):
        super().__init__(status, exc_or_message)
        if isinstance(exc_or_message, Exception):
            self.__cause__ = exc_or_message
