import h11


def parse_target(request: h11.Request) -> tuple[str, int, str]:
    """
    Разбор HTTP target/path.

    Args:
        Строка которую следует разобрать

    Returns:
        Кортеж содержащий при элемента: хост, порт, путь (URI)
    """
    host = port = None
    target = request.target.decode("ascii")
    if "://" in target:
        target = target.split("://", 1)[1]
        host, path = target.split("/", 1)
    else:
        path = target
        if found := [v.decode() for k, v in request.headers.raw_items() if k.lower() == b"host"]:
            host = found[0]
        else:
            ValueError("Cannot determine host")
    if ":" in host:
        host, port = host.split(":", 1)
    path = "/" + path if not path.startswith("/") else path
    if port is None:
        port = 433 if request.method == "CONNECT" else 80
    return host, port, path
