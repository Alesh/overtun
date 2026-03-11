def parse_target(target: str | bytes) -> tuple[str, int, str]:
    """Разбирает строку, содержащую URL целевого ресурса."""
    port = 80
    target = target.decode("ascii") if isinstance(target, bytes) else target
    if "://" in target:
        _, target = target.split("://", 1)
    host, *path = target.split("/")
    path = "/" + "/".join(path)
    if host:
        if "]:" in host:
            host, port = host[1:].split("]:", 1)
        elif ":" in host:
            host, port = host.split(":", 1)
        return host, int(port), path
    raise ValueError("Invalid target")
