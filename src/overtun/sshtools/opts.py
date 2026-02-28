import typing as t

DEFAULT_SSH_PARAMS = {
    "timeout": 30,
    "banner_timeout": 10,
    "auth_timeout": 20,
    "look_for_keys": False,
    "allow_agent": False,
}
DEFAULT_SSH_OPTIONS = {
    "allow_change_host_identification": False,
    "allow_create_host_identification": True,
}


class SshOpts(t.TypedDict, total=False):
    """SSH client connection options and parameters"""

    # SSH client params
    timeout: float
    banner_timeout: float
    auth_timeout: float
    look_for_keys: bool
    allow_agent: bool

    # other options
    allow_change_host_identification: bool
    allow_create_host_identification: bool


def make_ssh_opts(**opts: t.Unpack[SshOpts]) -> SshOpts:
    """SSH client parameters builder."""
    defaults = dict(DEFAULT_SSH_PARAMS, **DEFAULT_SSH_OPTIONS)
    return SshOpts(**dict(defaults, **opts))


def extract_ssh_params(opts: SshOpts) -> dict[str, t.Any]:
    """SSH client parameters extractor."""
    return dict(
        (k, v)
        for k, v in opts.items()
        if k in ["timeout", "banner_timeout", "auth_timeout", "look_for_keys", "allow_agent"]
    )
