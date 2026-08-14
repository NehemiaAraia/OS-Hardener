from .base import CommandOutput, Connection
from .fixture import FixtureConnection

__all__ = ["Connection", "CommandOutput", "FixtureConnection", "make_connection"]


def make_connection(backend, **kwargs):
    """Build a connection backend. winrm/ssh are imported lazily so the
    fixture path has no hard dependency on pywinrm/paramiko."""
    if backend == "fixture":
        return FixtureConnection(**kwargs)
    if backend == "winrm":
        from .winrm_conn import WinRMConnection
        return WinRMConnection(**kwargs)
    if backend == "ssh":
        from .ssh_conn import SSHConnection
        return SSHConnection(**kwargs)
    raise ValueError(f"unknown connection backend: {backend}")
