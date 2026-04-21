"""Probe 7: User identity."""

import os

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 7: User identity")
    print(SEPARATOR)

    uid = os.getuid()
    gid = os.getgid()
    user = os.environ.get("USER", "unknown")
    print(f"  UID={uid} GID={gid} USER={user}")
    print(f"  HOME={os.environ.get('HOME', 'unset')}")
