"""Probe 6: UTS namespace (hostname)."""

import socket

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 6: UTS namespace (hostname)")
    print(SEPARATOR)

    hostname = socket.gethostname()
    print(f"  Hostname: {hostname}")
    if hostname == "localhost":
        print("  BLOCKED: Hostname is 'localhost' (UTS isolated)")
    else:
        print(f"  PASS (VULNERABLE): Real hostname visible: {hostname}")
