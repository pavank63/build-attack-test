"""Probe 3: Network access."""

import socket

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 3: Network access")
    print(SEPARATOR)

    # DNS resolution
    try:
        addr = socket.getaddrinfo("pypi.org", 443)[0][4][0]
        print(f"  PASS (VULNERABLE): DNS resolved pypi.org -> {addr}")
    except (socket.gaierror, OSError) as e:
        print(f"  BLOCKED: DNS resolution failed -> {e}")

    # TCP connection (short timeout to avoid hanging)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        print("  PASS (VULNERABLE): TCP connection to 8.8.8.8:53 succeeded")
    except (ConnectionRefusedError, OSError) as e:
        print(f"  BLOCKED: TCP connection failed -> {e}")

    # GitLab DNS
    try:
        addr = socket.getaddrinfo("gitlab.com", 443)[0][4][0]
        print(f"  PASS (VULNERABLE): DNS resolved gitlab.com -> {addr}")
    except (socket.gaierror, OSError) as e:
        print(f"  BLOCKED: gitlab.com DNS failed -> {e}")
