"""Probe 3: Network access."""

import socket
import concurrent.futures

from . import SEPARATOR

DNS_TIMEOUT = 5  # seconds


def _resolve(host, port=443):
    """DNS resolve with a timeout (getaddrinfo has no timeout param)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(socket.getaddrinfo, host, port)
        result = future.result(timeout=DNS_TIMEOUT)
        return result[0][4][0]


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 3: Network access")
    print(SEPARATOR)

    # DNS resolution
    for host in ["pypi.org", "gitlab.com"]:
        try:
            addr = _resolve(host)
            print(f"  PASS (VULNERABLE): DNS resolved {host} -> {addr}")
        except concurrent.futures.TimeoutError:
            print(f"  BLOCKED: {host} DNS timed out ({DNS_TIMEOUT}s)")
        except (socket.gaierror, OSError) as e:
            print(f"  BLOCKED: {host} DNS failed -> {e}")

    # TCP connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        print("  PASS (VULNERABLE): TCP connection to 8.8.8.8:53 succeeded")
    except (ConnectionRefusedError, OSError) as e:
        print(f"  BLOCKED: TCP connection failed -> {e}")
