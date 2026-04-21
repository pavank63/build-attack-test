"""
Build-time security probe.

This setup.py runs during build_sdist / build_wheel and attempts
several attack vectors that build isolation should block.

Each probe prints PASS (attack succeeded = vulnerable) or
BLOCKED (attack failed = isolated).
"""

import os
import socket
import subprocess
import sys

SEPARATOR = "=" * 60

def probe_netrc():
    """Try to read .netrc credential files."""
    print(f"\n{SEPARATOR}")
    print("PROBE 1: Credential file access (.netrc)")
    print(SEPARATOR)

    paths = [
        os.path.expanduser("~/.netrc"),
        "/root/.netrc",
        "/opt/app-root/src/.netrc",
    ]

    for path in paths:
        try:
            with open(path) as f:
                content = f.read()
            # Don't print actual content, just confirm access
            print(f"  PASS (VULNERABLE): Read {path} ({len(content)} bytes)")
        except PermissionError:
            print(f"  BLOCKED: {path} -> Permission denied")
        except FileNotFoundError:
            print(f"  SKIPPED: {path} -> File not found")
        except Exception as e:
            print(f"  BLOCKED: {path} -> {e}")


def probe_env_vars():
    """Try to read sensitive environment variables."""
    print(f"\n{SEPARATOR}")
    print("PROBE 2: Sensitive environment variables")
    print(SEPARATOR)

    targets = [
        "NETRC",
        "NGC_API_KEY",
        "TWINE_PASSWORD",
        "CI_JOB_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "PYPI_TOKEN",
    ]

    for var in targets:
        val = os.environ.get(var)
        if val:
            # Mask value, just show it exists
            masked = val[:4] + "****" if len(val) > 4 else "****"
            print(f"  PASS (VULNERABLE): ${var} = {masked}")
        else:
            print(f"  BLOCKED/ABSENT: ${var} not set")


def probe_network():
    """Try to reach the network."""
    print(f"\n{SEPARATOR}")
    print("PROBE 3: Network access")
    print(SEPARATOR)

    # DNS resolution
    try:
        addr = socket.getaddrinfo("pypi.org", 443)[0][4][0]
        print(f"  PASS (VULNERABLE): DNS resolved pypi.org -> {addr}")
    except (socket.gaierror, OSError) as e:
        print(f"  BLOCKED: DNS resolution failed -> {e}")

    # TCP connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        print("  PASS (VULNERABLE): TCP connection to 8.8.8.8:53 succeeded")
    except (ConnectionRefusedError, OSError) as e:
        print(f"  BLOCKED: TCP connection failed -> {e}")


def probe_processes():
    """Try to see other processes."""
    print(f"\n{SEPARATOR}")
    print("PROBE 4: Process visibility (PID namespace)")
    print(SEPARATOR)

    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        # In a PID namespace, we should only see our own processes
        print(f"  Visible processes: {len(lines) - 1}")  # minus header
        if len(lines) > 5:
            print("  PASS (VULNERABLE): Can see many processes")
        else:
            print("  BLOCKED: Only own processes visible (PID isolated)")
        for line in lines[:10]:
            print(f"    {line}")
        if len(lines) > 10:
            print(f"    ... ({len(lines) - 10} more)")
    except FileNotFoundError:
        print("  SKIPPED: 'ps' not available")
    except Exception as e:
        print(f"  ERROR: {e}")


def probe_ipc():
    """Try to access shared IPC resources."""
    print(f"\n{SEPARATOR}")
    print("PROBE 5: IPC namespace isolation")
    print(SEPARATOR)

    try:
        result = subprocess.run(
            ["ipcs", "-a"], capture_output=True, text=True, timeout=5
        )
        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
        # In an isolated IPC namespace, there should be no shared segments
        has_segments = any(
            l.startswith("0x") or l[0:1].isdigit()
            for l in lines
        )
        if has_segments:
            print("  PASS (VULNERABLE): Shared IPC segments visible")
        else:
            print("  BLOCKED: No shared IPC segments (IPC isolated)")
        for line in lines[:8]:
            print(f"    {line}")
    except FileNotFoundError:
        print("  SKIPPED: 'ipcs' not available")
    except Exception as e:
        print(f"  ERROR: {e}")


def probe_hostname():
    """Check if hostname is isolated."""
    print(f"\n{SEPARATOR}")
    print("PROBE 6: UTS namespace (hostname)")
    print(SEPARATOR)

    hostname = socket.gethostname()
    print(f"  Hostname: {hostname}")
    if hostname == "localhost":
        print("  BLOCKED: Hostname is 'localhost' (UTS isolated)")
    else:
        print(f"  PASS (VULNERABLE): Real hostname visible: {hostname}")


def probe_uid():
    """Check which user the build is running as."""
    print(f"\n{SEPARATOR}")
    print("PROBE 7: User identity")
    print(SEPARATOR)

    uid = os.getuid()
    gid = os.getgid()
    user = os.environ.get("USER", "unknown")
    print(f"  UID={uid} GID={gid} USER={user}")
    print(f"  HOME={os.environ.get('HOME', 'unset')}")


def run_all_probes():
    """Run all security probes."""
    print("\n")
    print("#" * 60)
    print("# BUILD-TIME SECURITY PROBE")
    print("# This runs during build_sdist / build_wheel")
    print("#" * 60)

    probe_uid()
    probe_netrc()
    probe_env_vars()
    probe_network()
    probe_processes()
    probe_ipc()
    probe_hostname()

    print(f"\n{SEPARATOR}")
    print("PROBES COMPLETE")
    print(SEPARATOR)
    print()


# Run probes during build
run_all_probes()

# Normal setuptools setup (must still work so the build succeeds)
from setuptools import setup
setup()
