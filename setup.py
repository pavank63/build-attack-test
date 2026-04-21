"""
Build-time security probe.

This setup.py runs during build_sdist / build_wheel and attempts
several attack vectors that build isolation should block.

Each probe prints PASS (attack succeeded = vulnerable) or
BLOCKED (attack failed = isolated).

Targets are based on the real RHEL AI builder environment.
"""

import os
import socket
import subprocess
import sys

SEPARATOR = "=" * 60


def probe_netrc():
    """Try to read .netrc credential files.

    In the builder container, .netrc is mounted at
    /opt/app-root/src/.netrc (mode 600, root:root) and contains
    GitLab PAT tokens for package index access.
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 1: Credential file access (.netrc)")
    print(SEPARATOR)

    paths = [
        # Builder container mounts .netrc here via --mount=type=secret
        "/opt/app-root/src/.netrc",
        # Standard Unix locations
        os.path.expanduser("~/.netrc"),
        "/root/.netrc",
    ]

    for path in paths:
        try:
            with open(path) as f:
                content = f.read()
            print(f"  PASS (VULNERABLE): Read {path} ({len(content)} bytes)")
            # Check if it looks like real credentials
            if "machine" in content and "password" in content:
                print(f"  !! Contains machine/password entries")
        except PermissionError:
            print(f"  BLOCKED: {path} -> Permission denied")
        except FileNotFoundError:
            print(f"  SKIPPED: {path} -> File not found")
        except Exception as e:
            print(f"  BLOCKED: {path} -> {e}")


def probe_env_vars():
    """Try to read sensitive environment variables.

    These are real variables present in the builder environment:
    - NETRC: overrides .netrc location
    - TWINE_PASSWORD: set by gaudi_mirror plugin from .netrc
    - TWINE_USERNAME: set alongside TWINE_PASSWORD
    - CI_JOB_TOKEN: GitLab CI built-in token
    - CI_REGISTRY_PASSWORD: container registry auth
    - BOT_PAT: GitLab personal access token for the build bot
    - NGC_API_KEY: NVIDIA GPU Cloud API key
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 2: Sensitive environment variables")
    print(SEPARATOR)

    # Grouped by source
    targets = {
        # GitLab CI/CD tokens
        "CI_JOB_TOKEN": "GitLab CI job token",
        "CI_REGISTRY_PASSWORD": "Container registry password",
        "BOT_PAT": "GitLab bot personal access token",
        # Credential file pointers
        "NETRC": ".netrc file path override",
        # Package upload credentials (set by gaudi_mirror plugin)
        "TWINE_USERNAME": "PyPI/GitLab upload username",
        "TWINE_PASSWORD": "PyPI/GitLab upload password",
        # Vendor API keys
        "NGC_API_KEY": "NVIDIA GPU Cloud API key",
        # Build system internals
        "FROMAGER_ARGS": "Arbitrary fromager CLI arguments",
        "WHEEL_SERVER_PROJECT_PATH": "GitLab wheel index project path",
        "TOOL_SERVER_URL": "Package index URL for tools",
        # Generic sensitive vars
        "GH_TOKEN": "GitHub token",
        "GITHUB_TOKEN": "GitHub token",
        "AWS_SECRET_ACCESS_KEY": "AWS secret key",
    }

    for var, description in targets.items():
        val = os.environ.get(var)
        if val:
            masked = val[:4] + "****" if len(val) > 4 else "****"
            print(f"  PASS (VULNERABLE): ${var} ({description}) = {masked}")
        else:
            print(f"  BLOCKED/ABSENT: ${var} ({description})")


def probe_network():
    """Try to reach the network.

    A malicious build could exfiltrate stolen credentials to an
    external server. Test both DNS and direct TCP.
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 3: Network access")
    print(SEPARATOR)

    # DNS resolution
    try:
        addr = socket.getaddrinfo("pypi.org", 443)[0][4][0]
        print(f"  PASS (VULNERABLE): DNS resolved pypi.org -> {addr}")
    except (socket.gaierror, OSError) as e:
        print(f"  BLOCKED: DNS resolution failed -> {e}")

    # TCP connection to external host
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        print("  PASS (VULNERABLE): TCP connection to 8.8.8.8:53 succeeded")
    except (ConnectionRefusedError, OSError) as e:
        print(f"  BLOCKED: TCP connection failed -> {e}")

    # Try reaching GitLab (where credentials would be most useful)
    try:
        addr = socket.getaddrinfo("gitlab.com", 443)[0][4][0]
        print(f"  PASS (VULNERABLE): DNS resolved gitlab.com -> {addr}")
    except (socket.gaierror, OSError) as e:
        print(f"  BLOCKED: gitlab.com DNS failed -> {e}")


def probe_processes():
    """Try to see other processes.

    Without PID isolation, a build can see all processes including
    other parallel builds, fromager itself, and any credential-
    handling processes.
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 4: Process visibility (PID namespace)")
    print(SEPARATOR)

    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        count = len(lines) - 1  # minus header
        print(f"  Visible processes: {count}")
        if count > 5:
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
    """Try to access shared IPC resources.

    Shared memory segments and semaphores from other builds or
    system services are visible without IPC isolation.
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 5: IPC namespace isolation")
    print(SEPARATOR)

    try:
        result = subprocess.run(
            ["ipcs", "-a"], capture_output=True, text=True, timeout=5
        )
        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
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
    """Check if hostname is isolated.

    Real hostname leaks the build machine identity.
    """
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


def probe_ca_certs():
    """Try to read CA certificates and RPM GPG keys.

    The builder installs Red Hat IT Root CA and vendor GPG keys.
    These aren't secrets per se, but reveal the build environment.
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 8: CA certificates and GPG keys")
    print(SEPARATOR)

    paths = [
        "/etc/pki/ca-trust/source/anchors/Red_Hat_IT_Root_CA.pem",
        "/etc/pki/rpm-gpg/RPM-GPG-KEY-NVIDIA-CUDA-9",
    ]

    for path in paths:
        try:
            size = os.path.getsize(path)
            print(f"  FOUND: {path} ({size} bytes)")
        except (FileNotFoundError, PermissionError) as e:
            print(f"  NOT FOUND: {path} -> {e}")


def probe_build_cache():
    """Try to access build caches.

    ccache and cargo caches persist across builds. A malicious build
    could poison these to inject code into future builds.
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 9: Build cache access")
    print(SEPARATOR)

    cache_dirs = [
        ("/var/cache/builder/ccache", "C/C++ compiler cache"),
        ("/var/cache/builder/cargo/home", "Rust cargo home"),
        ("/var/cache/builder/cargo/target", "Rust build target"),
    ]

    for path, description in cache_dirs:
        if os.path.isdir(path):
            try:
                entries = os.listdir(path)
                print(f"  PASS (VULNERABLE): {description} at {path} ({len(entries)} entries)")
            except PermissionError:
                print(f"  BLOCKED: {description} at {path} -> Permission denied")
        else:
            print(f"  NOT FOUND: {description} at {path}")

    # Check if we can write to ccache (cache poisoning)
    ccache_dir = os.environ.get("CCACHE_DIR", "/var/cache/builder/ccache")
    if os.path.isdir(ccache_dir):
        test_file = os.path.join(ccache_dir, ".probe_test")
        try:
            with open(test_file, "w") as f:
                f.write("probe")
            os.unlink(test_file)
            print(f"  PASS (VULNERABLE): Can WRITE to ccache dir (cache poisoning possible)")
        except (PermissionError, OSError) as e:
            print(f"  BLOCKED: Cannot write to ccache -> {e}")


def probe_settings_files():
    """Try to read package override settings.

    Settings files contain per-package build configuration including
    environment variables passed to builds.
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 10: Package settings access")
    print(SEPARATOR)

    settings_dirs = [
        "/work/overrides/settings",
        "/work/overrides",
    ]

    for d in settings_dirs:
        if os.path.isdir(d):
            try:
                entries = os.listdir(d)
                yaml_files = [e for e in entries if e.endswith(".yaml")]
                print(f"  FOUND: {d} ({len(yaml_files)} yaml files)")
                for f in yaml_files[:5]:
                    print(f"    - {f}")
                if len(yaml_files) > 5:
                    print(f"    ... ({len(yaml_files) - 5} more)")
            except PermissionError:
                print(f"  BLOCKED: {d} -> Permission denied")
        else:
            print(f"  NOT FOUND: {d}")


def probe_persistent_process():
    """Try to spawn a background process that outlives the build.

    A malicious build could fork a daemon that persists after the build
    finishes. Without PID namespace isolation, this process stays alive
    and can continue reading files, modifying caches, or waiting for
    network access to exfiltrate data.

    With PID namespace isolation (--build-isolation), the kernel kills
    all processes in the namespace when the init process exits.

    This probe writes a marker file and spawns a background process
    that updates it every 2 seconds. After the build, check:
      - Is the process still running?  ps aux | grep fmr_probe
      - Is the marker being updated?   cat /tmp/fmr_probe_marker
    """
    print(f"\n{SEPARATOR}")
    print("PROBE 11: Persistent background process")
    print(SEPARATOR)

    marker = "/tmp/fmr_probe_marker"
    try:
        pid = os.fork()
        if pid == 0:
            # Child: detach from parent, become a daemon
            os.setsid()
            try:
                # Write marker every 2 seconds for 5 minutes
                import time
                for i in range(150):
                    with open(marker, "w") as f:
                        f.write(f"alive: iteration={i} pid={os.getpid()} time={time.time()}\n")
                    time.sleep(2)
            except Exception:
                pass
            os._exit(0)
        else:
            # Parent: report success
            print(f"  SPAWNED: Background daemon with PID {pid}")
            print(f"  Marker file: {marker}")
            print(f"  To verify after build:")
            print(f"    ps aux | grep fmr_probe  # should be gone with --build-isolation")
            print(f"    cat {marker}              # should stop updating")
            print(f"  PASS (VULNERABLE): Daemon spawned successfully")
    except Exception as e:
        print(f"  BLOCKED: Cannot fork -> {e}")


def run_all_probes():
    """Run all security probes."""
    print("\n")
    print("#" * 60)
    print("# BUILD-TIME SECURITY PROBE")
    print("# This runs during build_sdist / build_wheel")
    print(f"# Python: {sys.version}")
    print(f"# Platform: {sys.platform}")
    print("#" * 60)

    probe_uid()
    probe_netrc()
    probe_env_vars()
    probe_network()
    probe_processes()
    probe_ipc()
    probe_hostname()
    probe_ca_certs()
    probe_build_cache()
    probe_settings_files()
    probe_persistent_process()

    print(f"\n{SEPARATOR}")
    print("ALL PROBES COMPLETE")
    print(SEPARATOR)
    print()


# Run probes during build
run_all_probes()

# Normal setuptools setup (must still work so the build succeeds)
from setuptools import setup
setup()
