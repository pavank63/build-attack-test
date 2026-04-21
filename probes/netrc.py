"""Probe 1: Credential file access (.netrc)."""

import os

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 1: Credential file access (.netrc)")
    print(SEPARATOR)

    paths = [
        "/opt/app-root/src/.netrc",
        os.path.expanduser("~/.netrc"),
        "/root/.netrc",
    ]

    for path in paths:
        try:
            with open(path) as f:
                content = f.read()
            print(f"  PASS (VULNERABLE): Read {path} ({len(content)} bytes)")
            if "machine" in content and "password" in content:
                print("  !! Contains machine/password entries")
        except PermissionError:
            print(f"  BLOCKED: {path} -> Permission denied")
        except FileNotFoundError:
            print(f"  SKIPPED: {path} -> File not found")
        except Exception as e:
            print(f"  BLOCKED: {path} -> {e}")
