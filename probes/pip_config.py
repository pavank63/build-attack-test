"""Probe 15: pip config poisoning."""

import os

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 15: pip config poisoning")
    print(SEPARATOR)

    pip_configs = [
        "/etc/pip.conf",
        os.path.join(os.environ.get("HOME", "/root"), ".config/pip/pip.conf"),
        os.path.join(os.environ.get("VIRTUAL_ENV", "/nonexistent"), "pip.conf"),
    ]

    for path in pip_configs:
        try:
            exists = os.path.exists(path)
            with open(path, "a") as f:
                f.write("")
            if exists:
                print(f"  PASS (VULNERABLE): Can modify {path}")
            else:
                print(f"  PASS (VULNERABLE): Can create {path}")
                os.unlink(path)
        except PermissionError:
            print(f"  BLOCKED: {path} -> Permission denied")
        except FileNotFoundError:
            print(f"  SKIPPED: {path} -> Parent directory not found")
        except Exception as e:
            print(f"  BLOCKED: {path} -> {e}")
