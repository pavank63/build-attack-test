"""Probe 10: Package settings access."""

import os

from . import SEPARATOR


def run():
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
