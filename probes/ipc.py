"""Probe 5: IPC namespace isolation."""

import subprocess

from . import SEPARATOR


def run():
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
