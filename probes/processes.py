"""Probe 4: Process visibility (PID namespace)."""

import subprocess

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 4: Process visibility (PID namespace)")
    print(SEPARATOR)

    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        count = len(lines) - 1
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
