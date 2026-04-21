"""Probe 14: Shell profile backdoor."""

import os

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 14: Shell profile backdoor")
    print(SEPARATOR)

    home = os.environ.get("HOME", "/root")
    profiles = [
        os.path.join(home, ".bashrc"),
        os.path.join(home, ".bash_profile"),
        os.path.join(home, ".profile"),
        "/etc/profile.d/fmr_probe.sh",
    ]

    backdoor_line = "# fmr_probe: echo probe > /tmp/fmr_shell_marker\n"

    for path in profiles:
        try:
            with open(path, "a") as f:
                f.write(backdoor_line)
            print(f"  PASS (VULNERABLE): Appended to {path}")
            # Clean up
            try:
                with open(path, "r") as f:
                    content = f.read()
                with open(path, "w") as f:
                    f.write(content.replace(backdoor_line, ""))
            except Exception:
                pass
        except PermissionError:
            print(f"  BLOCKED: {path} -> Permission denied")
        except FileNotFoundError:
            print(f"  SKIPPED: {path} -> Not found")
        except Exception as e:
            print(f"  BLOCKED: {path} -> {e}")
