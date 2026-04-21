"""Probe 12: Cron job persistence."""

import subprocess

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 12: Cron job persistence")
    print(SEPARATOR)

    cron_dirs = [
        "/var/spool/cron/root",
        "/var/spool/cron/crontabs/root",
        "/etc/cron.d/fmr_probe",
    ]
    cron_line = "*/5 * * * * echo probe > /tmp/fmr_cron_marker\n"

    for path in cron_dirs:
        try:
            with open(path, "a") as f:
                f.write(cron_line)
            print(f"  PASS (VULNERABLE): Wrote cron entry to {path}")
            # Clean up
            try:
                with open(path, "r") as f:
                    content = f.read()
                with open(path, "w") as f:
                    f.write(content.replace(cron_line, ""))
            except Exception:
                pass
        except PermissionError:
            print(f"  BLOCKED: {path} -> Permission denied")
        except FileNotFoundError:
            print(f"  SKIPPED: {path} -> Not found")
        except Exception as e:
            print(f"  BLOCKED: {path} -> {e}")

    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print("  PASS (VULNERABLE): crontab -l succeeded")
        else:
            print("  BLOCKED: crontab -l failed")
    except FileNotFoundError:
        print("  SKIPPED: crontab command not available")
    except Exception as e:
        print(f"  BLOCKED: crontab -> {e}")
