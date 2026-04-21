"""Probe 13: Python .pth file backdoor."""

import os
import site

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 13: Python .pth file backdoor")
    print(SEPARATOR)

    site_dirs = site.getsitepackages()
    try:
        site_dirs.append(site.getusersitepackages())
    except Exception:
        pass

    pth_content = "import os; os.environ.setdefault('FMR_PTH_PROBE', 'active')\n"
    pth_name = "fmr_probe.pth"

    for d in site_dirs:
        if not os.path.isdir(d):
            print(f"  SKIPPED: {d} -> Not found")
            continue
        pth_path = os.path.join(d, pth_name)
        try:
            with open(pth_path, "w") as f:
                f.write(pth_content)
            print(f"  PASS (VULNERABLE): Wrote {pth_path}")
            print("  !! Code will run on EVERY Python startup")
            os.unlink(pth_path)
        except PermissionError:
            print(f"  BLOCKED: {pth_path} -> Permission denied")
        except Exception as e:
            print(f"  BLOCKED: {pth_path} -> {e}")
