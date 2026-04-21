"""Probe 11: Persistent background process.

Uses subprocess.Popen instead of os.fork() to avoid inheriting
pyproject_hooks' stdout pipe (which causes the build to hang).
"""

import os
import sys
import subprocess

from . import SEPARATOR

MARKER = "/tmp/fmr_probe_marker"


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 11: Persistent background process")
    print(SEPARATOR)

    try:
        # Spawn a detached process that writes a marker file.
        # Uses subprocess.Popen with start_new_session=True to fully
        # detach from the parent. stdin/stdout/stderr are redirected
        # to /dev/null so we don't hold pyproject_hooks' pipes open.
        proc = subprocess.Popen(
            [
                sys.executable, "-c",
                f"import time, os\n"
                f"for i in range(150):\n"
                f"    with open('{MARKER}', 'w') as f:\n"
                f"        f.write(f'alive: iteration={{i}} pid={{os.getpid()}} time={{time.time()}}\\n')\n"
                f"    time.sleep(2)\n"
            ],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"  SPAWNED: Background process with PID {proc.pid}")
        print(f"  Marker file: {MARKER}")
        print(f"  To verify after build:")
        print(f"    cat {MARKER}              # should stop updating with --build-isolation")
        print(f"    ps -p {proc.pid}          # should be gone with --build-isolation")
        print("  PASS (VULNERABLE): Background process spawned")
    except Exception as e:
        print(f"  BLOCKED: Cannot spawn -> {e}")
