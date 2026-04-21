"""
Build-time security probe.

Runs during build_sdist / build_wheel to test what a malicious
build backend can access. Each probe prints PASS (attack succeeded)
or BLOCKED (attack failed).
"""

import os
import sys

# setuptools runs setup.py via exec() and the source root may not
# be on sys.path. Add it so the probes package is importable.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from probes import SEPARATOR
from probes import (
    uid,
    netrc,
    env_vars,
    network,
    processes,
    ipc,
    hostname,
    ca_certs,
    build_cache,
    settings_files,
    persistent_process,
    cron_job,
    pth_backdoor,
    shell_profile,
    pip_config,
)

ALL_PROBES = [
    uid,
    netrc,
    env_vars,
    network,
    processes,
    ipc,
    hostname,
    ca_certs,
    build_cache,
    settings_files,
    persistent_process,
    cron_job,
    pth_backdoor,
    shell_profile,
    pip_config,
]

print("\n")
print("#" * 60)
print("# BUILD-TIME SECURITY PROBE")
print("# This runs during build_sdist / build_wheel")
print(f"# Python: {sys.version}")
print(f"# Platform: {sys.platform}")
print("#" * 60)

for probe in ALL_PROBES:
    try:
        probe.run()
    except Exception as e:
        print(f"\n  ERROR in {probe.__name__}: {e}")

print(f"\n{SEPARATOR}")
print("ALL PROBES COMPLETE")
print(SEPARATOR)
print()

from setuptools import setup
setup()
