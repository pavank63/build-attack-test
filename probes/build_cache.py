"""Probe 9: Build cache access."""

import os

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 9: Build cache access")
    print(SEPARATOR)

    cache_dirs = [
        ("/var/cache/builder/ccache", "C/C++ compiler cache"),
        ("/var/cache/builder/cargo/home", "Rust cargo home"),
        ("/var/cache/builder/cargo/target", "Rust build target"),
    ]

    for path, description in cache_dirs:
        if os.path.isdir(path):
            try:
                entries = os.listdir(path)
                print(f"  PASS (VULNERABLE): {description} at {path} ({len(entries)} entries)")
            except PermissionError:
                print(f"  BLOCKED: {description} at {path} -> Permission denied")
        else:
            print(f"  NOT FOUND: {description} at {path}")

    # Check if we can write to ccache (cache poisoning)
    ccache_dir = os.environ.get("CCACHE_DIR", "/var/cache/builder/ccache")
    if os.path.isdir(ccache_dir):
        test_file = os.path.join(ccache_dir, ".probe_test")
        try:
            with open(test_file, "w") as f:
                f.write("probe")
            os.unlink(test_file)
            print("  PASS (VULNERABLE): Can WRITE to ccache dir (cache poisoning possible)")
        except (PermissionError, OSError) as e:
            print(f"  BLOCKED: Cannot write to ccache -> {e}")
