"""Probe 8: CA certificates and GPG keys."""

import os

from . import SEPARATOR


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 8: CA certificates and GPG keys")
    print(SEPARATOR)

    paths = [
        "/etc/pki/ca-trust/source/anchors/Red_Hat_IT_Root_CA.pem",
        "/etc/pki/rpm-gpg/RPM-GPG-KEY-NVIDIA-CUDA-9",
    ]

    for path in paths:
        try:
            size = os.path.getsize(path)
            print(f"  FOUND: {path} ({size} bytes)")
        except (FileNotFoundError, PermissionError) as e:
            print(f"  NOT FOUND: {path} -> {e}")
