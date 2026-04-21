"""Probe 2: Sensitive environment variables."""

import os

from . import SEPARATOR

TARGETS = {
    "CI_JOB_TOKEN": "GitLab CI job token",
    "CI_REGISTRY_PASSWORD": "Container registry password",
    "BOT_PAT": "GitLab bot personal access token",
    "NETRC": ".netrc file path override",
    "TWINE_USERNAME": "PyPI/GitLab upload username",
    "TWINE_PASSWORD": "PyPI/GitLab upload password",
    "NGC_API_KEY": "NVIDIA GPU Cloud API key",
    "FROMAGER_ARGS": "Arbitrary fromager CLI arguments",
    "WHEEL_SERVER_PROJECT_PATH": "GitLab wheel index project path",
    "TOOL_SERVER_URL": "Package index URL for tools",
    "GH_TOKEN": "GitHub token",
    "GITHUB_TOKEN": "GitHub token",
    "AWS_SECRET_ACCESS_KEY": "AWS secret key",
}


def run():
    print(f"\n{SEPARATOR}")
    print("PROBE 2: Sensitive environment variables")
    print(SEPARATOR)

    for var, description in TARGETS.items():
        val = os.environ.get(var)
        if val:
            masked = val[:4] + "****" if len(val) > 4 else "****"
            print(f"  PASS (VULNERABLE): ${var} ({description}) = {masked}")
        else:
            print(f"  BLOCKED/ABSENT: ${var} ({description})")
