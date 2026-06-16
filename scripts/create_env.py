"""Create the local virtual environment used by `make env`.

Python 3.11 is the reproducibility target. On developer machines without a
registered 3.11 interpreter, this falls back to the current interpreter so the
rest of Phase 0 can still be exercised locally.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"


def candidate_commands() -> list[list[str]]:
    if sys.platform.startswith("win"):
        return [["py", "-3.11"], ["python3.11"], ["py", "-3.12"], ["python3.12"], ["python"]]
    return [["python3.11"], ["python3.12"], ["python3"], ["python"]]


def version_for(cmd: list[str]) -> tuple[int, int] | None:
    exe = shutil.which(cmd[0])
    if not exe:
        return None
    try:
        code = "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
        result = subprocess.run(
            [*cmd, "-c", code],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None
    major, minor = result.stdout.strip().split(".")
    return int(major), int(minor)


def main() -> int:
    selected: list[str] | None = None
    selected_version: tuple[int, int] | None = None
    fallback: tuple[list[str], tuple[int, int]] | None = None

    for cmd in candidate_commands():
        version = version_for(cmd)
        if not version:
            continue
        if fallback is None:
            fallback = (cmd, version)
        if version == (3, 11):
            selected = cmd
            selected_version = version
            break

    if selected is None and fallback is not None:
        selected, selected_version = fallback

    if selected is None or selected_version is None:
        print("No usable Python interpreter found.", file=sys.stderr)
        return 1

    if selected_version != (3, 11):
        print(
            f"WARNING: Python 3.11 was not found; creating env with "
            f"{selected_version[0]}.{selected_version[1]}."
        )

    if VENV.exists():
        print(f"{VENV} already exists")
        return 0

    subprocess.run([*selected, "-m", "venv", str(VENV)], check=True)
    print(f"created {VENV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
