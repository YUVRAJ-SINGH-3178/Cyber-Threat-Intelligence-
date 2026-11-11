"""Single-command repository runner: setup, test, run-experiments, make-figures."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def _run(cmd: list[str]) -> int:
    print(f"> {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=str(ROOT), check=False).returncode


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("setup", "test", "run-experiments", "make-figures"):
        print("Usage: python manage.py <setup|test|run-experiments|make-figures>")
        return 2

    cmd = sys.argv[1]
    if cmd == "setup":
        rc = _run([sys.executable, "-m", "pip", "install", "--no-deps", "--no-build-isolation", "-e", "."])
        if rc != 0:
            return rc
        return _run([sys.executable, "-m", "agent_cti.cli", "demo-pillar1"])
    if cmd == "test":
        return _run([sys.executable, "-m", "pytest", "-v"])
    if cmd == "run-experiments":
        return _run([sys.executable, str(ROOT / "experiments" / "run_experiments.py"), *sys.argv[2:]])
    if cmd == "make-figures":
        return _run([sys.executable, str(ROOT / "experiments" / "make_figures.py")])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

