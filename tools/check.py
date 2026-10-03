# Path: working/tools/check.py
"""Run the same format, lint and regression checks locally and in CI.

After development tools are found, each run keeps a fresh receipt and raw logs.
Exit zero means every command passed; nonzero stops at the first failed gate.
No source code is changed by this tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=ROOT / "verification-results")
    args = parser.parse_args()
    run_name = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = args.output_root.resolve() / run_name
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["COVERAGE_FILE"] = str(output / ".coverage")
    commands = [
        ("format", ["ruff", "format", "--check", "."]),
        ("lint", ["ruff", "check", "."]),
        (
            "tests",
            ["coverage", "run", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
        ),
        ("coverage-json", ["coverage", "json", "-o", str(output / "coverage.json")]),
        ("coverage-report", ["coverage", "report"]),
    ]
    records = []
    try:
        installed_tools = {name: version(name) for name in ("ruff", "coverage")}
    except Exception as exc:
        print(
            f"Development tools unavailable: {exc}. Install requirements-dev.txt.", file=sys.stderr
        )
        return 2
    print(f"Python: {sys.version}; platform: {platform.platform()}", flush=True)
    print(f"Development tools: {installed_tools}", flush=True)
    for name, arguments in commands:
        command = [sys.executable, "-B", "-X", "utf8", "-m", *arguments]
        print(f"Running {name}...", flush=True)
        try:
            result = subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=300,
                check=False,
            )
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:

            def decode(value: bytes | str | None) -> str:
                return (
                    value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")
                )

            stdout, stderr, code = decode(exc.stdout), decode(exc.stderr), 124
            stderr += "\nCheck exceeded its 300-second time limit.\n"
        (output / f"{name}.stdout.txt").write_text(stdout, encoding="utf-8")
        (output / f"{name}.stderr.txt").write_text(stderr, encoding="utf-8")
        records.append({"name": name, "command": command, "exit_code": code})
        if stdout:
            print(stdout.rstrip(), flush=True)
        if stderr:
            print(stderr.rstrip(), file=sys.stderr)
        if code:
            break
    coverage_file = output / "coverage.json"
    coverage_totals = None
    if coverage_file.exists():
        coverage_totals = json.loads(coverage_file.read_text(encoding="utf-8"))["totals"]
    files = [
        *ROOT.glob("enigma_lab/*.py"),
        *ROOT.glob("enigma_demo/*.py"),
        *ROOT.glob("enigma_demo/*.json"),
        *ROOT.glob("enigma_demo/static/*"),
        *ROOT.glob("tests/*.py"),
        *ROOT.glob("tests/fixtures/*"),
        *ROOT.glob("tools/*.py"),
        *ROOT.glob("experiments/*/*.py"),
        *ROOT.glob("experiments/*/*.json"),
        ROOT / "pyproject.toml",
        ROOT / "requirements-dev.txt",
        ROOT / ".github/workflows/ci.yml",
        ROOT / "Start_Enigma_Demo.ps1",
    ]
    receipt = {
        "created_utc": datetime.now(UTC).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "project": str(ROOT),
        "tools": installed_tools,
        "commands": records,
        "passed": len(records) == len(commands) and all(item["exit_code"] == 0 for item in records),
        "coverage_totals": coverage_totals,
        "source_sha256": {
            str(path.relative_to(ROOT)): digest(path) for path in sorted(files) if path.is_file()
        },
        "limits": [
            "Local execution only; does not establish remote GitHub Actions success.",
            "Coverage measures executed application statements/branches, not correctness or historical fidelity.",
            "Subprocess smoke checks are not automatically included in parent-process coverage.",
            "Python coverage includes enigma_lab and enigma_demo; HTML, CSS, JavaScript and PowerShell are verified separately.",
        ],
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"Receipt: {output / 'receipt.json'}")
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
