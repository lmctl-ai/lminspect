#!/usr/bin/env python3
"""The committed lminspect version floor plus workflow run number is stable."""
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
current = (root / "VERSION").read_text(encoding="utf-8").strip()
match = re.fullmatch(r"(0\.1)\.(\d+)", current)
assert match, current
patch = int(match[2])

def derive(*args):
    return subprocess.check_output(["bash", root / "scripts/derive-release-version.sh", *args], text=True).strip()

assert derive("--diagnostic") == current
assert derive("1") == f"0.1.{patch + 1}"
assert derive("17") == f"0.1.{patch + 17}"
assert derive("17") == f"0.1.{patch + 17}"
workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
build = (root / "test.sh").read_text(encoding="utf-8")
assert "branches: [main]" in workflow and "tags: ['v*']" not in workflow
assert "needs: [version, build]" in workflow and "needs.version.outputs.release" in workflow
assert "LINSPECT_RELEASE_VERSION: ${{ needs.version.outputs.version }}" in workflow
assert "-X main.version=${RELEASE_VERSION}" in build
print("PASS lminspect run-derived version contract")
