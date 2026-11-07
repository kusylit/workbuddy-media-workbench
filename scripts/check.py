#!/usr/bin/env python3
"""Local release check for WorkBuddy Media Workbench.

Run from the repository root:

    python scripts/check.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = [
    "media_studio.py",
    "plugin.json",
    "start.sh",
    "README.md",
    "README.en.md",
    "LICENSE",
    ".gitignore",
    "studio-config.example.json",
]
TEXT_FILES = [
    "media_studio.py",
    "plugin.json",
    "start.sh",
    "README.md",
    "README.en.md",
    "LICENSE",
    "studio-config.example.json",
    "media-studio.cmd",
    "media-studio-stop.cmd",
]
SECRET_PATTERNS = [
    ("local Windows user path", re.compile(r"C:\\Users\\", re.I)),
    ("local username", re.compile(r"庞皓文")),
    ("GitHub token", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("OpenAI-style key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Bearer credential", re.compile(r"Bearer\s+[A-Za-z0-9_-]{20,}")),
]
RUNTIME_NAMES = [
    "studio-config.json",
    "studio-jobs.json",
    "studio-tags.json",
    "studio-favorites.json",
    "studio-console.log",
    "studio-audit.log",
]


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    for name in REQUIRED:
        if not (ROOT / name).is_file():
            errors.append(f"missing required file: {name}")

    source = ROOT / "media_studio.py"
    if source.is_file():
        try:
            compile(source.read_text(encoding="utf-8"), str(source), "exec")
        except Exception as exc:
            errors.append(f"Python syntax: {exc}")

    manifest_path = ROOT / "plugin.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not manifest.get("id") or not manifest.get("version"):
                errors.append("plugin.json missing id or version")
        except Exception as exc:
            errors.append(f"plugin.json: {exc}")

    start = ROOT / "start.sh"
    if start.is_file() and b"\r\n" in start.read_bytes():
        errors.append("start.sh must use LF line endings")

    for name in TEXT_FILES:
        path = ROOT / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"{label} found in {name}")

    for name in RUNTIME_NAMES:
        if (ROOT / name).exists():
            warnings.append(f"runtime file present (must stay untracked): {name}")
    if (ROOT / "media-out").exists():
        warnings.append("runtime directory present (must stay untracked): media-out/")

    for item in warnings:
        print("WARN:", item)
    for item in errors:
        print("FAIL:", item)
    if errors:
        print(f"\n{len(errors)} check(s) failed.")
        return 1
    print("OK: syntax, manifest, files and public-release scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
