#!/usr/bin/env python3
"""Synchronize or check the maintained Skill, its source contract, mirrors and ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/universal-crypto-rules"
ZIP = ROOT / "docs/universal-crypto-rules.zip"
MIRRORS = [ROOT / "docs/universal-crypto-rules"]

def files(folder):
    return {f.relative_to(folder).as_posix(): f for f in folder.rglob("*")
            if f.is_file() and f.name != ".DS_Store" and "__pycache__" not in f.parts}

def source_hashes():
    paths = list((ROOT / "src/main/java").rglob("*.java"))
    paths += [ROOT / name for name in ("pom.xml", "build.sh", "Makefile", "status.sh", "LICENSE")]
    paths += [path for path in (ROOT / "src/main/resources").rglob("*") if path.is_file() and path.name != ".DS_Store"]
    paths += [path for path in (ROOT / "src/test/resources").rglob("*") if path.is_file() and path.name != ".DS_Store"]
    paths += list((ROOT / "scripts").glob("*.py"))
    return {f.relative_to(ROOT).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(paths)}

def check(mirrors=MIRRORS):
    errors = []
    contract = json.loads((SKILL / "assets/source-contract.json").read_text(encoding="utf-8"))
    current = source_hashes()
    for name in set(contract["files"]) - set(current):
        errors.append("source contract contains removed input: " + name)
    for name, expected in current.items():
        if contract["files"].get(name) != expected:
            errors.append("source contract: " + name)
    authoritative = files(SKILL)
    for mirror in mirrors:
        if not mirror.exists():
            errors.append("missing mirror: " + str(mirror)); continue
        for name, original in authoritative.items():
            copied = mirror / name
            if not copied.is_file() or copied.read_bytes() != original.read_bytes():
                errors.append(str(mirror) + ": " + name)
    try:
        with zipfile.ZipFile(ZIP) as archive:
            for name, original in authoritative.items():
                entry = "universal-crypto-rules/" + name
                if entry not in archive.namelist() or archive.read(entry) != original.read_bytes():
                    errors.append("Skill ZIP: " + name)
    except (OSError, zipfile.BadZipFile) as error:
        errors.append("Skill ZIP: " + str(error))
    for file in (SKILL / "references").glob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", file.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"): continue
            target = target.split("#", 1)[0]
            if target and not (file.parent / target).exists(): errors.append(str(file.relative_to(ROOT)) + ": broken link " + target)
    for example in (SKILL / "assets/examples").glob("*.json"):
        if not example.name.endswith((".rules.json", ".fixtures.json")): continue
        resource = ROOT / "src/main/resources/com/universal/crypto/presets" / example.name
        if not resource.is_file() or resource.read_bytes() != example.read_bytes():
            errors.append("packaged preset: " + example.name)
    constants = (ROOT / "src/main/java/com/universal/crypto/model/Constants.java").read_text(encoding="utf-8").split("public static final class ExecutionPhase", 1)[1].split("private ExecutionPhase()", 1)[0]
    phases = set(re.findall(r'public static final String \w+ = "([^"]+)"', constants))
    schema = json.loads((SKILL / "assets/rule.schema.json").read_text(encoding="utf-8"))
    def patterns(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "executionPhase": yield value["pattern"]
                else: yield from patterns(value)
        elif isinstance(node, list):
            for value in node: yield from patterns(value)
    for pattern in patterns(schema):
        first = re.search(r"\^\(([^)]+)\)", pattern)
        if not first or set(first.group(1).split("|")) != phases: errors.append("Schema has stale/unknown execution phases")
        if any(re.fullmatch(pattern, phase) is None for phase in phases): errors.append("Schema execution phases do not match Java constants")
    return errors

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Read-only consistency check")
    parser.add_argument("--install", action="store_true", help="Also synchronize/check the installed ~/.codex Skill")
    parser.add_argument("--date", help="Documented release date when synchronizing")
    args = parser.parse_args()
    mirrors = MIRRORS + ([Path.home() / ".codex/skills/universal-crypto-rules"] if args.install else [])
    if not args.check:
        contract_path = SKILL / "assets/source-contract.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["files"] = source_hashes()
        if args.date: contract["documentedDate"] = args.date
        contract_path.write_bytes((json.dumps(contract, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        for mirror in mirrors:
            shutil.copytree(SKILL, mirror, dirs_exist_ok=True)
        with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, file in sorted(files(SKILL).items()): archive.write(file, "universal-crypto-rules/" + name)
    errors = check(mirrors)
    if errors:
        print("\n".join(errors), file=sys.stderr); return 1
    print("Skill source contract, references, schema, selected mirrors and ZIP are consistent.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
