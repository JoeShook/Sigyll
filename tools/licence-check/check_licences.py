#!/usr/bin/env python3
"""Checks the licence of every package in Sigyll's CycloneDX BOMs against an allow-list.

Sigyll is used commercially, so a dependency must carry a permissive licence (allowed_licences.json,
"licences"). A package whose licence is anything else, or that declares none, fails the check unless
it is listed under "exceptions" with the reason it is acceptable (for example, a build-time tool that
never ships). Licence expressions are honoured: "MIT OR GPL-3.0" passes, "MIT AND GPL-3.0" does not.

Usage: check_licences.py [--allowed FILE] BOM.json [BOM.json ...]
Exit code 1 when any package fails.
"""
import json
import re
import sys
from pathlib import Path

DEFAULT_ALLOWED = Path(__file__).with_name("allowed_licences.json")


def expression_allowed(expression: str, allowed: set[str]) -> bool:
    """A licence expression passes when one OR branch passes and every AND term in it is allowed."""
    expression = expression.replace("(", " ").replace(")", " ")
    for branch in re.split(r"\s+OR\s+", expression.strip()):
        terms = [t.strip() for t in re.split(r"\s+AND\s+", branch) if t.strip()]
        # "WITH <exception>" only narrows the licence it follows.
        if terms and all(re.split(r"\s+WITH\s+", t)[0] in allowed for t in terms):
            return True
    return False


def component_licences(component: dict) -> list[str]:
    """The component's licences as SPDX ids or expressions; a non-SPDX licence by its name (or "unknown")."""
    found = []
    for entry in component.get("licenses") or []:
        if "expression" in entry:
            found.append(entry["expression"])
        elif "license" in entry:
            licence = entry["license"]
            found.append(licence.get("id") or f"non-SPDX: {licence.get('name') or licence.get('url') or 'unknown'}")
    return found


def check(bom_paths: list[Path], allowed_path: Path) -> list[str]:
    config = json.loads(allowed_path.read_text(encoding="utf-8"))
    allowed = set(config["licences"])
    exceptions = {name.lower() for name in config.get("exceptions", {})}

    failures = {}
    for bom_path in bom_paths:
        bom = json.loads(bom_path.read_text(encoding="utf-8"))
        for component in bom.get("components", []):
            name, version = component.get("name", "?"), component.get("version", "?")
            if name.lower() in exceptions:
                continue
            licences = component_licences(component)
            if not licences:
                failures[(name, version)] = "declares no licence"
            elif not all(expression_allowed(lic, allowed) for lic in licences):
                failures[(name, version)] = "licensed " + "; ".join(licences)
    return [f"{name} {version}: {reason}" for (name, version), reason in sorted(failures.items())]


def main(argv: list[str]) -> int:
    allowed_path = DEFAULT_ALLOWED
    if len(argv) >= 2 and argv[0] == "--allowed":
        allowed_path, argv = Path(argv[1]), argv[2:]
    if not argv:
        print(__doc__)
        return 2

    failures = check([Path(p) for p in argv], allowed_path)
    for failure in failures:
        print(f"::error::{failure}, which is not on the licence allow-list ({allowed_path.name})")
    if failures:
        print(f"{len(failures)} package(s) need a permissive licence, or an entry under \"exceptions\" saying why "
              f"they are acceptable.")
        return 1
    print(f"Licences checked in {len(argv)} BOM(s): all allowed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
