"""Compare action-scoped test evidence across two declared release snapshots.

Run: python check.py baseline.json candidate.json
Exit 0: evidence applies to all declared actions. Exit 1: review or retest.
Exit 2: invalid input. Component values must be immutable version identifiers.
The snapshot author is responsible for declaring complete dependencies.
"""
import argparse
import json
from pathlib import Path


def action(snapshot, name):
    record = snapshot["actions"].get(name)
    if not isinstance(record, dict) or record.get("complete") is not True:
        return None
    deps = record.get("dependencies")
    test = record.get("test")
    if not isinstance(test, str) or not test.strip():
        return None
    if not isinstance(deps, list) or not deps:
        return None
    versions = {}
    for dep in deps:
        if not isinstance(dep, str) or not dep.strip() or dep in versions:
            return None
        version = snapshot["components"].get(dep)
        if not isinstance(version, str) or not version.strip():
            return None
        versions[dep] = version
    return test, versions


def compare(before, after):
    for snapshot in (before, after):
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("components"), dict):
            raise ValueError("components must be an object")
        if not isinstance(snapshot.get("actions"), dict) or not snapshot["actions"]:
            raise ValueError("actions must be a nonempty object")
    results = {}
    for name in sorted(before["actions"].keys() | after["actions"].keys()):
        old, new = action(before, name), action(after, name)
        result = {"status": "UNKNOWN", "reason": "missing action or incomplete scope"}
        if old and new:
            test, versions = new
            evidence = before["actions"][name].get("passed_test")
            if evidence != old[0]:
                result["reason"] = "no passing baseline test for the declared scope"
            else:
                components = versions.keys() | old[1].keys()
                changed = sorted(k for k in components if versions.get(k) != old[1].get(k))
                retest = bool(changed) or old[0] != test
                result = {"status": "RETEST" if retest else "APPLIES",
                          "changed_components": changed, "test": test}
        results[name] = result
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    try:
        report = compare(*(json.loads(p.read_text(encoding="utf-8"))
                           for p in (args.baseline, args.candidate)))
    except (ValueError, OSError) as error:
        parser.exit(2, f"{error}\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(int(any(item["status"] != "APPLIES" for item in report.values())))
