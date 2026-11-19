"""
mutation_check.py — does conformance.py actually catch what it claims to?
=========================================================================
Not collected by pytest (the name is not test_*.py and not conformance.py).
    python tests/fault_injection/mutation_check.py

For every property conformance.py says it checks, this breaks that property in
a scratch copy of the tree and requires the suite to turn red. A conformance
suite that has never been seen to fail has not been shown to work; a suite that
stays green when the thing it guards is deliberately broken is worse than none.
A mutation whose pattern is not found exactly once is itself a failure — the
tree changed and the check silently stopped checking.
"""
from __future__ import annotations
import os, re, shutil, subprocess, sys, tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MUTATIONS = [
    ("immutability: committed evidence becomes mutable", "hb_eval_sdk/evidence.py",
     [(r"@dataclass\(frozen=True\)(\s*\nclass FaultEvent)", r"@dataclass\1")]),
    ("provenance: EVENTS labelled agent_reported", "hb_eval_sdk/evidence.py",
     [(r'("provenance"\] = \{\s*\n\s*)"source": "runtime_observed"', r'\1"source": "agent_reported"')]),
    ("provenance: the store SUMMARY labelled agent_reported", "hb_eval_sdk/evidence.py",
     [(r'("intent_mismatches": len\(mismatched\),\s*\n\s*)"source": "runtime_observed"', r'\1"source": "agent_reported"')]),
    ("replay: fault schedule ignores the seed", "hb_eval_sdk/faults.py",
     [(r"draw = int\(hashlib\.sha256\(key\)\.hexdigest\(\)\[:8\], 16\) / 0xFFFFFFFF",
       "draw = __import__('random').random()")]),
    ("types: no fault is ever applied", "hb_eval_sdk/faults.py",
     [(r"    if probability >= 1\.0:\n        return True", "    if probability >= 1.0:\n        return False")]),
    ("tamper: evidence is reachable by a forgeable session_id string", "hb_eval_sdk/evidence.py",
     [(r"    key = id\(session_obj\)\n    store = _stores_by_identity",
       "    key = getattr(session_obj, 'session_id', id(session_obj))\n    store = _stores_by_identity")]),
]


def _run(tree: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, HBEVAL_ALLOW_FAULT_INJECTION="true",
               PYTHONPATH=os.pathsep.join([os.path.join(tree, "hb_eval_sdk"), tree]))
    return subprocess.run([sys.executable, os.path.join(tree, "tests", "fault_injection", "conformance.py")],
                          capture_output=True, text=True, env=env, timeout=300)


def _copy() -> str:
    d = tempfile.mkdtemp(prefix="mut_")
    tree = os.path.join(d, "t")
    shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns("__pycache__", ".git", "dist", "build", "*.egg-info"))
    return tree


def main() -> int:
    bad = 0
    base_tree = _copy()
    base = _run(base_tree)
    print(f"  baseline (unmodified)                                   exit={base.returncode}"
          f"  {'OK' if base.returncode == 0 else 'BROKEN — cannot judge mutations'}")
    shutil.rmtree(os.path.dirname(base_tree), ignore_errors=True)
    if base.returncode != 0:
        print(base.stdout[-1500:]); return 1
    for name, rel, subs in MUTATIONS:
        tree = _copy()
        path = os.path.join(tree, rel)
        src = open(path, encoding="utf-8", newline="").read()
        for pat, rep in subs:
            found = len(re.findall(pat, src))
            if found != 1:
                print(f"  FAIL  {name}\n        mutation pattern matched {found}x (need exactly 1): the check is stale")
                bad += 1; break
            src = re.sub(pat, rep, src)
        else:
            open(path, "w", encoding="utf-8", newline="").write(src)
            r = _run(tree)
            failed = re.findall(r"FAIL\s+(\S[^\n]*?)\s{2,}", r.stdout)
            caught = r.returncode != 0
            print(f"  {'CAUGHT' if caught else 'MISSED'}  {name}")
            if caught:
                print(f"          red rows: {', '.join(f.strip() for f in failed) or '(suite error)'}")
            else:
                bad += 1
        shutil.rmtree(os.path.dirname(tree), ignore_errors=True)
    print(f"\n  {len(MUTATIONS) - bad}/{len(MUTATIONS)} mutations caught")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
