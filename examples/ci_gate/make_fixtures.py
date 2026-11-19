"""Regenerate the example gate inputs from the test fixtures.
    PYTHONPATH=hb_eval_sdk:. python examples/ci_gate/make_fixtures.py
The committed JSON files let anyone run the gate with no credentials and no network:
    hb-eval gate --reference-baseline examples/ci_gate/ref.json \
                 --candidate-baseline examples/ci_gate/cand.json \
                 --slo-policy examples/ci_gate/policy_pass.json --enforce
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path[:0] = [os.path.join(ROOT, "hb_eval_sdk"), ROOT, os.path.join(ROOT, "tests", "baseline")]
from hb_eval_sdk.battery import battery_spec_fingerprint                       # noqa: E402
from test_comparability import baseline as _baseline, _rebuild as _rb          # noqa: E402


def _w(name, obj):
    with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True); fh.write("\n")


a = _baseline()
ok = _rb(a, metrics=tuple((n, (0.9 if n == "frr" else v), ver, p) for n, v, ver, p in a.metrics),
         envelope_hash="sha256:" + "77" * 32)
bad = _rb(a, battery_spec_fingerprint="a-different-spec", envelope_hash="sha256:" + "88" * 32)
_w("ref.json", a.to_dict()); _w("cand.json", ok.to_dict()); _w("cand_incomparable.json", bad.to_dict())
_w("policy_pass.json", {"policy_version": "example-v1", "conditions": [
    {"metric_name": "frr", "comparator": "gte", "threshold": 0.80}]})
_w("policy_fail.json", {"policy_version": "example-v1", "conditions": [
    {"metric_name": "frr", "comparator": "gte", "threshold": 0.99}]})
print("wrote 5 files; battery fingerprint", battery_spec_fingerprint())
