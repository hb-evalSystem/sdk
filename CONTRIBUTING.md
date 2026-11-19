# Contributing to hb-eval-sdk

1. **Run the suite the way CI does**
   `HBEVAL_ALLOW_FAULT_INJECTION=true PYTHONPATH=hb_eval_sdk:. pytest tests` — currently 730.
   Also run `python tests/fault_injection/conformance.py` and `python tests/fault_injection/mutation_check.py`.
   CI (`.github/workflows/ci.yml`) runs all of this on Python 3.9–3.13 plus bandit, pip-audit and a build check;
   a pull request should be green there before review.
2. **A claim needs a check.** A change that says it closes something must come
   with a test that fails when the thing is broken (see how `conformance.py`
   treats its own probe). A test that has never been seen to fail has not been
   shown to work.
3. **Metric definitions do not move quietly.** Changing how a metric is computed
   requires a new `SCORING_VERSION`; the battery fingerprint must not change
   unless the battery changes on purpose.
4. **Say what it does not do.** New modules state their limits in the module
   docstring and in `CHANGELOG.md`, in the same change.
5. **No secrets in the tree.** Keys come from environment variables.
