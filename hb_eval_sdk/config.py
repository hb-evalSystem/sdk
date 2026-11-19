"""
HB-Eval SDK — default configuration.

These are defaults only; every value can be overridden via the HBEvalClient
constructor or environment variables. The gateway URL points to the
production deployment on Railway.
"""

DEFAULT_GATEWAY_URL = "https://hbeval-reliability-os-production.up.railway.app"
DEFAULT_TIMEOUT = 10          # seconds per request
DEFAULT_MAX_RETRIES = 2       # network-failure retries before Safe Halt
DEFAULT_PROJECT_ID = "00000000-0000-0000-0000-000000000001"

# WIRE protocol this SDK speaks. 2.8.0 = 2.7.0 plus the additive enforcement surface
# (see docs/PROTOCOL.md §8). The Gateway advertises its own in the X-HBEval-Protocol
# response header; hb_eval_sdk.protocol compares major.minor and the client warns on
# a mismatch. Patch never matters.
PROTOCOL_VERSION = "2.8.0"
# MEASUREMENT protocol: stamps passports and baselines. Unchanged — nothing about how
# a metric is computed changed in 2.13.0. Do NOT bump this for a new endpoint.
MEASUREMENT_PROTOCOL_VERSION = "2.7.0"