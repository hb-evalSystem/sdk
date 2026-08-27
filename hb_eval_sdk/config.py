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

# Protocol version this SDK implements. The Gateway advertises its own; a
# mismatch in the major.minor component is a compatibility warning.
PROTOCOL_VERSION = "2.7.0"