"""
HB-Eval SDK — cryptographic and helper primitives.

Every function here implements a specific clause of docs/PROTOCOL.md.
The nonce handling in particular is the corrected version: a nonce is
12 bytes, and hex is only its transport encoding (Protocol §2).
"""

import secrets
import time
import hmac
import hashlib


# Protocol §2 — AES-256-GCM nonce length in bytes (NIST-recommended 96 bits).
NONCE_BYTES = 12


def generate_nonce_bytes() -> bytes:
    """
    Generate exactly 12 cryptographically secure random bytes.

    These 12 bytes ARE the AES-GCM nonce. They are transported as 24 hex
    characters, but the cipher always operates on these 12 raw bytes. This
    is the single fix for the v2.0.0 nonce-length defect, where the old code
    fed 24 bytes (the hex string re-encoded) into a cipher expecting 12.
    """
    return secrets.token_bytes(NONCE_BYTES)


def nonce_to_hex(nonce_bytes: bytes) -> str:
    """Encode the 12-byte nonce as a 24-character lowercase hex string for transport."""
    return nonce_bytes.hex()


def generate_timestamp() -> str:
    """Return the current Unix time in whole seconds, as a string (Protocol §3)."""
    return str(int(time.time()))


def compute_signature(signing_secret: bytes, nonce_hex: str, timestamp: str, ciphertext_hex: str) -> str:
    """
    Compute the canonical HMAC-SHA256 signature defined in Protocol §4.

    The signed message is the exact concatenation:
        nonce_hex + "." + timestamp + "." + ciphertext_hex

    The key is the SEPARATE signing secret — never the API key, never a hash
    of the API key. The ciphertext is included so that tampering with the
    encrypted payload invalidates the signature.
    """
    message = f"{nonce_hex}.{timestamp}.{ciphertext_hex}".encode("utf-8")
    return hmac.new(signing_secret, message, hashlib.sha256).hexdigest()
