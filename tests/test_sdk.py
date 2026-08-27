"""
HB-Eval SDK — test suite.

These tests verify the protocol implementation and the validation layer
without requiring a live Gateway. They cover the three contract fixes
(nonce, signature, validation) and confirm all five metrics round-trip.
"""

import base64
import pytest

from hb_eval_sdk import (
    HBEvalClient, EvaluationResult, MemoryMatch, Metrics, Verdict,
    HBEvalError, ValidationError, EncryptionError,
)
from hb_eval_sdk.utils import (
    generate_nonce_bytes, nonce_to_hex, compute_signature, NONCE_BYTES,
)
from hb_eval_sdk.validation import validate_payload


# ── fixtures ──────────────────────────────────────────────────────────────

VALID_AES = base64.b64encode(b"x" * 32).decode()
VALID_SIGNING = base64.b64encode(b"y" * 32).decode()


def _client():
    return HBEvalClient(api_key="test-key", aes_key=VALID_AES, signing_secret=VALID_SIGNING)


def _valid_payload():
    return {
        "trajectory": [{"step": 1, "action": "chain_start"}],
        "sub_tasks": 2,
        "constraint_violations": 0,
        "recovery_episodes": [],
        "agent_id": "test-agent",
    }


# ── nonce (Protocol §2) ─────────────────────────────────────────────────────

def test_nonce_is_exactly_12_bytes():
    nonce = generate_nonce_bytes()
    assert len(nonce) == NONCE_BYTES == 12

def test_nonce_hex_is_24_chars():
    assert len(nonce_to_hex(generate_nonce_bytes())) == 24

def test_nonce_hex_round_trips_to_12_bytes():
    nonce = generate_nonce_bytes()
    assert bytes.fromhex(nonce_to_hex(nonce)) == nonce
    assert len(bytes.fromhex(nonce_to_hex(nonce))) == 12


# ── signature (Protocol §4) ─────────────────────────────────────────────────

def test_signature_is_deterministic():
    secret = b"z" * 32
    a = compute_signature(secret, "aa", "100", "bb")
    b = compute_signature(secret, "aa", "100", "bb")
    assert a == b

def test_signature_changes_with_ciphertext():
    secret = b"z" * 32
    a = compute_signature(secret, "aa", "100", "bb")
    b = compute_signature(secret, "aa", "100", "cc")
    assert a != b  # ciphertext is part of the signed message

def test_signature_changes_with_key():
    a = compute_signature(b"k" * 32, "aa", "100", "bb")
    b = compute_signature(b"j" * 32, "aa", "100", "bb")
    assert a != b


# ── client construction ─────────────────────────────────────────────────────

def test_client_requires_signing_secret():
    with pytest.raises(EncryptionError):
        HBEvalClient(api_key="k", aes_key=VALID_AES, signing_secret="")

def test_client_rejects_short_aes_key():
    short = base64.b64encode(b"tooshort").decode()
    with pytest.raises(EncryptionError):
        HBEvalClient(api_key="k", aes_key=short, signing_secret=VALID_SIGNING)

def test_client_rejects_bad_base64_aes():
    with pytest.raises(EncryptionError):
        HBEvalClient(api_key="k", aes_key="not!!base64", signing_secret=VALID_SIGNING)


# ── encryption round-trip sanity ─────────────────────────────────────────────

def test_encrypt_returns_hex_nonce_and_ciphertext():
    c = _client()
    nonce_hex, ct_hex = c._encrypt({"hello": "world"})
    assert len(nonce_hex) == 24
    bytes.fromhex(nonce_hex)   # valid hex
    bytes.fromhex(ct_hex)      # valid hex


# ── validation (Protocol §5, §6) ─────────────────────────────────────────────

def test_valid_payload_passes():
    validate_payload(_valid_payload())  # should not raise

def test_missing_trajectory_rejected():
    p = _valid_payload(); p.pop("trajectory")
    with pytest.raises(ValidationError):
        validate_payload(p)

def test_empty_trajectory_rejected():
    p = _valid_payload(); p["trajectory"] = []
    with pytest.raises(ValidationError):
        validate_payload(p)

def test_zero_sub_tasks_rejected():
    p = _valid_payload(); p["sub_tasks"] = 0
    with pytest.raises(ValidationError):
        validate_payload(p)

def test_negative_sub_tasks_rejected():
    p = _valid_payload(); p["sub_tasks"] = -3
    with pytest.raises(ValidationError):
        validate_payload(p)

def test_negative_violations_rejected():
    p = _valid_payload(); p["constraint_violations"] = -1
    with pytest.raises(ValidationError):
        validate_payload(p)

def test_ti_score_out_of_range_rejected():
    p = _valid_payload(); p["ti_score"] = 9.0
    with pytest.raises(ValidationError):
        validate_payload(p)

def test_missing_agent_id_rejected():
    p = _valid_payload(); p.pop("agent_id")
    with pytest.raises(ValidationError):
        validate_payload(p)

def test_memory_query_before_fault_rejected():
    p = _valid_payload()
    p["recovery_episodes"] = [{"fault_onset_step": 5, "memory_query_step": 2}]
    with pytest.raises(ValidationError):
        validate_payload(p)

def test_valid_recovery_episode_passes():
    p = _valid_payload()
    p["recovery_episodes"] = [{
        "fault_onset_step": 2, "recovered": True, "steps_to_recovery": 1,
        "approach_correct": True, "memory_query_step": 3,
        "memory_similarity_met": True, "modification_verified": True,
    }]
    validate_payload(p)  # should not raise


# ── models: all five metrics (Issue 4) ───────────────────────────────────────

def test_metrics_model_holds_all_five():
    m = Metrics(pei=0.9, irs=0.8, frr=0.95, ti=4.2, csi=0.88)
    assert m.pei == 0.9 and m.irs == 0.8 and m.frr == 0.95
    assert m.ti == 4.2 and m.csi == 0.88

def test_metrics_allow_none():
    m = Metrics(pei=0.9)
    assert m.irs is None and m.csi is None  # undefined stays None, not 0.0

def test_result_parses_full_response():
    data = {
        "verdict": "SAFE", "tier": 2, "certified": True,
        "metrics": {"pei": 0.9, "irs": 0.8, "frr": 0.95, "ti": 4.2, "csi": 0.88},
        "memory_hit": True, "run_id": "abc",
    }
    r = HBEvalClient._parse_result(data)
    assert r.verdict == Verdict.SAFE
    assert r.tier == 2 and r.certified is True
    assert r.metrics.csi == 0.88

def test_result_preserves_null_metrics():
    data = {"verdict": "UNSAFE", "metrics": {"pei": 0.5, "irs": None, "csi": None}}
    r = HBEvalClient._parse_result(data)
    assert r.metrics.irs is None and r.metrics.csi is None
