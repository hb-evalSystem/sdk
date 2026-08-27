"""
HB-Eval SDK — Basic Usage Example

Replace the three placeholder credentials with your project's real values
before running. All three are issued together when your project is created:
    - api_key:        identifies your project (sent on each request)
    - aes_key:        base64 32-byte key (encrypts your payload)
    - signing_secret: base64 secret (signs your request; never transmitted)
"""

import os
from hb_eval_sdk import HBEvalClient
from hb_eval_sdk.exceptions import (
    SafeHaltError, AuthenticationError, ConnectionError, ValidationError,
)

API_KEY = os.getenv("HBEVAL_API_KEY", "your_api_key_here")
AES_KEY = os.getenv("HBEVAL_AES_KEY", "your_base64_32byte_aes_key_here")
SIGNING_SECRET = os.getenv("HBEVAL_SIGNING_SECRET", "your_base64_signing_secret_here")


def main():
    client = HBEvalClient(
        api_key=API_KEY,
        aes_key=AES_KEY,
        signing_secret=SIGNING_SECRET,
    )

    payload = {
        "trajectory": [
            {"step": 1, "action": "chain_start", "input": "Find the top 3 Python NLP libraries."},
            {"step": 2, "action": "tool_call", "tool": "web_search", "input": "top Python NLP libraries"},
            {"step": 3, "action": "chain_end", "output": "spaCy, Transformers, NLTK."},
        ],
        "sub_tasks": 3,
        "constraint_violations": 0,
        "recovery_episodes": [],   # no faults in this run
        "agent_id": "demo-agent-001",
    }

    try:
        result = client.evaluate(payload)
        print(f"Verdict   : {result.verdict.value}")
        print(f"Tier      : {result.tier}")
        print(f"Certified : {result.certified}")
        print(f"PEI       : {result.metrics.pei}")
        print(f"IRS       : {result.metrics.irs}")   # None here — no faults to recover from
        print(f"FRR       : {result.metrics.frr}")
        print(f"TI        : {result.metrics.ti}")
        print(f"CSI       : {result.metrics.csi}")
        print(f"Run ID    : {result.run_id}")
        if result.note:
            print(f"Note      : {result.note}")
    except ValidationError as e:
        print(f"[VALIDATION] {e}")        # caught locally, before any network call
    except SafeHaltError as e:
        print(f"[SAFE HALT] {e} (reason: {e.reason})")
    except AuthenticationError as e:
        print(f"[AUTH] {e}")
    except ConnectionError as e:
        print(f"[CONNECTION] {e}")


if __name__ == "__main__":
    main()
