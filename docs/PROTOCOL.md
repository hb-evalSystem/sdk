# HB-Eval wire protocol — 2.8.0

> **Provenance.** `gateway.py` and `client.py` both cite "docs/PROTOCOL.md", but no copy of it
> existed in any repository available when SDK 2.13.0 was prepared. This document was
> **reconstructed from the code that implements it** (`client.py`, `utils.py`, `config.py`,
> `gateway.py`, `enforcement_api.py`). Where the code is the only authority, it says "see". It
> adds no behaviour; if it disagrees with the code, the code is right and this file is a bug.

## 1. Two versions, deliberately separate
| Name | Value | Meaning | Moves when |
|---|---|---|---|
| `PROTOCOL_VERSION` (wire) | **2.8.0** | which requests exist and how they are signed and shaped | an endpoint is added (minor) or an old peer would break (major) |
| `MEASUREMENT_PROTOCOL_VERSION` | **2.7.0** | the protocol the *scores* were produced under; stamps passports and baselines | how a metric is computed changes |

Results under different measurement protocols are not directly comparable. Adding an endpoint
must never change that stamp — doing so would claim a measurement change that did not happen.
2.8.0 is 2.7.0 plus the additive enforcement surface (§8); no existing request changed.

## 2. Encryption
AES-256-GCM. Key: 32 bytes (base64 on the wire configuration). Nonce: 12 random bytes per
request, transported as 24 lowercase hex characters. Ciphertext: hex of the GCM output
(ciphertext ‖ tag). Plaintext: UTF-8 JSON.

## 3. Request headers
| Header | Value |
|---|---|
| `Authorization` | `Bearer <api_key>` |
| `X-HBEval-Nonce` | 24 hex chars (§2) |
| `X-HBEval-Timestamp` | request time, seconds |
| `X-HBEval-Signature` | §4 |
| `X-HBEval-Protocol` | the SDK's wire version |

## 4. Signature
`HMAC-SHA256(signing_secret, nonce_hex + "." + timestamp + "." + ciphertext_hex)`, hex-encoded.
`signing_secret` is a **separate** secret (≥ 32 bytes) that is never transmitted and is
independent of the API key and the AES key. Altering any of the three signed values invalidates it.

## 5. Payload validation
The Gateway validates payload shape server-side **before** any computation. The rules are in
`validation.py`; they are defence in depth beside the SDK's own checks.

## 6. Recovery data
Evaluations carry `recovery_episodes` as a **list**. See `engines.py` for how it is read.

## 7. Endpoints
Signed/encrypted evaluation: `POST /evaluate`, `/evaluate_battery`, `/evaluate_verified`
(`/evaluate_plain` for the unencrypted path). Memory and explanation: `POST /api/v1/memory/retrieve`,
`/api/v1/explain`. Monitoring: `POST /api/v1/monitoring/{session,stream,trend}`,
`POST /api/v1/battery/preview`. Passports: `GET /api/v1/passport/key`, `GET /api/v1/passport/{agent_id}`,
`POST /api/v1/passport/{demo,verify}`. Observatory: `GET /api/v1/observatory`,
`POST /api/v1/observatory/consent`. Health: `GET /health`. MCP and OAuth discovery endpoints
are outside this protocol.

## 7a. Evaluation responses
`verdict` is one of `SAFE`, `UNSAFE` or `INSUFFICIENT_DATA`. `INSUFFICIENT_DATA` means the evidence cannot support
either: `unmeasured_metrics` lists what could not be measured (typically `frr`, `irs`, `ti`, because no fault occurred),
`tier` is null and `qualified` / `certified` are false. It is **never** to be read as a pass; it is the normal answer for
an agent evaluated without fault injection. Metrics that could not be measured are `null`, never `0`. A response with
no `verdict` must be treated as `UNSAFE`, and an unrecognised value as an error.

## 8. Enforcement surface (new in 2.8.0) — OFF unless the operator enables it
`POST /api/v1/enforce/decide`, `/result`, `/evidence`.
- **Authentication:** header `X-HBEval-Enforce-Key`, compared in constant time. The surface is
  **not mounted** unless the Gateway is started with `HBEVAL_ENFORCE_API_KEY` (≥ 24 chars).
  A shared secret is a stop-gap; workload identity (mTLS) between the sidecar and the Gateway is
  still an open deployment requirement.
- **`/decide`** — body: `agent_id, correlation_id, action, target, arguments, participant_id,
  agent_instance_id, execution_id, session_id?, requested_at`. Returns a decision and a
  single-use `decision_id`. `404` unknown agent; `422` unknown action.
- **`/result`** — body: `agent_id, decision_id, mechanism, outcome, observed_at, detail?`.
  Seals the observed outcome as an enforcement event. A `decision_id` can be used once (`404`
  after); unknown mechanism `422`; contract violation `409`.
- **`/evidence`** — body: `agent_id` (+ optional tool logs). Returns the operational log, lineage
  validity and the derived operational passport. The Gateway adds no interpretation.
- The Gateway holds **no decision logic**: decisions come from the SDK (`hb_eval_sdk.enforcement`).

## 9. Compatibility
The Gateway advertises its wire version in the `X-HBEval-Protocol` **response** header; the SDK
compares it once per client (`hb_eval_sdk.protocol`).
| Difference | Level | SDK behaviour |
|---|---|---|
| major | `incompatible` | `ProtocolMismatchWarning` |
| minor | `warn` | `ProtocolMismatchWarning` (endpoints may be missing on one side) |
| patch | `ok` | silent |
| peer sent nothing / unreadable | `unknown` | silent; `client.protocol_compatibility` records it. **Never reported as ok.** |

Gateways older than 2.8.0 do not advertise, so an SDK talking to one sees `unknown`.

## 10. Not covered
No machine-readable conformance vectors exist yet for §2–§4. Adding them is the way to let a
third-party implementation prove it speaks this protocol.
