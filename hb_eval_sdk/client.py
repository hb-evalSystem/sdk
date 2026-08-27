"""
HB-Eval SDK — the client.

This client implements docs/PROTOCOL.md exactly. The three v2.0.0 contract
bugs are fixed here in coordination with the Gateway:

  1. Nonce (Protocol §2): 12 random bytes, transported as 24 hex chars,
     decoded back to 12 bytes for the cipher. Client and Gateway now agree.

  2. Signature (Protocol §4): HMAC-SHA256 over
     nonce_hex + "." + timestamp + "." + ciphertext_hex, keyed with a
     SEPARATE signing secret that is never transmitted. Client and Gateway
     build the identical string with the identical key.

  3. Validation (Protocol §5): every payload is validated locally before
     encryption, so malformed or adversarial input never even leaves the
     client.

The signing secret is a distinct credential from the API key. You receive
both when you create a project. The API key identifies you on every request;
the signing secret never travels — it only proves, via the signature, that
the request genuinely came from someone holding it.
"""

import json
import base64
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from .exceptions import (
    ConnectionError,
    AuthenticationError,
    EncryptionError,
    SafeHaltError,
)
from .models import EvaluationResult, MemoryMatch, Metrics, Verdict
from .utils import (
    generate_nonce_bytes,
    nonce_to_hex,
    generate_timestamp,
    compute_signature,
)
from .validation import validate_payload
import time


class HBEvalClient:
    """
    Client for the HB-Eval reliability Gateway.

    Args:
        api_key:        Project API key (sent as a bearer token to identify you).
        aes_key:        Base64-encoded 32-byte AES-256 key (encrypts the payload).
        signing_secret: Base64-encoded signing secret (signs the request; never sent).
        gateway_url:    Override the default Gateway URL.
        timeout:        Per-request timeout in seconds.
        max_retries:    Network-failure retries before a mandatory Safe Halt.

    The three credentials are issued together when a project is created. Keep
    the AES key and the signing secret confidential; only the API key is ever
    transmitted, and even it travels over TLS.
    """

    def __init__(
        self,
        api_key: str,
        aes_key: str,
        signing_secret: str,
        gateway_url: str = None,
        timeout: int = None,
        max_retries: int = None,
    ):
        if not api_key or not isinstance(api_key, str):
            raise EncryptionError("api_key is required and must be a string.")

        self.api_key = api_key
        self.timeout = timeout or config.DEFAULT_TIMEOUT
        self.max_retries = max_retries or config.DEFAULT_MAX_RETRIES
        self.gateway_url = (gateway_url or config.DEFAULT_GATEWAY_URL).rstrip("/")

        # Decode and validate the AES key — must be exactly 32 bytes (AES-256).
        try:
            self.aes_key = base64.b64decode(aes_key)
        except Exception as exc:
            raise EncryptionError(f"AES key is not valid base64: {exc}")
        if len(self.aes_key) != 32:
            raise EncryptionError(
                f"AES key must be 32 bytes after base64 decoding (got {len(self.aes_key)})."
            )

        # Decode the SEPARATE signing secret. This is the key fix for the
        # signature design: it is independent of the API key and never sent.
        if not signing_secret or not isinstance(signing_secret, str):
            raise EncryptionError(
                "signing_secret is required. It is issued alongside your API key "
                "and AES key when you create a project, and must never be transmitted."
            )
        try:
            self.signing_secret = base64.b64decode(signing_secret)
        except Exception as exc:
            raise EncryptionError(f"signing_secret is not valid base64: {exc}")
        if len(self.signing_secret) < 32:
            raise EncryptionError(
                "signing_secret must be at least 32 bytes after base64 decoding."
            )

    # ── encryption (Protocol §2) ────────────────────────────────────────────

    def _encrypt(self, payload: dict) -> tuple[str, str]:
        """
        Encrypt the payload with AES-256-GCM.

        Returns (nonce_hex, ciphertext_hex). The nonce is 12 raw bytes used
        directly by the cipher; nonce_hex is only its 24-char transport form.
        """
        nonce_bytes = generate_nonce_bytes()          # exactly 12 bytes
        nonce_hex = nonce_to_hex(nonce_bytes)          # 24 hex chars for transport
        aesgcm = AESGCM(self.aes_key)
        plaintext = json.dumps(payload).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce_bytes, plaintext, None)   # 12-byte nonce
        return nonce_hex, ciphertext.hex()

    # ── headers (Protocol §3, §4) ───────────────────────────────────────────

    def _build_headers(self, nonce_hex: str, timestamp: str, ciphertext_hex: str) -> dict:
        """
        Build request headers including the canonical signature.

        The signature covers nonce, timestamp, AND ciphertext, keyed with the
        separate signing secret (Protocol §4). Tampering with any of the three
        transmitted values invalidates it.
        """
        signature = compute_signature(self.signing_secret, nonce_hex, timestamp, ciphertext_hex)
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-HBEval-Nonce": nonce_hex,
            "X-HBEval-Timestamp": timestamp,
            "X-HBEval-Signature": signature,
            "X-HBEval-Protocol": config.PROTOCOL_VERSION,
            "Content-Type": "application/json",
        }

    # ── public API ──────────────────────────────────────────────────────────

    def evaluate(self, payload: dict, max_retries: int = None) -> EvaluationResult:
        """
        Evaluate an agent trajectory and return its reliability result.

        The payload is validated locally (Protocol §5) before anything is
        encrypted or sent — a malformed payload raises ValidationError
        immediately, with no network call. On network failure, the client
        retries up to max_retries times and then raises SafeHaltError, because
        a reliability system must fail closed rather than proceed unevaluated.
        """
        # Local validation first — defense in depth, fast clear errors.
        validate_payload(payload)

        retries = max_retries if max_retries is not None else self.max_retries
        for attempt in range(retries + 1):
            try:
                nonce_hex, ciphertext_hex = self._encrypt(payload)
                timestamp = generate_timestamp()
                headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)

                response = requests.post(
                    f"{self.gateway_url}/evaluate",
                    json={"ciphertext": ciphertext_hex},
                    headers=headers,
                    timeout=self.timeout,
                )

                if response.status_code == 401:
                    raise AuthenticationError("Invalid API key.")
                if response.status_code == 403:
                    raise AuthenticationError("Invalid signature or expired request.")
                if response.status_code == 429:
                    # Surface the limit message, which is safe and user-facing.
                    raise ConnectionError(self._safe_detail(response, "Monthly evaluation limit reached."))
                if response.status_code != 200:
                    # Fail closed and quiet — do not leak the raw Gateway body (Issue 5).
                    raise ConnectionError(
                        f"Evaluation failed with status {response.status_code}."
                    )

                return self._parse_result(response.json())

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                if attempt < retries:
                    time.sleep(1 * (attempt + 1))
                    continue
                raise SafeHaltError(
                    f"Connection to the reliability core lost after {retries + 1} attempt(s). "
                    "Safe Halt enforced: the agent must not proceed unevaluated."
                ) from exc
            except (AuthenticationError, EncryptionError, SafeHaltError):
                raise
            except ConnectionError:
                raise
            except Exception as exc:
                # Unknown failure — fail closed without echoing internals.
                raise ConnectionError("An unexpected error occurred during evaluation.") from exc

    def evaluate_with_battery(
        self,
        base_task: dict,
        agent_runner,
        n_scenarios: int = 18,
        required_in_response: list = None,
        seed: int = None,
        fault_types: list = None,
        domains: list = None,
        max_retries: int = None,
    ) -> dict:
        """Local active evaluation (path B, free).

        Runs YOUR agent locally across a fault-injection battery, then sends
        the raw per-scenario responses to the Gateway, which scores all five
        metrics and decides the verdict server-side (tamper-resistant). The
        result is marked 'unverified' because the platform did not run the
        agent itself.

        Args:
            base_task: {"system": str, "question": str,
                        "required_in_response": [optional list]}
            agent_runner: callable(system_prompt, question) -> response_text.
                          You run your own agent here; the SDK never sees its
                          credentials, only its text output.
            n_scenarios: battery size (clamped to [6, 60]).
            fault_types: restrict to these fault types. Omit for the full
                taxonomy, which is the default because full coverage is the
                point of the battery. Narrowing is a real reduction in
                coverage, so a result from a narrowed run is not comparable
                with a full one — preview a selection at
                https://hbeval.com/dashboard/studio before committing to it.
            domains: restrict to these domains. Same caveat.

        Returns the comprehensive report (verdict, aggregate metrics,
        reliability gap, per-scenario detail).
        """
        from .battery import run_local_battery, battery_spec_fingerprint

        scenario_results = run_local_battery(
            base_task, agent_runner, n_scenarios, seed=seed,
            fault_types=fault_types, domains=domains,
        )
        required = required_in_response or base_task.get("required_in_response", [])

        payload = {
            "scenario_results": scenario_results,
            "required_in_response": required,
            "agent_id": base_task.get("agent_id", "local-battery-agent"),
            # Recorded so a narrowed battery is stored as narrowed. Without
            # this, a two-fault run and a six-fault run look identical in the
            # history and would be compared as though they were.
            "selection": ({"fault_types": fault_types, "domains": domains}
                          if (fault_types or domains) else None),
            # Fingerprint of the battery specification this client ran. The
            # Gateway compares it with its own: if the two have drifted, the
            # local and verified paths are no longer stressing agents
            # identically, and the report says so instead of presenting
            # incomparable numbers as comparable.
            "battery_spec": battery_spec_fingerprint(),
        }

        retries = max_retries if max_retries is not None else self.max_retries
        for attempt in range(retries + 1):
            try:
                nonce_hex, ciphertext_hex = self._encrypt(payload)
                timestamp = generate_timestamp()
                headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)
                response = requests.post(
                    f"{self.gateway_url}/evaluate_battery",
                    json={"ciphertext": ciphertext_hex},
                    headers=headers, timeout=self.timeout,
                )
                if response.status_code == 401:
                    raise AuthenticationError("Invalid API key.")
                if response.status_code == 403:
                    raise AuthenticationError("Invalid signature or expired request.")
                if response.status_code == 429:
                    raise ConnectionError(self._safe_detail(response, "Monthly limit reached."))
                if response.status_code != 200:
                    raise ConnectionError(f"Battery evaluation failed with status {response.status_code}.")
                return response.json()
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                if attempt < retries:
                    time.sleep(1 * (attempt + 1))
                    continue
                raise SafeHaltError(
                    f"Connection lost after {retries + 1} attempt(s). Safe Halt enforced."
                ) from exc
            except (AuthenticationError, EncryptionError, SafeHaltError, ConnectionError):
                raise
            except Exception as exc:
                raise ConnectionError("An unexpected error occurred during battery evaluation.") from exc

    def request_verified_evaluation(
        self,
        agent_url: str,
        base_task: dict,
        consent: bool,
        n_scenarios: int = 30,
        agent_headers: dict = None,
        required_in_response: list = None,
        max_retries: int = None,
    ) -> dict:
        """Verified active evaluation (path A, paid).

        The PLATFORM calls your agent endpoint across the fault battery, so the
        result cannot be tampered with and is marked 'verified'. Requires a
        paid plan and EXPLICIT consent (the platform will make outbound calls
        to your agent). The agent URL must be a public HTTPS endpoint; internal
        addresses are refused (SSRF protection).

        Args:
            agent_url: public HTTPS endpoint of your agent.
            consent: must be True — you authorise the platform to call it.
            n_scenarios: up to 100 (full CSI on the paid path).
        """
        if not consent:
            from .exceptions import ValidationError
            raise ValidationError(
                "consent=True is required: the platform will call your agent endpoint."
            )

        payload = {
            "agent_url": agent_url,
            "base_task": base_task,
            "n_scenarios": n_scenarios,
            "consent": True,
            "agent_headers": agent_headers or {},
            "required_in_response": required_in_response or base_task.get("required_in_response", []),
            "agent_id": base_task.get("agent_id", "verified-agent"),
        }

        retries = max_retries if max_retries is not None else self.max_retries
        for attempt in range(retries + 1):
            try:
                nonce_hex, ciphertext_hex = self._encrypt(payload)
                timestamp = generate_timestamp()
                headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)
                response = requests.post(
                    f"{self.gateway_url}/evaluate_verified",
                    json={"ciphertext": ciphertext_hex},
                    headers=headers, timeout=self.timeout,
                )
                if response.status_code == 401:
                    raise AuthenticationError("Invalid API key.")
                if response.status_code == 402:
                    raise ConnectionError(self._safe_detail(
                        response, "The verified path requires a paid plan."))
                if response.status_code == 403:
                    raise AuthenticationError("Invalid signature or expired request.")
                if response.status_code == 400:
                    raise ConnectionError(self._safe_detail(
                        response, "Agent URL rejected or consent missing."))
                if response.status_code != 200:
                    raise ConnectionError(f"Verified evaluation failed with status {response.status_code}.")
                return response.json()
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                if attempt < retries:
                    time.sleep(1 * (attempt + 1))
                    continue
                raise SafeHaltError(
                    f"Connection lost after {retries + 1} attempt(s). Safe Halt enforced."
                ) from exc
            except (AuthenticationError, EncryptionError, SafeHaltError, ConnectionError):
                raise
            except Exception as exc:
                raise ConnectionError("An unexpected error occurred during verified evaluation.") from exc

    def retrieve_memory(self, context: str, project_id: str = None, top_k: int = 5) -> list:
        """
        Retrieve semantically similar past episodes from EDM.

        Free-plan projects receive up to 3 matches; paid plans up to top_k.
        """
        if not isinstance(context, str) or not context.strip():
            from .exceptions import ValidationError
            raise ValidationError("context is required and must be a non-empty string.")

        if project_id is None:
            project_id = config.DEFAULT_PROJECT_ID

        nonce_hex, ciphertext_hex = self._encrypt(
            {"context": context, "project_id": project_id, "top_k": top_k}
        )
        timestamp = generate_timestamp()
        headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)

        try:
            response = requests.post(
                f"{self.gateway_url}/api/v1/memory/retrieve",
                json={"ciphertext": ciphertext_hex},
                headers=headers,
                timeout=self.timeout,
            )
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            raise ConnectionError("Could not reach the memory service.") from exc

        if response.status_code != 200:
            raise ConnectionError(f"Memory retrieval failed with status {response.status_code}.")

        data = response.json()
        return [MemoryMatch(**m) for m in data.get("memories", data.get("matches", []))]

    def explain(self, plan_summary: str) -> dict:
        """Explain a decision, grounded in a qualified recorded episode.

        Calls the Gateway's HCI-EDM interpretability layer. The explanation
        cites a specific stored episode that cleared the reliability bar,
        together with that episode's real recorded metrics — it is not a
        rationale generated after the fact. When no sufficiently similar
        qualified precedent exists, the Gateway returns an explicit
        uncertainty response deferring to human review rather than inventing
        a plausible-sounding reason.
        """
        if not isinstance(plan_summary, str) or not plan_summary.strip():
            from .exceptions import ValidationError
            raise ValidationError("plan_summary is required and must be a non-empty string.")

        nonce_hex, ciphertext_hex = self._encrypt({"plan_summary": plan_summary})
        timestamp = generate_timestamp()
        headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)

        try:
            response = requests.post(
                f"{self.gateway_url}/api/v1/explain",
                json={"ciphertext": ciphertext_hex},
                headers=headers,
                timeout=self.timeout,
            )
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            raise ConnectionError("Could not reach the interpretability service.") from exc

        if response.status_code != 200:
            raise ConnectionError(f"Explanation failed with status {response.status_code}.")

        return response.json()

    def set_observatory_contribution(self, enabled: bool) -> dict:
        """Opt this account in or out of the public Observatory.

        The Observatory publishes AGGREGATE reliability statistics across
        deployments, so the field can see what operational reliability looks
        like in practice rather than only in controlled studies.

        Contribution is OFF until you turn it on here. When enabled, a
        completed monitoring session contributes an anonymised row: the five
        metric values, a bucketed step count, which metrics breached, and
        whether the run halted.

        What is never sent: your agent identifier, your account identifier,
        your session metadata, and your step labels. Those are dropped before
        the contribution is written, so they are absent from the public table
        rather than merely hidden from the public page. Published figures are
        additionally withheld until enough distinct accounts contribute, so no
        statistic can be traced to a single deployment.

        Args:
            enabled: True to contribute, False to stop.

        Returns:
            The stored preference.
        """
        nonce_hex, ciphertext_hex = self._encrypt({"enabled": bool(enabled)})
        timestamp = generate_timestamp()
        headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)

        try:
            response = requests.post(
                f"{self.gateway_url}/api/v1/observatory/consent",
                json={"ciphertext": ciphertext_hex},
                headers=headers,
                timeout=self.timeout,
            )
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            raise ConnectionError("Could not reach the Observatory service.") from exc

        if response.status_code != 200:
            raise ConnectionError(
                f"Setting Observatory contribution failed with status {response.status_code}."
            )

        return response.json()

    def get_trend(self, agent_id: str, window: int = 20) -> dict:
        """Return an agent's reliability trend over its monitoring history.

        Answers "is this agent getting more or less reliable over time?" —
        a question a single point-in-time verdict cannot address. Reads the
        monitoring sessions recorded by monitor(), aggregated server-side.
        """
        if not isinstance(agent_id, str) or not agent_id.strip():
            from .exceptions import ValidationError
            raise ValidationError("agent_id is required and must be a non-empty string.")

        nonce_hex, ciphertext_hex = self._encrypt(
            {"agent_id": agent_id, "window": int(window)}
        )
        timestamp = generate_timestamp()
        headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)

        try:
            response = requests.post(
                f"{self.gateway_url}/api/v1/monitoring/trend",
                json={"ciphertext": ciphertext_hex},
                headers=headers,
                timeout=self.timeout,
            )
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            raise ConnectionError("Could not reach the monitoring service.") from exc

        if response.status_code != 200:
            raise ConnectionError(f"Trend retrieval failed with status {response.status_code}.")

        return response.json()

    def monitor(
        self,
        agent_id: str,
        *,
        thresholds: dict = None,
        on_threshold_breach=None,
        halt_signal=None,
        halt_policy: dict = None,
        policies: list = None,
        tool_policy: dict = None,
        send_summary: bool = True,
        stream: bool = True,
        batch_size: int = 5,
        flush_interval: float = 2.0,
        **session_metadata,
    ):
        """Open a runtime monitoring session over a live agent run.

        Unlike evaluate_with_battery (which judges a run after it finishes),
        this observes the agent step by step WHILE it executes, recomputing
        live reliability signals after each recorded step so degradation is
        detected at the moment it happens rather than afterwards.

        Per-step computation is local and in-process: real-time monitoring
        cannot afford a network round-trip per step, and running locally is
        also why basic monitoring costs nothing. On close, the session
        summary is sent to the Gateway for storage, trend history, and (once
        managed alerting ships) webhook dispatch.

        Args:
            agent_id: identifier of the agent being monitored.
            thresholds: per-metric floors; merged over the defaults
                (see monitoring.DEFAULT_THRESHOLDS).
            on_threshold_breach: callback(metric, value, floor, session)
                invoked the moment a metric crosses its floor.
            halt_signal: callable(session) -> bool consulted by
                session.should_halt, for stop logic a declarative policy
                cannot express.
            halt_policy: declarative Safe Halt rule, e.g.
                {"metric": "frr", "below": 0.5, "for_steps": 3}. The metric
                must stay below the value for that many CONSECUTIVE steps
                before the session halts, so a single noisy dip does not stop
                a healthy agent. Omit it and the session only observes.

                The halt is cooperative: the SDK sets session.should_halt and
                your loop must check it and break. Nothing is killed for you —
                terminating a thread mid-step could leave a transaction half
                applied, which is the damage the halt exists to prevent.
            send_summary: set False to keep the session entirely local.
            stream: push progress to the Gateway DURING the run so the
                dashboard updates live. Sending happens on a background
                thread, never on the agent's execution path. Set False to
                report only once, at session close.
            batch_size: how many queued frames trigger a send. A threshold
                breach always sends immediately regardless of this.
            flush_interval: maximum seconds between sends, so a slow agent
                still reports progress.
            **session_metadata: arbitrary labels stored with the session.

        Args (beyond the originals):
            policies: rules that raise a directive when a metric stays below a
                floor, e.g.
                    [{"when": {"metric": "frr", "below": 0.5, "for_steps": 3},
                      "then": "halt"}]
                Actions: halt, escalate, retry. Read session.directive to
                consume one — reading clears it, so a loop cannot act on the
                same signal twice.
            tool_policy: circuit breaker per tool, e.g.
                    {"failures_before_open": 3, "probe_after_steps": 10}
                session.unreliable_tools then lists tools whose breaker is
                open. Advisory: the call is reported, never blocked.

        Both default to off. Acquiring the ability to retry or escalate by
        upgrading a library is not something anyone should get by surprise.

        Usage:
            with client.monitor(agent_id="my-agent") as m:
                for step in agent.run(task):
                    m.record_step(action=step.name, success=step.ok)
                    if m.should_halt:
                        break
            print(m.summary)
        """
        from .monitoring import MonitorSession

        return MonitorSession(
            self,
            agent_id,
            thresholds=thresholds,
            on_threshold_breach=on_threshold_breach,
            halt_signal=halt_signal,
            halt_policy=halt_policy,
            policies=policies,
            tool_policy=tool_policy,
            send_summary=send_summary,
            stream=stream,
            batch_size=batch_size,
            flush_interval=flush_interval,
            session_metadata=session_metadata or None,
        )

    def _send_monitoring_batch(self, batch: dict) -> None:
        """Send one live progress batch for an in-flight monitoring session.

        Called ONLY from the monitoring background thread — never from the
        agent's execution path — so its latency does not slow the run being
        observed.

        Encrypted and signed with the same envelope as every other call, so
        live telemetry is protected exactly like evaluation data.

        Raises on failure so the session can count send errors and surface
        them via session.streaming_stats. The caller catches; a dashboard that
        silently stops updating is worse than one whose staleness is visible.
        """
        nonce_hex, ciphertext_hex = self._encrypt(batch)
        timestamp = generate_timestamp()
        headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)
        response = requests.post(
            f"{self.gateway_url}/api/v1/monitoring/stream",
            json={"ciphertext": ciphertext_hex},
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise ConnectionError(
                f"Monitoring stream rejected with status {response.status_code}."
            )

    def _send_monitoring_summary(self, summary: dict) -> None:
        """Send a closed monitoring session to the Gateway.

        Encrypted and signed with the same envelope as every other call, so
        monitoring data is protected exactly like evaluation data.

        Deliberately fail-soft: monitoring must never be the reason a user's
        agent run breaks. If the endpoint is unavailable (older Gateway) or
        the network is down, the local session still holds its full summary
        and the caller can read it from session.summary.
        """
        try:
            nonce_hex, ciphertext_hex = self._encrypt(summary)
            timestamp = generate_timestamp()
            headers = self._build_headers(nonce_hex, timestamp, ciphertext_hex)
            requests.post(
                f"{self.gateway_url}/api/v1/monitoring/session",
                json={"ciphertext": ciphertext_hex},
                headers=headers,
                timeout=self.timeout,
            )
        except Exception:
            # Intentionally swallowed: see docstring.
            return

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_detail(response, fallback: str) -> str:
        """Extract a user-safe 'detail' string from a response, never raw internals."""
        try:
            detail = response.json().get("detail")
            if isinstance(detail, str) and detail:
                return detail
        except Exception:
            pass
        return fallback

    @staticmethod
    def _parse_result(data: dict) -> EvaluationResult:
        """
        Build an EvaluationResult from the Gateway response (Protocol §7).

        All five metrics are read. A null metric stays None — never coerced
        to 0.0 — so the caller can distinguish "undefined" from "scored zero".
        """
        metrics_data = data.get("metrics", {}) or {}
        return EvaluationResult(
            verdict=Verdict(data.get("verdict", "UNSAFE")),
            metrics=Metrics(
                pei=metrics_data.get("pei"),
                irs=metrics_data.get("irs"),
                frr=metrics_data.get("frr"),
                ti=metrics_data.get("ti"),
                csi=metrics_data.get("csi"),
            ),
            tier=data.get("tier"),
            certified=data.get("certified", False),
            safe_halt=data.get("safe_halt", False),
            memory_hit=data.get("memory_hit", False),
            run_id=data.get("run_id"),
            reason=data.get("reason"),
            note=data.get("note"),
            guidance=data.get("guidance"),
        )