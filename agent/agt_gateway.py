"""Shared Agent Governance Toolkit (AGT) action gateway.

This module is intentionally tiny and import-safe. It is the code boundary used
by runtime call sites before they dispatch actions, accept async results, ingest
CLI text, write proof/state, or emit final completion claims.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from hermes_constants import get_hermes_home

AGT_AUDIT_LOG_NAME = "agt_action_gateway.jsonl"

AGT_POLICIES = frozenset(
    {
        "proof.required_for_done",
        "builder_only_code_mutation",
        "no_child_self_report_as_proof",
        "no_receipt_only_role_start_as_execution_proof",
        "parent_owned_proof_write",
        "no_terminal_junk_as_user_intent",
        "remote_target_requires_ssh",
        "remote_mutation_requires_approval",
        "robot_hand_discovery_required",
        "codegraph_current_before_edit",
        "model_inherit_controller_default",
        "stale_async_quarantine",
    }
)

RECEIPT_ONLY_EVIDENCE = frozenset(
    {
        "pid",
        "local_process",
        "spawn_receipt",
        "spawn_receipt_only",
        "receipt_only",
    }
)

PROTECTED_TARGET_ROOTS = ("/etc", "/opt", "/root")


@dataclass(frozen=True)
class AGTDecision:
    """Decision returned by the shared AGT gateway."""

    decision: str
    action: str
    caller: str
    policy: str
    reason: str
    state_hash: str
    target: str = ""
    override_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    audit_path: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def blocked(self) -> bool:
        return self.decision in {"deny", "quarantine"}

    def error_message(self) -> str:
        prefix = "AGT QUARANTINED" if self.decision == "quarantine" else "AGT DENIED"
        return f"{prefix}: policy={self.policy} action={self.action} reason={self.reason}"


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, Mapping):
            return {str(k): _json_safe(v) for k, v in value.items()}
        if isinstance(value, (set, tuple, list)):
            return [_json_safe(v) for v in value]
        return str(value)


def _audit_path() -> Path:
    path = get_hermes_home() / "logs" / AGT_AUDIT_LOG_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _state_hash(state: Mapping[str, Any] | None, metadata: Mapping[str, Any]) -> str:
    explicit = metadata.get("state_hash") if isinstance(metadata, Mapping) else None
    if explicit:
        return str(explicit)
    payload = {"state": _json_safe(dict(state or {})), "metadata": _json_safe(dict(metadata or {}))}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_audit(decision: AGTDecision) -> AGTDecision:
    path = _audit_path()
    event = asdict(decision)
    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    for key in ("remote_target", "attempted_path", "attempted_command", "role", "session_id"):
        if key in metadata and key not in event:
            event[key] = metadata[key]
    event["ts"] = time.time()
    event["audit_path"] = str(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
    return AGTDecision(**{**asdict(decision), "audit_path": str(path)})


def _looks_protected_path(value: str) -> bool:
    if not value:
        return False
    try:
        path = str(Path(value).expanduser())
    except Exception:
        path = value
    return any(path == root or path.startswith(root + "/") for root in PROTECTED_TARGET_ROOTS)


def _command_uses_ssh(command: str) -> bool:
    return "ssh vps" in command or "ssh root@srv1336035.hstgr.cloud" in command


def _metadata_strings(metadata: Mapping[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
            values.extend(str(v) for v in value)
    return values


def agt_action_gateway(
    *,
    action: str,
    caller: str,
    policies: Sequence[str] | str,
    target: str = "",
    state: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    override_reason: str | None = None,
) -> AGTDecision:
    """Evaluate an action before execution and append an audit event.

    Deny/quarantine decisions are blocking. Callers must return before executing
    the protected action when ``decision.blocked`` is true.
    """

    meta = dict(metadata or {})
    policy_list = [policies] if isinstance(policies, str) else list(policies)
    state_map = dict(state or {})
    state_hash = _state_hash(state_map, meta)

    decision = "allow"
    matched_policy = policy_list[0] if policy_list else "none"
    reason = "policy allow"

    if "stale_async_quarantine" in policy_list:
        dispatched_hash = meta.get("dispatch_state_hash") or meta.get("state_hash")
        current_hash = meta.get("current_state_hash")
        if dispatched_hash and current_hash and str(dispatched_hash) != str(current_hash):
            decision = "quarantine"
            matched_policy = "stale_async_quarantine"
            reason = "async result state hash mismatch"

    if decision == "allow" and "no_terminal_junk_as_user_intent" in policy_list:
        if meta.get("terminal_junk") is True:
            decision = "quarantine"
            matched_policy = "no_terminal_junk_as_user_intent"
            reason = "terminal control/cursor junk is not user intent"

    if decision == "allow" and "remote_target_requires_ssh" in policy_list:
        remote_target = str(meta.get("remote_target") or state_map.get("remote_target") or "")
        if remote_target == "vps":
            command = str(meta.get("command") or "")
            target_values = [target, *_metadata_strings(meta, "path", "target_path", "paths")]
            protected = bool(meta.get("protected_local_target")) or any(
                _looks_protected_path(value) for value in target_values
            )
            if protected and not _command_uses_ssh(command):
                decision = "deny"
                matched_policy = "remote_target_requires_ssh"
                reason = "remote target vps requires ssh vps for protected target paths"

    if decision == "allow" and "remote_mutation_requires_approval" in policy_list:
        remote_target = str(meta.get("remote_target") or state_map.get("remote_target") or "")
        if remote_target == "vps" and meta.get("remote_mutation") is True:
            if not meta.get("remote_mutation_approved"):
                decision = "deny"
                matched_policy = "remote_mutation_requires_approval"
                reason = "remote target vps mutation requires explicit approved mutation phase"

    if decision == "allow" and "robot_hand_discovery_required" in policy_list:
        if meta.get("raw_discovery") is True:
            has_current = bool(meta.get("robot_hand_current"))
            named_gap = str(meta.get("robot_hand_gap") or "")
            stale_without_gap = bool(meta.get("robot_hand_stale")) and not named_gap
            if stale_without_gap:
                decision = "deny"
                matched_policy = "robot_hand_discovery_required"
                reason = "stale robot-hand index cannot silently count as current discovery"
            elif not has_current and not named_gap:
                decision = "deny"
                matched_policy = "robot_hand_discovery_required"
                reason = "robot-hand discovery required before raw file search/read fallback"
            elif named_gap:
                matched_policy = "robot_hand_discovery_required"
                reason = f"explicit robot-hand gap permits raw fallback: {named_gap}"

    if decision == "allow" and "codegraph_current_before_edit" in policy_list:
        if meta.get("code_mutation") is True and meta.get("codegraph_stale") is True:
            if not (meta.get("codegraph_current") or meta.get("codegraph_synced")):
                decision = "deny"
                matched_policy = "codegraph_current_before_edit"
                reason = "CodeGraph stale status requires sync or block before edit"

    if decision == "allow" and "parent_owned_proof_write" in policy_list:
        role = str(meta.get("role") or state_map.get("current_role") or "")
        if meta.get("proof_or_state_write") is True and role not in {"controller", "parent", ""}:
            decision = "deny"
            matched_policy = "parent_owned_proof_write"
            reason = "proof/state writes are parent/controller-owned"

    if decision == "allow" and "builder_only_code_mutation" in policy_list:
        role = str(meta.get("role") or state_map.get("current_role") or "")
        if meta.get("code_mutation") is True and role not in {"builder", "controller", "parent"}:
            decision = "deny"
            matched_policy = "builder_only_code_mutation"
            reason = "code mutation is Builder-only"

    if decision == "allow" and "model_inherit_controller_default" in policy_list:
        parent_model = str(meta.get("parent_model") or state_map.get("controller_model") or "")
        child_model = str(meta.get("child_model") or "")
        explicit = bool(override_reason or meta.get("explicit_model_override"))
        if parent_model and child_model and child_model != parent_model and not explicit:
            decision = "deny"
            matched_policy = "model_inherit_controller_default"
            reason = "child model differs from controller without explicit override"

    if decision == "allow" and "no_receipt_only_role_start_as_execution_proof" in policy_list:
        evidence_type = str(meta.get("evidence_type") or meta.get("runtime_kind") or "")
        if meta.get("execution_proof") is True and evidence_type in RECEIPT_ONLY_EVIDENCE:
            decision = "deny"
            matched_policy = "no_receipt_only_role_start_as_execution_proof"
            reason = "receipt-only role start is not execution proof"

    if decision == "allow" and (
        "proof.required_for_done" in policy_list or "no_child_self_report_as_proof" in policy_list
    ):
        if meta.get("child_self_report") is True and meta.get("satisfies_proof") is True:
            decision = "deny"
            matched_policy = "no_child_self_report_as_proof"
            reason = "child self-report cannot satisfy proof"
        if decision == "allow" and meta.get("final_completion_claim") is True:
            has_proof = bool(
                meta.get("proof_packet_exists")
                and meta.get("guardian_pass")
                and meta.get("current_state_hash_matches")
            )
            if not has_proof:
                decision = "deny"
                matched_policy = "proof.required_for_done"
                reason = "final completion requires proof packet, Guardian PASS, and current state hash match"

    if decision == "allow" and override_reason:
        reason = "explicit override allowed"

    return _write_audit(
        AGTDecision(
            decision=decision,
            action=action,
            caller=caller,
            policy=matched_policy,
            reason=reason,
            state_hash=state_hash,
            target=str(target or ""),
            override_reason=override_reason,
            metadata=_json_safe(meta),
        )
    )


def agt_block_error(decision: AGTDecision) -> str | None:
    if decision.blocked:
        return decision.error_message()
    return None
