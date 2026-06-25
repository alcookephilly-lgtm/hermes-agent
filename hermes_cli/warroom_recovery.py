"""Parent-owned Warroom recovery helpers.

These helpers are deliberately small and data-shaped. They turn hung child
work into ledger/checkpoint/rescue/quarantine evidence that the parent
Controller can verify. A child self-report is never closure proof.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def utc_stamp(epoch: Optional[float] = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if epoch is None else epoch))


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def append_jsonl(path: str | Path, row: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def new_task_card(
    *,
    run_id: str,
    parent_session_id: str,
    card_id: str,
    role: str,
    mission_scope: str,
    allowed_files: Iterable[str],
    denied_roots: Iterable[str],
    child_session_id: Optional[str] = None,
    delegation_id: Optional[str] = None,
    now: Optional[float] = None,
    lease_seconds: int = 300,
) -> Dict[str, Any]:
    current = time.time() if now is None else now
    return {
        "schema_version": 1,
        "run_id": run_id,
        "parent_session_id": parent_session_id,
        "card_id": card_id,
        "role": role,
        "child_session_id": child_session_id,
        "delegation_id": delegation_id,
        "mission_scope": mission_scope,
        "allowed_files": list(allowed_files),
        "denied_roots": list(denied_roots),
        "lease": {
            "state": "running",
            "lease_id": card_id,
            "started_at": utc_stamp(current),
            "expires_at": utc_stamp(current + lease_seconds),
            "expires_epoch": current + lease_seconds,
            "last_heartbeat_at": utc_stamp(current),
            "last_heartbeat_epoch": current,
            "last_checkpoint_at": utc_stamp(current),
            "last_checkpoint_epoch": current,
            "stale_after_seconds": lease_seconds,
        },
        "checkpoint": None,
    }


def _renew(card: Dict[str, Any], *, now: Optional[float], lease_seconds: Optional[int] = None) -> float:
    current = time.time() if now is None else now
    lease = card.setdefault("lease", {})
    seconds = lease_seconds or int(lease.get("stale_after_seconds") or 300)
    lease["state"] = "renewed"
    lease["last_heartbeat_at"] = utc_stamp(current)
    lease["last_heartbeat_epoch"] = current
    lease["expires_at"] = utc_stamp(current + seconds)
    lease["expires_epoch"] = current + seconds
    return current


def record_child_heartbeat(
    card: Dict[str, Any],
    ledger_path: str | Path,
    *,
    tool_name: str,
    tool_target: str,
    result_class: str = "completed",
    exit_code: Optional[int] = None,
    artifact_path: Optional[str] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    current = _renew(card, now=now)
    event = {
        "event": "heartbeat",
        "ts": utc_stamp(current),
        "run_id": card.get("run_id"),
        "card_id": card.get("card_id"),
        "role": card.get("role"),
        "child_session_id": card.get("child_session_id"),
        "delegation_id": card.get("delegation_id"),
        "tool_name": tool_name,
        "tool_target": tool_target,
        "result_class": result_class,
        "exit_code": exit_code,
        "artifact_path": artifact_path,
        "last_activity_desc": f"{tool_name}:{result_class}",
        "current_tool": tool_name,
    }
    append_jsonl(ledger_path, event)
    return event


def record_checkpoint(
    card: Dict[str, Any],
    ledger_path: str | Path,
    *,
    seq: int,
    checkpoint_type: str,
    tool: str,
    target: str,
    artifact_path: str,
    stdout_path: Optional[str] = None,
    exit_code: Optional[int] = None,
    next_exact_step: Optional[str] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    current = _renew(card, now=now)
    lease = card.setdefault("lease", {})
    lease["last_checkpoint_at"] = utc_stamp(current)
    lease["last_checkpoint_epoch"] = current
    checkpoint = {
        "seq": seq,
        "type": checkpoint_type,
        "tool": tool,
        "target": target,
        "artifact_path": artifact_path,
        "stdout_path": stdout_path,
        "exit_code": exit_code,
        "next_exact_step": next_exact_step,
    }
    card["checkpoint"] = checkpoint
    append_jsonl(ledger_path, {**card, "checkpoint": checkpoint})
    return checkpoint


def mark_stalled_if_expired(
    card: Dict[str, Any],
    *,
    now: Optional[float] = None,
    tracked_process_running: bool = False,
    stdout_grew: bool = False,
) -> Dict[str, Any]:
    current = time.time() if now is None else now
    lease = card.setdefault("lease", {})
    if tracked_process_running and stdout_grew:
        _renew(card, now=current)
        lease["state"] = "running"
        lease["stale_reason"] = None
        lease["process_heartbeat"] = "stdout_growth"
        return card
    if current > float(lease.get("expires_epoch") or 0):
        lease["state"] = "stalled"
        lease["stalled_at"] = utc_stamp(current)
        lease["stale_reason"] = "lease expired without checkpoint or stdout growth"
    return card


def _tail_text(path: Path, limit: int = 4000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"<read failed: {exc}>"
    return text[-limit:]


def harvest_stalled_card(
    card: Dict[str, Any],
    *,
    ledger_path: str | Path,
    log_paths: Iterable[str | Path] = (),
    hash_paths: Iterable[str | Path] = (),
    repo_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    artifacts: List[str] = [str(ledger_path), *[str(p) for p in log_paths]]
    hashes = {str(p): sha256_file(p) for p in hash_paths if Path(p).exists()}
    harvest: Dict[str, Any] = {
        "parent_card_id": card.get("card_id"),
        "stalled_child_id": card.get("child_session_id") or card.get("delegation_id") or card.get("card_id"),
        "harvested_artifacts": artifacts,
        "ledger_tail": _tail_text(Path(ledger_path)),
        "log_tails": {str(p): _tail_text(Path(p)) for p in log_paths},
        "current_file_hashes": hashes,
    }
    if repo_path is not None:
        try:
            proc = subprocess.run(["git", "status", "--short"], cwd=str(repo_path), text=True, capture_output=True, timeout=5, check=False)
            harvest["git_status_short"] = proc.stdout
        except Exception as exc:
            harvest["git_status_short"] = f"<git status failed: {exc}>"
    return harvest


def recovery_decision(card: Dict[str, Any], harvest: Dict[str, Any], *, sufficient_for_parent_continue: bool, exact_next_step: str) -> Dict[str, Any]:
    if sufficient_for_parent_continue:
        return {
            "parent_card_id": card.get("card_id"),
            "stalled_child_id": harvest.get("stalled_child_id"),
            "harvested_artifacts": harvest.get("harvested_artifacts", []),
            "decision": "continue_direct",
            "reason": "harvested state enough for parent to continue",
            "next_exact_step": exact_next_step,
        }
    reduced = {
        "card_id": f"rescue-{card.get('card_id')}",
        "stalled_card_id": card.get("card_id"),
        "allowed_files": card.get("allowed_files", []),
        "denied_roots": card.get("denied_roots", []),
        "harvested_artifacts": harvest.get("harvested_artifacts", []),
        "exact_next_step": exact_next_step,
    }
    return {
        "parent_card_id": card.get("card_id"),
        "stalled_child_id": harvest.get("stalled_child_id"),
        "harvested_artifacts": harvest.get("harvested_artifacts", []),
        "decision": "spawn_rescue",
        "reason": "isolated rescue worker needed",
        "rescue_worker_card": reduced,
    }


def quarantine_late_async_result(
    *,
    late_result_id: str,
    claimed_file_hashes: Dict[str, str],
    tests_rerun: Iterable[Dict[str, Any]],
    newer_rescue_conflict: bool = False,
    received_at: Optional[float] = None,
) -> Dict[str, Any]:
    checked: Dict[str, str] = {}
    hash_match = True
    for path, expected in claimed_file_hashes.items():
        p = Path(path)
        current = sha256_file(p) if p.exists() else "MISSING"
        checked[path] = current
        if current != expected:
            hash_match = False
    tests = list(tests_rerun)
    tests_pass = all(int(t.get("exit_code", 1)) == 0 for t in tests)
    accepted = hash_match and tests_pass and not newer_rescue_conflict
    return {
        "late_result_id": late_result_id,
        "received_at": utc_stamp(received_at),
        "status": "accepted" if accepted else "rejected_stale",
        "current_file_hashes_checked": checked,
        "tests_rerun": tests,
        "verdict": "accepted_after_file_and_test_verification" if accepted else "rejected_stale_or_conflicting",
    }


def validate_long_command_proof(proof: Dict[str, Any]) -> bool:
    session = proof.get("process_session_id") or proof.get("session_id") or proof.get("target")
    stdout_path = proof.get("stdout_path")
    return bool(session and stdout_path and Path(str(stdout_path)).exists() and isinstance(proof.get("exit_code"), int))


def pid_receipt_counts_as_active_work(record: Dict[str, Any]) -> bool:
    runtime_id = str(record.get("runtime_id") or "")
    if runtime_id.startswith("pid:"):
        return False
    if record.get("spawn_receipt_only") is True:
        return False
    return bool(record.get("child_session_id") or record.get("delegation_id"))


def mission_closure_allowed_from_role(*, source_role: str, proof_packet_exists: bool, guardian_pass: bool) -> bool:
    return source_role == "controller" and proof_packet_exists and guardian_pass
