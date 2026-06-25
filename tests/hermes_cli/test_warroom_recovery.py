from __future__ import annotations

import json
from pathlib import Path

from hermes_cli.warroom_recovery import (
    harvest_stalled_card,
    mark_stalled_if_expired,
    mission_closure_allowed_from_role,
    new_task_card,
    pid_receipt_counts_as_active_work,
    quarantine_late_async_result,
    record_checkpoint,
    record_child_heartbeat,
    recovery_decision,
    sha256_file,
    validate_long_command_proof,
)


def _card(tmp_path: Path):
    return new_task_card(
        run_id="run-l2",
        parent_session_id="parent",
        card_id="L2-001",
        role="builder",
        child_session_id="child-1",
        delegation_id="deleg-1",
        mission_scope="small job card",
        allowed_files=[str(tmp_path / "target.py")],
        denied_roots=["/secrets"],
        now=1_000,
        lease_seconds=300,
    )


def test_child_heartbeat_writes_ledger_event_and_checkpoint_renews_lease(tmp_path):
    ledger = tmp_path / "task-card-ledger.jsonl"
    card = _card(tmp_path)

    heartbeat = record_child_heartbeat(
        card,
        ledger,
        tool_name="terminal",
        tool_target="pytest -q",
        result_class="completed",
        exit_code=0,
        artifact_path=str(tmp_path / "pytest.log"),
        now=1_010,
    )
    checkpoint = record_checkpoint(
        card,
        ledger,
        seq=1,
        checkpoint_type="test_result",
        tool="process.wait",
        target="proc_123",
        artifact_path=str(tmp_path / "checkpoint.txt"),
        stdout_path=str(tmp_path / "pytest.log"),
        exit_code=0,
        next_exact_step="continue",
        now=1_020,
    )

    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert heartbeat["event"] == "heartbeat"
    assert rows[0]["event"] == "heartbeat"
    assert card["lease"]["state"] == "renewed"
    assert card["lease"]["last_checkpoint_epoch"] == 1_020
    assert card["lease"]["expires_epoch"] == 1_320
    assert checkpoint["stdout_path"].endswith("pytest.log")


def test_idle_child_stalls_but_stdout_growth_renews_running_card(tmp_path):
    stalled = _card(tmp_path)
    mark_stalled_if_expired(stalled, now=1_401)
    assert stalled["lease"]["state"] == "stalled"
    assert "lease expired" in stalled["lease"]["stale_reason"]

    running = _card(tmp_path)
    mark_stalled_if_expired(running, now=1_401, tracked_process_running=True, stdout_grew=True)
    assert running["lease"]["state"] == "running"
    assert running["lease"]["process_heartbeat"] == "stdout_growth"
    assert running["lease"]["stale_reason"] is None


def test_harvest_stalled_card_parent_continue_and_rescue_worker_card(tmp_path):
    ledger = tmp_path / "task-card-ledger.jsonl"
    log = tmp_path / "child.log"
    target = tmp_path / "target.py"
    ledger.write_text('{"event":"heartbeat"}\n', encoding="utf-8")
    log.write_text("last stdout\n", encoding="utf-8")
    target.write_text("print('ok')\n", encoding="utf-8")
    card = _card(tmp_path)
    mark_stalled_if_expired(card, now=1_401)

    harvest = harvest_stalled_card(card, ledger_path=ledger, log_paths=[log], hash_paths=[target])
    assert harvest["stalled_child_id"] == "child-1"
    assert harvest["current_file_hashes"][str(target)] == sha256_file(target)
    assert "last stdout" in harvest["log_tails"][str(log)]

    direct = recovery_decision(card, harvest, sufficient_for_parent_continue=True, exact_next_step="parent continues")
    assert direct["decision"] == "continue_direct"

    rescue = recovery_decision(card, harvest, sufficient_for_parent_continue=False, exact_next_step="retry small card")
    assert rescue["decision"] == "spawn_rescue"
    assert rescue["rescue_worker_card"]["stalled_card_id"] == "L2-001"
    assert rescue["rescue_worker_card"]["allowed_files"] == [str(target)]


def test_late_async_quarantine_accepts_only_after_hash_and_test_verification(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("v1\n", encoding="utf-8")
    claimed = {str(target): sha256_file(target)}

    accepted = quarantine_late_async_result(
        late_result_id="late-1",
        claimed_file_hashes=claimed,
        tests_rerun=[{"command": "pytest -q impacted", "exit_code": 0}],
    )
    assert accepted["status"] == "accepted"

    target.write_text("v2\n", encoding="utf-8")
    rejected_hash = quarantine_late_async_result(
        late_result_id="late-2",
        claimed_file_hashes=claimed,
        tests_rerun=[{"command": "pytest -q impacted", "exit_code": 0}],
    )
    assert rejected_hash["status"] == "rejected_stale"

    new_claim = {str(target): sha256_file(target)}
    rejected_test = quarantine_late_async_result(
        late_result_id="late-3",
        claimed_file_hashes=new_claim,
        tests_rerun=[{"command": "pytest -q impacted", "exit_code": 1}],
    )
    assert rejected_test["status"] == "rejected_stale"


def test_long_command_pid_receipt_and_child_self_report_do_not_close(tmp_path):
    stdout = tmp_path / "run.log"
    stdout.write_text("real stdout\n", encoding="utf-8")
    assert validate_long_command_proof({"process_session_id": "proc_1", "stdout_path": str(stdout), "exit_code": 0}) is True
    assert validate_long_command_proof({"process_session_id": "proc_1", "exit_code": 0}) is False

    assert pid_receipt_counts_as_active_work({"runtime_id": "pid:123", "spawn_receipt_only": True}) is False
    assert pid_receipt_counts_as_active_work({"delegation_id": "deleg-1", "spawn_receipt_only": False}) is True

    assert mission_closure_allowed_from_role(source_role="builder", proof_packet_exists=True, guardian_pass=True) is False
    assert mission_closure_allowed_from_role(source_role="controller", proof_packet_exists=True, guardian_pass=False) is False
    assert mission_closure_allowed_from_role(source_role="controller", proof_packet_exists=True, guardian_pass=True) is True
