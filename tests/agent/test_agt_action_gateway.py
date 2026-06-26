import json
from pathlib import Path

from agent.agt_gateway import agt_action_gateway


BOUNDARIES = [
    "delegate_task.dispatch",
    "warroom.role_dispatch",
    "async_result.accept",
    "cli.user_message_ingest",
    "protected_target_path",
    "proof_state.write",
    "final_completion_claim",
]


def _events(home: Path):
    path = home / "logs" / "agt_action_gateway.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_agt_gateway_logs_allow_for_all_wave1_boundaries(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    for action in BOUNDARIES:
        decision = agt_action_gateway(
            action=action,
            caller="tests.agent.test_agt_action_gateway",
            policies=("model_inherit_controller_default",),
            target=f"target:{action}",
            state={"controller_model": "gpt-5.5"},
            metadata={"parent_model": "gpt-5.5", "child_model": "gpt-5.5"},
        )
        assert decision.allowed

    events = _events(tmp_path)
    assert [event["action"] for event in events] == BOUNDARIES
    for event in events:
        assert event["decision"] == "allow"
        assert event["policy"] == "model_inherit_controller_default"
        assert event["caller"] == "tests.agent.test_agt_action_gateway"
        assert event["reason"] == "policy allow"
        assert event["state_hash"]
        assert event["target"].startswith("target:")


def test_deny_decision_stops_action_before_execution(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    executed = False

    decision = agt_action_gateway(
        action="protected_target_path",
        caller="test",
        policies=("remote_target_requires_ssh",),
        target="/etc/cron.d/mls-vulture-vps-live",
        state={"remote_target": "vps"},
        metadata={"remote_target": "vps", "path": "/etc/cron.d/mls-vulture-vps-live", "command": "cat /etc/cron.d/mls-vulture-vps-live"},
    )
    if decision.allowed:
        executed = True

    assert decision.decision == "deny"
    assert executed is False
    assert _events(tmp_path)[-1]["reason"] == "remote target vps requires ssh vps for protected target paths"


def test_quarantine_decision_logs_and_blocks(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    accepted = False

    decision = agt_action_gateway(
        action="async_result.accept",
        caller="test",
        policies=("stale_async_quarantine",),
        target="deleg_old",
        metadata={"dispatch_state_hash": "old", "current_state_hash": "new"},
    )
    if decision.allowed:
        accepted = True

    assert decision.decision == "quarantine"
    assert accepted is False
    assert _events(tmp_path)[-1]["policy"] == "stale_async_quarantine"


def test_explicit_override_allows_and_logs_reason(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    decision = agt_action_gateway(
        action="delegate_task.dispatch",
        caller="test",
        policies=("model_inherit_controller_default",),
        target="child",
        metadata={"parent_model": "gpt-5.5", "child_model": "gpt-5.4", "explicit_model_override": True},
        override_reason="delegation.model",
    )

    assert decision.allowed
    event = _events(tmp_path)[-1]
    assert event["override_reason"] == "delegation.model"
    assert event["reason"] == "explicit override allowed"


def test_receipt_only_role_start_cannot_count_as_execution_proof(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    decision = agt_action_gateway(
        action="warroom.role_execution_proof",
        caller="test",
        policies=("no_receipt_only_role_start_as_execution_proof",),
        target="builder",
        metadata={"runtime_kind": "spawn_receipt", "evidence_type": "spawn_receipt", "execution_proof": True},
    )

    assert decision.decision == "deny"
    assert "receipt-only role start" in decision.reason


def test_child_self_report_cannot_satisfy_done_proof(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    decision = agt_action_gateway(
        action="final_completion_claim",
        caller="test",
        policies=("proof.required_for_done", "no_child_self_report_as_proof"),
        target="sid",
        metadata={"child_self_report": True, "satisfies_proof": True},
    )

    assert decision.decision == "deny"
    assert decision.policy == "no_child_self_report_as_proof"


def test_final_claim_requires_current_state_hash_match(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    decision = agt_action_gateway(
        action="final_completion_claim",
        caller="test",
        policies=("proof.required_for_done",),
        target="sid",
        metadata={
            "final_completion_claim": True,
            "proof_packet_exists": True,
            "guardian_pass": True,
            "current_state_hash_matches": False,
        },
    )
    assert decision.decision == "deny"
    assert "current state hash match" in decision.reason

    allowed = agt_action_gateway(
        action="final_completion_claim",
        caller="test",
        policies=("proof.required_for_done",),
        target="sid",
        metadata={
            "final_completion_claim": True,
            "proof_packet_exists": True,
            "guardian_pass": True,
            "current_state_hash_matches": True,
        },
    )
    assert allowed.allowed


def test_terminal_and_file_protected_path_call_sites_block_before_execution(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_REMOTE_TARGET", "vps")

    from tools.terminal_tool import terminal_tool
    from tools.file_tools import read_file_tool, write_file_tool

    terminal_result = json.loads(terminal_tool("cat /etc/passwd", timeout=1))
    read_result = json.loads(read_file_tool("/etc/passwd"))
    write_result = json.loads(write_file_tool("/etc/blocked", "x"))

    assert terminal_result["exit_code"] == -1
    assert "remote_target_requires_ssh" in terminal_result["error"]
    assert "remote_target_requires_ssh" in read_result["error"]
    assert "remote_target_requires_ssh" in write_result["error"]


def test_remote_audit_flattens_target_context_and_blocks_mutation_without_approval(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    blocked = agt_action_gateway(
        action="remote_target_access",
        caller="test",
        policies=("remote_target_requires_ssh", "remote_mutation_requires_approval"),
        target="ssh vps 'sudo systemctl restart hermes-gateway'",
        state={"remote_target": "vps"},
        metadata={
            "session_id": "sid",
            "remote_target": "vps",
            "role": "builder",
            "attempted_path": "",
            "attempted_command": "ssh vps 'sudo systemctl restart hermes-gateway'",
            "command": "ssh vps 'sudo systemctl restart hermes-gateway'",
            "remote_mutation": True,
            "remote_mutation_approved": False,
        },
    )

    assert blocked.decision == "deny"
    assert blocked.policy == "remote_mutation_requires_approval"
    event = _events(tmp_path)[-1]
    assert event["remote_target"] == "vps"
    assert event["attempted_command"].startswith("ssh vps")
    assert event["role"] == "builder"
    assert event["session_id"] == "sid"


def test_robot_hand_gateway_blocks_raw_fallback_until_current_or_gap(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    blocked = agt_action_gateway(
        action="raw_discovery_fallback",
        caller="test",
        policies=("robot_hand_discovery_required",),
        target="search_files:foo",
        metadata={"raw_discovery": True, "robot_hand_current": False, "robot_hand_stale": False},
    )
    assert blocked.decision == "deny"
    assert "robot-hand discovery required" in blocked.reason

    stale = agt_action_gateway(
        action="raw_discovery_fallback",
        caller="test",
        policies=("robot_hand_discovery_required",),
        target="search_files:foo",
        metadata={"raw_discovery": True, "robot_hand_current": True, "robot_hand_stale": True},
    )
    assert stale.decision == "deny"
    assert "stale robot-hand index" in stale.reason

    allowed_gap = agt_action_gateway(
        action="raw_discovery_fallback",
        caller="test",
        policies=("robot_hand_discovery_required",),
        target="search_files:foo",
        metadata={"raw_discovery": True, "robot_hand_gap": "ROBOT_HAND_GAP"},
    )
    assert allowed_gap.allowed
    assert "explicit robot-hand gap" in allowed_gap.reason


def test_codegraph_stale_gateway_blocks_edit_until_synced(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    blocked = agt_action_gateway(
        action="code_mutation",
        caller="test",
        policies=("codegraph_current_before_edit",),
        target="module.py",
        metadata={"code_mutation": True, "codegraph_stale": True},
    )
    assert blocked.decision == "deny"
    assert "CodeGraph stale" in blocked.reason

    synced = agt_action_gateway(
        action="code_mutation",
        caller="test",
        policies=("codegraph_current_before_edit",),
        target="module.py",
        metadata={"code_mutation": True, "codegraph_stale": True, "codegraph_synced": True},
    )
    assert synced.allowed
