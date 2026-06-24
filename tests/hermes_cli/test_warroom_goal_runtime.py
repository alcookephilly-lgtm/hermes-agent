from __future__ import annotations

from pathlib import Path
import json

import pytest


@pytest.fixture()
def hermes_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    from hermes_cli import goals
    try:
        from hermes_cli import warroom_goal
        warroom_goal._DB_CACHE.clear()
    except Exception:
        pass
    goals._DB_CACHE.clear()
    yield home
    goals._DB_CACHE.clear()
    try:
        warroom_goal._DB_CACHE.clear()
    except Exception:
        pass


def _strict_goal(
    *,
    acceptance_heading: str = "Acceptance:",
    constraints_heading: str = "Constraints:",
    verify_heading: str = "Verify with:",
) -> str:
    return (
        "Use plan adversary skill for: build hardwire\n\n"
        f"{acceptance_heading}\n"
        "- proof\n\n"
        f"{constraints_heading}\n"
        "- worktree only\n\n"
        f"{verify_heading}\n"
        "pytest -q"
    )


def _unlock_runtime_for_policy_test(state):
    state.status = "active"
    state.gates["role_spawn"] = "pass"
    state.gates["delegate_runtime"] = "pass"
    state.delegate_runtime_available = True
    state.required_action = None
    state.role_spawn_gap = None
    state.last_gap = None
    return state


def _fake_background_delegate(monkeypatch):
    calls = []

    def fake_delegate_task(**kwargs):
        calls.append(kwargs)
        return json.dumps(
            {
                "status": "dispatched",
                "delegation_id": f"delegation-{len(calls)}",
                "mode": "background",
            }
        )

    import tools.delegate_tool as delegate_tool

    monkeypatch.setattr(delegate_tool, "delegate_task", fake_delegate_task)
    return calls


def test_notice_reports_runtime_drift_visibility(monkeypatch, tmp_path):
    from hermes_cli import warroom_goal

    loaded_file = tmp_path / "warroom_goal.py"
    loaded_file.write_text("current file on disk", encoding="utf-8")
    monkeypatch.setattr(warroom_goal, "_LOADED_CODE_PATH", loaded_file)
    monkeypatch.setattr(warroom_goal, "_LOADED_CODE_SHA256", "loaded-sha")
    monkeypatch.setattr(warroom_goal, "_LOADED_REPO_ROOT", tmp_path)
    monkeypatch.setattr(warroom_goal, "_LOADED_GIT_HEAD", "aaaaaaaaaaaa1111")
    monkeypatch.setattr(warroom_goal, "_sha256_file_optional", lambda path: "current-sha")
    monkeypatch.setattr(
        warroom_goal,
        "_git_output",
        lambda args, cwd: "bbbbbbbbbbbb2222" if args == ["rev-parse", "HEAD"] else None,
    )

    state = warroom_goal.WarroomGoalState(workflow="global_plan_adversary", status="active")
    notice = warroom_goal.notice_for_state(state)
    status_line = state.status_line()

    for rendered in (notice, status_line):
        assert "Runtime drift:" in rendered
        assert "loaded_code_commit=aaaaaaaaaaaa" in rendered
        assert "repo_HEAD=bbbbbbbbbbbb" in rendered
        assert "stale=yes" in rendered
        assert "repo_head_mismatch" in rendered
        assert "loaded_file_changed_on_disk" in rendered
        assert f"loaded_code_path={loaded_file}" in rendered


def test_notice_reports_runtime_not_stale_when_loaded_code_matches_repo(monkeypatch, tmp_path):
    from hermes_cli import warroom_goal

    loaded_file = tmp_path / "warroom_goal.py"
    loaded_file.write_text("same file", encoding="utf-8")
    monkeypatch.setattr(warroom_goal, "_LOADED_CODE_PATH", loaded_file)
    monkeypatch.setattr(warroom_goal, "_LOADED_CODE_SHA256", "same-sha")
    monkeypatch.setattr(warroom_goal, "_LOADED_REPO_ROOT", tmp_path)
    monkeypatch.setattr(warroom_goal, "_LOADED_GIT_HEAD", "cccccccccccc3333")
    monkeypatch.setattr(warroom_goal, "_sha256_file_optional", lambda path: "same-sha")
    monkeypatch.setattr(
        warroom_goal,
        "_git_output",
        lambda args, cwd: "cccccccccccc3333" if args == ["rev-parse", "HEAD"] else None,
    )

    notice = warroom_goal.notice_for_state(
        warroom_goal.WarroomGoalState(workflow="global_plan_adversary", status="active")
    )

    assert "loaded_code_commit=cccccccccccc" in notice
    assert "repo_HEAD=cccccccccccc" in notice
    assert "stale=no" in notice
    assert "reasons=none" in notice


def test_detect_warroom_goal_triggers_and_global_fallback():
    from hermes_cli.warroom_goal import detect_warroom_goal

    fast = detect_warroom_goal("Use adversary skill for: ship runtime enforcement")
    assert fast is not None
    assert fast.workflow == "fast_adversary"
    assert fast.body == "ship runtime enforcement"

    strict = detect_warroom_goal("Use plan adversary skill for: ship runtime enforcement")
    assert strict is not None
    assert strict.workflow == "strict_plan_adversary"

    generic = detect_warroom_goal("I might use adversary skill for: nope")
    assert generic is not None
    assert generic.workflow == "global_plan_adversary"
    assert generic.body == "I might use adversary skill for: nope"

    quoted = detect_warroom_goal('Example: "/goal Use adversary skill for: nope"')
    assert quoted is not None
    assert quoted.workflow == "global_plan_adversary"

    typo = detect_warroom_goal("Use adversary-skill for: nope")
    assert typo is not None
    assert typo.workflow == "global_plan_adversary"


@pytest.mark.parametrize(
    "verify_heading",
    [
        "Verify with these read-only commands:",
        "Verification:",
        "Test with:",
        "Commands to run:",
        "Proof commands:",
    ],
)
def test_detect_warroom_goal_accepts_verify_heading_variants(verify_heading):
    from hermes_cli.warroom_goal import detect_warroom_goal

    strict = detect_warroom_goal(
        _strict_goal(
            acceptance_heading="Acceptance criteria:",
            constraints_heading="Boundaries:",
            verify_heading=verify_heading,
        )
    )
    assert strict is not None
    assert strict.workflow == "strict_plan_adversary"
    assert strict.missing_sections == []


@pytest.mark.parametrize(
    ("acceptance_heading", "constraints_heading"),
    [
        ("Acceptance criteria:", "Constraint:"),
        ("Done when:", "Boundaries:"),
        ("Accepted when:", "Limitations:"),
    ],
)
def test_detect_warroom_goal_accepts_acceptance_and_constraints_variants(acceptance_heading, constraints_heading):
    from hermes_cli.warroom_goal import detect_warroom_goal

    strict = detect_warroom_goal(
        _strict_goal(
            acceptance_heading=acceptance_heading,
            constraints_heading=constraints_heading,
            verify_heading="Verification:",
        )
    )
    assert strict is not None
    assert strict.missing_sections == []


def test_global_goal_creates_plan_roles_without_budget_or_fallback(hermes_home, tmp_path, monkeypatch):
    from hermes_cli.warroom_goal import create_warroom_goal, handle_global_goal_slash, load_warroom_goal

    state = create_warroom_goal(
        "sid-global",
        "ship universal slash goal hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert state.workflow == "global_plan_adversary"
    assert state.required_roles == ["controller", "plan_builder", "plan_adversary", "plan_reviewer"]
    assert state.status == "gap"
    assert state.gates["role_spawn"] == "gap"
    assert state.gates["delegate_runtime"] == "stub_only"
    assert state.delegate_runtime_available is False
    assert state.required_action == "blocked_gap"
    assert "real delegated role runtime missing" in (state.last_gap or "")
    assert "50" not in state.gates

    handled = handle_global_goal_slash(
        "sid-global-api",
        "/goal ship from API ingress",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert handled is not None
    assert "WARROOM V3 global_plan_adversary" in handled["response"]
    assert load_warroom_goal("sid-global-api").workflow == "global_plan_adversary"

    calls = _fake_background_delegate(monkeypatch)
    parent_agent = object()
    handled_live = handle_global_goal_slash(
        "sid-global-api-live",
        "/goal ship from API ingress",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
        parent_agent=parent_agent,
    )
    live_state = load_warroom_goal("sid-global-api-live")
    assert handled_live is not None
    assert live_state is not None
    assert handled_live["kickoff"] is not None
    assert "real delegated role runtime missing" not in handled_live["response"]
    assert live_state.status == "active"
    assert live_state.gates["role_spawn"] == "pass"
    assert live_state.gates["delegate_runtime"] == "pass"
    assert live_state.delegate_runtime_available is True
    assert len(calls) == 3
    assert {r["delegation_id"] for r in live_state.role_records.values() if r.get("delegation_id")} == {
        "delegation-1",
        "delegation-2",
        "delegation-3",
    }
    assert all(call["background"] is True and call["parent_agent"] is parent_agent for call in calls)


def test_create_fast_state_persists_roles_and_gates(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, load_warroom_goal

    state = create_warroom_goal(
        "sid-fast",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert state.workflow == "fast_adversary"
    assert state.controller_active is True
    assert state.required_roles == ["controller", "builder", "adversary", "reviewer", "guardian"]
    assert state.gates["controller_active"] == "pass"
    assert state.gates["tracking"] == "pass"

    reloaded = load_warroom_goal("sid-fast")
    assert reloaded is not None
    assert reloaded.workflow == "fast_adversary"


def test_role_records_expose_shared_context_pack_and_profiles(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, load_warroom_goal

    shared = tmp_path / "shared-context-pack.md"
    shared.write_text("shared\n", encoding="utf-8")

    state = create_warroom_goal(
        "sid-role-profiles",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )

    controller = state.role_records["controller"]
    builder = state.role_records["builder"]
    reviewer = state.role_records["reviewer"]
    guardian = state.role_records["guardian"]

    assert controller["shared_context_pack_path"] == str(shared)
    assert controller["toolset_profile"] == "docs-only"
    assert controller["mutation_profile"] == "tracking-docs-only"
    assert controller["source_mutation_allowed"] is False

    assert builder["shared_context_pack_path"] == str(shared)
    assert builder["toolset_profile"] == "edit/test"
    assert builder["mutation_profile"] == "source-mutation-allowed"
    assert builder["source_mutation_allowed"] is True

    assert reviewer["toolset_profile"] == "read/test/review"
    assert reviewer["mutation_profile"] == "read-only"
    assert reviewer["source_mutation_allowed"] is False
    assert guardian["toolset_profile"] == "read/test/review"

    reloaded = load_warroom_goal("sid-role-profiles")
    assert reloaded is not None
    assert reloaded.role_records["builder"]["shared_context_pack_path"] == str(shared)


def test_strict_state_requires_plan_before_mutation(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy

    state = create_warroom_goal(
        "sid-strict",
        "Use plan adversary skill for: build hardwire\n\nAcceptance:\n- proof\n\nConstraints:\n- worktree only\n\nVerify with:\npytest",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    from hermes_cli.warroom_goal import save_warroom_goal
    _unlock_runtime_for_policy_test(state)
    state.current_role = "builder"
    save_warroom_goal("sid-strict", state)
    msg = enforce_tool_policy("sid-strict", "write_file", {"path": str(tmp_path / "x.py")})
    assert msg is not None
    assert "plan gate" in msg.lower()


def test_strict_parser_block_reports_missing_sections_and_allows_read_only_terminal(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, notice_for_state

    state = create_warroom_goal(
        "sid-strict-missing-verify",
        "Use plan adversary skill for: build hardwire\n\nAcceptance criteria:\n- proof\n\nBoundaries:\n- worktree only",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert state.status == "blocked"
    assert state.last_gap == "Missing required strict sections: Verify with"
    assert state.gates["plan"] == "blocked"
    assert state.gates["role_spawn"] == "blocked"
    assert state.required_action is None

    notice = notice_for_state(state)
    assert "GAP: Missing required strict sections: Verify with" in notice
    assert "required role spawn action is pending" not in notice
    assert "spawned with persisted evidence" not in notice

    assert enforce_tool_policy(
        "sid-strict-missing-verify",
        "terminal",
        {"command": "git status --short", "workdir": str(tmp_path)},
    ) is None
    blocked = enforce_tool_policy(
        "sid-strict-missing-verify",
        "write_file",
        {"path": str(tmp_path / "x.py")},
    )
    assert blocked == "WARROOM V3 blocked: Missing required strict sections: Verify with"
    assert "spawn" not in blocked.lower()


def test_tool_policy_blocks_reviewer_and_skill_dir_mutation(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-policy",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "reviewer"
    save_warroom_goal("sid-policy", state)
    assert "reviewer" in enforce_tool_policy("sid-policy", "write_file", {"path": str(tmp_path / "x.py")}).lower()

    state.current_role = "builder"
    state.gates["tracking"] = "pass"
    state.gates["plan"] = "pass"
    save_warroom_goal("sid-policy", state)
    assert enforce_tool_policy("sid-policy", "write_file", {"path": str(tmp_path / "x.py")}) is None

    denied = enforce_tool_policy("sid-policy", "write_file", {"path": "/home/alcoo/.hermes/skills/nope/SKILL.md"})
    assert denied is not None
    assert "denied" in denied.lower()


def test_final_guard_blocks_done_without_proof_and_health_only(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, save_warroom_goal

    state = create_warroom_goal(
        "sid-final",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    blocked = guard_final_response("sid-final", "DONE. Health check passed.")
    assert "blocked" in blocked.lower()
    assert "proof packet" in blocked.lower()

    state.proof_packet_path = str(tmp_path / "proof-packet.md")
    Path(state.proof_packet_path).write_text("Status: PASS\nGuardian verdict: PASS\n", encoding="utf-8")
    state.final_claim_allowed = True
    save_warroom_goal("sid-final", state)
    blocked = guard_final_response("sid-final", "DONE. Health check passed.")
    assert "health check" in blocked.lower()

    ok = guard_final_response("sid-final", "DONE. pytest E2E passed and proof packet written.")
    assert ok.startswith("GOAL COMPLETED")
    assert "Proof packet:" in ok
    assert "Guardian verdict: PASS" in ok


def test_copy_and_halt_state_on_session_boundary(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, copy_warroom_goal, halt_warroom_goal, load_warroom_goal

    create_warroom_goal(
        "sid-parent",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    child = copy_warroom_goal("sid-parent", "sid-child", reason="compression")
    assert child is not None
    assert child.parent_session_id == "sid-parent"
    assert load_warroom_goal("sid-child") is not None

    halted = halt_warroom_goal("sid-child", reason="/stop")
    assert halted is not None
    assert halted.status == "halted"
    assert halted.halt_reason == "/stop"



def test_final_guard_allows_negated_or_progress_language(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response

    create_warroom_goal(
        "sid-final-negated",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert guard_final_response("sid-final-negated", "I am still working on it; no fix yet.", closure=True).startswith("I am still")
    assert guard_final_response("sid-final-negated", "Here is a complete log of what failed; not fixed.", closure=True).startswith("Here is")
    assert guard_final_response("sid-final-negated", "The working directory is /tmp and the issue remains open.", closure=True).startswith("The working")


def test_copy_does_not_overwrite_newer_child_state(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, copy_warroom_goal, load_warroom_goal, save_warroom_goal

    parent = create_warroom_goal(
        "sid-parent-newer-check",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    child = create_warroom_goal(
        "sid-child-newer-check",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    child.status = "gap"
    child.last_gap = "child-only update after compression"
    child.updated_at = parent.updated_at + 10
    save_warroom_goal("sid-child-newer-check", child)

    copied = copy_warroom_goal("sid-parent-newer-check", "sid-child-newer-check", reason="compression")
    assert copied.status == "gap"
    assert load_warroom_goal("sid-child-newer-check").last_gap == "child-only update after compression"


def test_tracking_gate_blocks_builder_mutation(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    missing_tracking = tmp_path / "missing-tracking"
    state = create_warroom_goal(
        "sid-tracking-block",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(missing_tracking),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.gates["tracking"] = "blocked"
    state.current_role = "builder"
    save_warroom_goal("sid-tracking-block", state)
    msg = enforce_tool_policy("sid-tracking-block", "write_file", {"path": str(tmp_path / "x.py")})
    assert msg is not None
    assert "tracking gate" in msg.lower()



def test_role_spawn_success_persists_ids_hashes_and_evidence(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal

    state = create_warroom_goal(
        "sid-spawn-success",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )

    assert state.status == "gap"
    assert state.gates["role_spawn"] == "gap"
    assert state.gates["delegate_runtime"] == "stub_only"
    assert state.delegate_runtime_available is False
    assert state.required_action == "blocked_gap"
    assert "real delegated role runtime missing" in (state.last_gap or "")
    assert set(state.role_records) == {"controller", "builder", "adversary", "reviewer", "guardian"}
    for role, record in state.role_records.items():
        assert record["role_card_sha256"]
        assert record["runtime_id"]
        assert Path(record["evidence_path"]).exists()
        assert role == "controller" or record["runtime_kind"] == "spawn_receipt"
        assert role == "controller" or record["spawn_receipt_only"] is True
    assert Path(state.role_spawn_evidence_path).exists()


def test_fake_local_role_spawn_blocks_manual_fallback_with_runtime_gap(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy

    create_warroom_goal(
        "sid-fake-runtime-gap",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )

    blocked_write = enforce_tool_policy("sid-fake-runtime-gap", "write_file", {"path": str(tmp_path / "x.py")})
    assert blocked_write is not None
    assert "real delegated role runtime missing" in blocked_write

    blocked_delegate = enforce_tool_policy("sid-fake-runtime-gap", "delegate_task", {"task": "fallback"})
    assert blocked_delegate is not None
    assert "real delegated role runtime missing" in blocked_delegate



def test_halted_state_allows_read_only_recovery_tools_but_blocks_mutation(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, halt_warroom_goal

    create_warroom_goal(
        "sid-halted-recovery",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    halted = halt_warroom_goal("sid-halted-recovery", reason="explicit_user_stop")
    assert halted is not None
    assert halted.status == "halted"

    assert enforce_tool_policy("sid-halted-recovery", "session_search", {}) is None
    assert enforce_tool_policy("sid-halted-recovery", "read_file", {"path": str(tmp_path / "proof.log")}) is None
    assert enforce_tool_policy("sid-halted-recovery", "search_files", {"pattern": "proof"}) is None
    assert enforce_tool_policy("sid-halted-recovery", "process", {"action": "list"}) is None
    assert enforce_tool_policy("sid-halted-recovery", "process", {"action": "log", "session_id": "proc-1"}) is None
    assert enforce_tool_policy("sid-halted-recovery", "terminal", {"command": "git status --short --branch"}) is None
    assert enforce_tool_policy(
        "sid-halted-recovery",
        "terminal",
        {"command": "ssh vps 'du -xhd1 / 2>/dev/null | sort -h | tail -40'"},
    ) is None
    assert enforce_tool_policy(
        "sid-halted-recovery",
        "terminal",
        {"command": "ssh vps 'docker system df -v 2>/dev/null || true'"},
    ) is None
    assert enforce_tool_policy(
        "sid-halted-recovery",
        "terminal",
        {"command": "ssh vps 'systemctl list-unit-files 2>/dev/null | grep -i mls || true'"},
    ) is None

    for tool_name, args in [
        ("write_file", {"path": str(tmp_path / "x.py")}),
        ("patch", {"path": str(tmp_path / "x.py"), "old_string": "x", "new_string": "y"}),
        ("execute_code", {"code": "print('x')"}),
        ("delegate_task", {"task": "fallback"}),
        ("process", {"action": "kill", "session_id": "proc-1"}),
        ("terminal", {"command": "touch x", "workdir": str(tmp_path)}),
        ("terminal", {"command": "mkdir build", "workdir": str(tmp_path)}),
        ("terminal", {"command": "printf hi > note.txt", "workdir": str(tmp_path)}),
        ("terminal", {"command": "printf hi >> note.txt", "workdir": str(tmp_path)}),
        ("terminal", {"command": "ssh vps 'systemctl restart nginx'"}),
        ("terminal", {"command": "ssh vps 'docker restart web'"}),
        ("terminal", {"command": "ssh vps 'kubectl delete pod x'"}),
        ("terminal", {"command": "ssh vps 'apt-get install -y jq'"}),
    ]:
        blocked = enforce_tool_policy("sid-halted-recovery", tool_name, args)
        assert blocked is not None
        assert "workflow is halted" in blocked



def test_gap_state_allows_read_only_recovery_tools_but_blocks_mutation(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy

    state = create_warroom_goal(
        "sid-gap-recovery",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert state.status == "gap"
    assert "real delegated role runtime missing" in (state.last_gap or "")

    assert enforce_tool_policy("sid-gap-recovery", "read_file", {"path": str(tmp_path / "proof.log")}) is None
    assert enforce_tool_policy("sid-gap-recovery", "process", {"action": "poll", "session_id": "proc-1"}) is None
    assert enforce_tool_policy(
        "sid-gap-recovery",
        "terminal",
        {"command": "ssh vps 'grep -i error /var/log/syslog 2>/dev/null || true'"},
    ) is None

    for tool_name, args in [
        ("write_file", {"path": str(tmp_path / "x.py")}),
        ("terminal", {"command": "ssh vps 'systemctl restart nginx'"}),
        ("terminal", {"command": "ssh vps 'docker restart web'"}),
        ("terminal", {"command": "ssh vps 'kubectl delete pod x'"}),
        ("terminal", {"command": "ssh vps 'apt-get install -y jq'"}),
    ]:
        blocked = enforce_tool_policy("sid-gap-recovery", tool_name, args)
        assert blocked is not None
        assert "workflow is gap" in blocked
        assert "real delegated role runtime missing" in blocked


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("ssh vps 'systemctl restart nginx'", True),
        ("ssh vps 'docker restart web'", True),
        ("ssh vps 'kubectl delete pod x'", True),
        ("ssh vps 'apt-get install -y jq'", True),
        ("ssh vps 'docker system df -v 2>/dev/null || true'", False),
    ],
)
def test_terminal_mutates_flags_admin_system_commands(command, expected):
    from hermes_cli.warroom_goal import _terminal_mutates

    assert _terminal_mutates({"command": command}) is expected


def test_missing_role_card_blocks_spawn_with_explicit_gap(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, save_warroom_goal, start_warroom_roles

    state = create_warroom_goal(
        "sid-missing-card",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.role_cards["reviewer"] = str(tmp_path / "missing-reviewer-card.md")
    state.required_action = "spawn_roles"
    state.roles_started["reviewer"] = False
    save_warroom_goal("sid-missing-card", state)

    blocked = start_warroom_roles("sid-missing-card", ["reviewer"])
    assert blocked.status == "gap"
    assert blocked.gates["role_spawn"] == "gap"
    assert "missing role card" in blocked.last_gap
    assert blocked.role_records["reviewer"]["runtime_id"] == "missing-role-card"


def test_strict_plan_starts_plan_roles_then_build_roles_after_gates(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, save_warroom_goal, start_plan_build_roles_if_ready

    state = create_warroom_goal(
        "sid-plan-sequence",
        "Use plan adversary skill for: build hardwire\n\nAcceptance:\n- proof\n\nConstraints:\n- worktree only\n\nVerify with:\npytest",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert set(state.role_records) == {"controller", "plan_builder", "plan_adversary", "plan_reviewer"}
    assert "builder" not in state.role_records

    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    save_warroom_goal("sid-plan-sequence", state)
    advanced = start_plan_build_roles_if_ready("sid-plan-sequence")
    assert advanced is not None
    assert {"builder", "adversary", "reviewer", "guardian"}.issubset(set(advanced.role_records))
    assert advanced.gates["build_role_spawn"] == "gap"
    assert advanced.required_action == "blocked_gap"
    assert "real delegated role runtime missing" in (advanced.last_gap or "")


def test_builder_self_report_cannot_unlock_guardian_final_gate(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-guardian-unlock",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    proof = tmp_path / "proof-packet.md"
    proof.write_text("tests passed\n", encoding="utf-8")
    state.proof_packet_path = str(proof)
    save_warroom_goal("sid-guardian-unlock", state)

    record_role_output("sid-guardian-unlock", "builder", evidence_path=str(tmp_path / "builder.txt"), verdict="PASS")
    assert "FINAL BLOCKED" in guard_final_response("sid-guardian-unlock", "DONE. pytest E2E passed.", closure=True)

    guardian = tmp_path / "guardian.txt"
    guardian.write_text("Guardian verdict: PASS\n", encoding="utf-8")
    unlocked = record_role_output("sid-guardian-unlock", "guardian", evidence_path=str(guardian), verdict="PASS")
    assert unlocked.guardian_pass is True
    assert unlocked.final_claim_allowed is True
    completed = guard_final_response("sid-guardian-unlock", "DONE. pytest E2E passed and proof packet written.", closure=True)
    assert completed.startswith("GOAL COMPLETED")
    assert "Role spawn evidence:" in completed
    assert "Normal chat fallback: NO" in completed
    from hermes_cli.warroom_goal import load_warroom_goal
    completed_state = load_warroom_goal("sid-guardian-unlock")
    assert completed_state.status == "done"
    assert completed_state.gates["proof_packet"] == "pass"
    assert completed_state.gates["e2e_claim"] == "pass"
    assert "GOAL COMPLETED emitted" in completed_state.gate_evidence["completion_output"]


def test_normal_chat_does_not_run_final_guard_while_spawn_pending(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, save_warroom_goal

    state = create_warroom_goal(
        "sid-spawn-pending",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.required_action = "spawn_roles"
    save_warroom_goal("sid-spawn-pending", state)
    assert guard_final_response("sid-spawn-pending", "Working on it.") == "Working on it."
    assert guard_final_response("sid-spawn-pending", "Working on it.", closure=True) == "Working on it."
    blocked = guard_final_response("sid-spawn-pending", "DONE. pytest E2E passed.")
    assert "FINAL BLOCKED" in blocked
    assert "required role spawn action is pending" in blocked


def test_role_ledger_distinguishes_real_child_session_stale_pid_and_status_line(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import (
        create_warroom_goal,
        record_child_progress,
        refresh_role_runtime_status,
        save_warroom_goal,
        start_warroom_roles,
    )

    state = create_warroom_goal(
        "sid-real-child",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )

    def adapter(**kwargs):
        return {
            "adapter": "native_delegate",
            "child_session_id": "child-session-1",
            "delegation_id": "delegation-1",
            "stdout": "spawned",
            "json_payload": {"ok": True},
            "current_phase": "running-tools",
        }

    updated = start_warroom_roles("sid-real-child", ["reviewer"], adapter=adapter, use_local_process=False)
    assert updated is not None
    assert updated.gates["role_spawn"] == "pass"
    assert updated.gates["delegate_runtime"] == "pass"
    assert updated.required_action is None
    record = updated.role_records["reviewer"]
    assert record["runtime_kind"] == "real_child_session"
    assert record["spawn_receipt_only"] is False
    assert record["child_session_id"] == "child-session-1"
    assert record["delegation_id"] == "delegation-1"
    assert record["status"] == "active_child_work"

    record["last_seen_epoch"] = 1
    refresh_role_runtime_status(updated, now=1_000)
    assert record["stale"] is True
    assert record["stale_reason"] == "child session heartbeat stale"
    save_warroom_goal("sid-real-child", updated)

    refreshed = record_child_progress("sid-real-child", child_session_id="child-session-1", phase="delegate heartbeat")
    assert refreshed is not None
    fresh_record = refreshed.role_records["reviewer"]
    assert fresh_record["stale"] is False
    assert fresh_record["stale_reason"] is None
    assert fresh_record["current_phase"] == "delegate heartbeat"
    assert fresh_record["last_seen_epoch"] > 1

    pid_record = next(r for role, r in refreshed.role_records.items() if role != "controller" and str(r.get("runtime_id", "")).startswith("pid:"))
    pid_record["runtime_id"] = "pid:999999999"
    pid_record["status"] = "spawn_receipt_only"
    refresh_role_runtime_status(refreshed)
    assert pid_record["spawn_receipt_only"] is True
    assert pid_record["status"] == "stale_dead_pid"
    line = refreshed.status_line()
    assert "child-session-1" in line
    assert "phase=delegate heartbeat" in line
    assert "stale" in line


def test_controller_can_write_tracking_docs_but_not_source(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-controller-tracking",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path / ".warroom"),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "controller"
    save_warroom_goal("sid-controller-tracking", state)

    assert enforce_tool_policy("sid-controller-tracking", "write_file", {"path": str(tmp_path / ".warroom" / "proof.md")}) is None
    blocked = enforce_tool_policy("sid-controller-tracking", "write_file", {"path": str(tmp_path / "source.py")})
    assert blocked is not None
    assert "Builder is the only mutation role" in blocked


def test_rc0_empty_transport_is_incomplete_not_success(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, start_warroom_roles

    create_warroom_goal(
        "sid-incomplete-transport",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )

    def empty_transport(**kwargs):
        return {"adapter": "native_delegate", "exit_code": 0, "stdout": ""}

    blocked = start_warroom_roles("sid-incomplete-transport", ["reviewer"], adapter=empty_transport, use_local_process=False)
    assert blocked is not None
    assert blocked.status == "gap"
    assert blocked.gates["role_spawn"] == "gap"
    assert "INCOMPLETE_TRANSPORT" in blocked.role_records["reviewer"]["error"]


def test_noncritical_halts_auto_continue_and_mission_critical_halts(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import apply_halt_policy, create_warroom_goal, load_warroom_goal

    create_warroom_goal(
        "sid-halt-policy",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    for reason in ["approval_phase", "live_promotion_phrase", "internal_reviewer_handoff", "guardian_handoff", "normal_milestone_boundary"]:
        state = apply_halt_policy("sid-halt-policy", reason=reason)
        assert state.status == "active"
        assert state.noncritical_pause_attempts[-1]["decision"] == "auto_continued"

    halted = apply_halt_policy("sid-halt-policy", reason="credentials_or_physical_access")
    assert halted.status == "halted"
    assert halted.halt_reason == "credentials_or_physical_access"

    create_warroom_goal(
        "sid-stop-policy",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    stopped = apply_halt_policy("sid-stop-policy", reason="/stop")
    assert stopped.status == "halted"
    assert stopped.halt_reason == "explicit_user_stop"



def test_terminal_and_execute_code_fail_closed_for_non_builder_and_builder_scope(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-terminal-policy",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "reviewer"
    save_warroom_goal("sid-terminal-policy", state)
    assert "reviewer" in enforce_tool_policy("sid-terminal-policy", "terminal", {"command": "touch x"}).lower()
    assert enforce_tool_policy("sid-terminal-policy", "terminal", {"command": "git status --short", "workdir": str(tmp_path)}) is None
    for mutating_cmd in [
        "python -c \"from pathlib import Path; Path('x').write_text('x')\"",
        "sed -i '1s/a/b/' file.txt",
        "git restore --source=HEAD --staged --worktree .",
        "printf hi >> note.txt",
    ]:
        blocked = enforce_tool_policy("sid-terminal-policy", "terminal", {"command": mutating_cmd, "workdir": str(tmp_path)})
        assert blocked is not None and "reviewer" in blocked.lower()
    assert "reviewer" in enforce_tool_policy("sid-terminal-policy", "execute_code", {"code": "open('x','w').write('x')"}).lower()

    state.current_role = "builder"
    state.gates["tracking"] = "pass"
    state.gates["plan"] = "pass"
    save_warroom_goal("sid-terminal-policy", state)
    assert enforce_tool_policy("sid-terminal-policy", "terminal", {"command": "pytest", "workdir": str(tmp_path)}) is None
    mutating_outside = enforce_tool_policy("sid-terminal-policy", "terminal", {"command": "touch x", "workdir": "/tmp"})
    assert mutating_outside is not None and "outside allowed worktree" in mutating_outside
    assert "execute_code is not allowed" in enforce_tool_policy("sid-terminal-policy", "execute_code", {"code": "Path('x').write_text('x')"})



def test_controller_read_only_terminal_allows_safe_stderr_redirects_but_blocks_file_redirects(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-controller-readonly-terminal",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "controller"
    save_warroom_goal("sid-controller-readonly-terminal", state)

    assert enforce_tool_policy(
        "sid-controller-readonly-terminal",
        "terminal",
        {"command": "ssh vps 'du -xhd1 / 2>/dev/null | sort -h | tail -40'", "workdir": str(tmp_path)},
    ) is None
    assert enforce_tool_policy(
        "sid-controller-readonly-terminal",
        "terminal",
        {"command": "docker system df -v 2>/dev/null || true", "workdir": str(tmp_path)},
    ) is None

    blocked = enforce_tool_policy(
        "sid-controller-readonly-terminal",
        "terminal",
        {"command": "printf hi > note.txt", "workdir": str(tmp_path)},
    )
    assert blocked is not None
    assert "Builder is the only mutation role" in blocked


def test_guardian_unlock_requires_existing_guardian_pass_evidence(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-guardian-evidence",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    proof = tmp_path / "proof-packet.md"
    proof.write_text("proof\n", encoding="utf-8")
    state.proof_packet_path = str(proof)
    save_warroom_goal("sid-guardian-evidence", state)

    missing = record_role_output("sid-guardian-evidence", "guardian", evidence_path=str(tmp_path / "missing.txt"), verdict="PASS")
    assert missing.guardian_pass is False
    assert "FINAL BLOCKED" in guard_final_response("sid-guardian-evidence", "DONE. pytest E2E passed and proof packet written.", closure=True)

    weak = tmp_path / "weak.txt"
    weak.write_text("PASS\n", encoding="utf-8")
    weak_state = record_role_output("sid-guardian-evidence", "guardian", evidence_path=str(weak), verdict="PASS")
    assert weak_state.guardian_pass is False

    good = tmp_path / "guardian.txt"
    good.write_text("Guardian verdict: PASS\n", encoding="utf-8")
    good_state = record_role_output("sid-guardian-evidence", "guardian", evidence_path=str(good), verdict="PASS")
    assert good_state.guardian_pass is True
    assert good_state.final_claim_allowed is True



def test_core_conversation_loop_builds_slash_goal_kickoff_context_without_transcript_mutation(hermes_home, tmp_path, monkeypatch):
    from agent.conversation_loop import _build_warroom_autocontinue_context
    from hermes_cli.warroom_goal import create_warroom_goal, controller_kickoff_prompt, notice_for_state

    monkeypatch.chdir(tmp_path)
    state = create_warroom_goal(
        "sid-core-global-goal",
        "core API ingress hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    original = "/goal core API ingress hardwire"
    merged = _build_warroom_autocontinue_context(
        user_message=original,
        notice=notice_for_state(state),
        kickoff=controller_kickoff_prompt(state),
    )
    assert original == "/goal core API ingress hardwire"
    assert "WARROOM V3 CONTROLLER" in merged
    assert "Do not wait for another user message" in merged


def test_core_run_conversation_slash_goal_reaches_runtime_without_user_nudge(hermes_home, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from agent import conversation_loop
    from hermes_cli.warroom_goal import load_warroom_goal

    monkeypatch.chdir(tmp_path)
    captured = {}

    def fake_context(agent, user_message, system_message, conversation_history, task_id, stream_callback, persist_user_message, **kwargs):
        return SimpleNamespace(
            user_message=user_message,
            original_user_message=user_message,
            messages=[{"role": "user", "content": user_message}],
            conversation_history=[],
            active_system_prompt="",
            effective_task_id="task-core",
            turn_id="turn-core",
            current_turn_user_idx=0,
            should_review_memory=False,
            plugin_user_context="",
            ext_prefetch_cache=None,
        )

    def fake_codex_turn(**kwargs):
        captured.update(kwargs)
        return {"final_response": "controller drove", "messages": kwargs["messages"], "api_call_count": 1}

    monkeypatch.setattr(conversation_loop, "build_turn_context", fake_context)
    delegate_calls = _fake_background_delegate(monkeypatch)
    agent = SimpleNamespace(
        session_id="sid-core-global-goal",
        api_mode="codex_app_server",
        model="test-model",
        provider="test-provider",
        base_url=None,
        platform="cli",
        max_iterations=50,
        iteration_budget=SimpleNamespace(remaining=50, used=0, max_total=50),
        quiet_mode=True,
        session_input_tokens=0,
        session_output_tokens=0,
        session_cache_read_tokens=0,
        session_cache_write_tokens=0,
        session_reasoning_tokens=0,
        session_prompt_tokens=0,
        session_completion_tokens=0,
        session_total_tokens=0,
        session_estimated_cost_usd=0.0,
        session_cost_status="ok",
        session_cost_source="test",
        context_compressor=SimpleNamespace(last_prompt_tokens=0),
        _tool_guardrail_halt_decision=None,
        _response_was_previewed=False,
        _interrupt_message=None,
        _stream_callback=None,
        _turn_failed_file_mutations={},
        _skill_nudge_interval=0,
        _iters_since_skill=0,
        valid_tool_names=set(),
        _run_codex_app_server_turn=fake_codex_turn,
        _save_trajectory=lambda *a, **k: None,
        _cleanup_task_resources=lambda *a, **k: None,
        _drop_trailing_empty_response_scaffolding=lambda *a, **k: None,
        _persist_session=lambda *a, **k: None,
        _turn_completion_explainer_enabled=lambda: False,
        _file_mutation_verifier_enabled=lambda: False,
        _format_file_mutation_failure_footer=lambda *a, **k: "",
        _format_turn_completion_explanation=lambda *a, **k: "",
        _drain_pending_steer=lambda: None,
        _sync_external_memory_for_turn=lambda *a, **k: None,
        _spawn_background_review=lambda *a, **k: None,
        clear_interrupt=lambda: None,
        _safe_print=lambda *a, **k: None,
        _emit_status=lambda *a, **k: None,
        _handle_max_iterations=lambda *a, **k: "",
    )

    result = conversation_loop.run_conversation(agent, "/goal core API ingress hardwire")

    assert result["final_response"] == "controller drove"
    assert len(delegate_calls) == 3
    assert captured != {}
    assert "WARROOM V3 global_plan_adversary enforced state created." in captured["user_message"]
    assert "real delegated role runtime missing" not in captured["user_message"]
    state = load_warroom_goal("sid-core-global-goal")
    assert state is not None
    assert state.status == "active"
    assert state.gates["delegate_runtime"] == "pass"
    assert state.gates["controller_kickoff"] == "pass"


def test_acp_goal_command_uses_global_hardwire_without_goalmanager(hermes_home, tmp_path, monkeypatch):
    pytest.importorskip("acp")
    from types import SimpleNamespace
    from acp_adapter.server import HermesACPAgent
    from hermes_cli.goals import GoalManager
    from hermes_cli.warroom_goal import load_warroom_goal

    server = object.__new__(HermesACPAgent)
    server.session_manager = SimpleNamespace(save_session=lambda session_id: None)
    parent_agent = SimpleNamespace(session_id="sid-acp-global-goal")
    calls = _fake_background_delegate(monkeypatch)
    state = SimpleNamespace(session_id="sid-acp-global-goal", cwd=tmp_path, queued_prompts=[], agent=parent_agent)

    response = HermesACPAgent._cmd_goal(server, "ACP ingress hardwire", state)

    assert "WARROOM V3 global_plan_adversary" in response
    assert "real delegated role runtime missing" not in response
    assert state.queued_prompts
    assert "WARROOM V3 CONTROLLER" in state.queued_prompts[0]
    assert len(calls) == 3
    assert GoalManager("sid-acp-global-goal").state is None
    state_record = load_warroom_goal("sid-acp-global-goal")
    assert state_record is not None
    assert state_record.workflow == "global_plan_adversary"
    assert state_record.gates["delegate_runtime"] == "pass"



def test_warroom_goal_clears_legacy_goalmanager_state(hermes_home, tmp_path):
    from hermes_cli.goals import GoalManager
    from hermes_cli.warroom_goal import create_warroom_goal

    mgr = GoalManager("sid-clear-legacy")
    mgr.set("old budget loop", max_turns=3)
    assert mgr.has_goal()

    create_warroom_goal(
        "sid-clear-legacy",
        "global hardwire replaces old goal loop",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )

    cleared = GoalManager("sid-clear-legacy")
    assert cleared.state is not None
    assert cleared.state.status == "cleared"
    assert not cleared.has_goal()
    assert not cleared.is_active()


def test_plan_build_roles_auto_start_when_builder_mutation_reaches_policy(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, load_warroom_goal, save_warroom_goal

    state = create_warroom_goal(
        "sid-auto-build-roles",
        "ship plan then build",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert set(state.role_records) == {"controller", "plan_builder", "plan_adversary", "plan_reviewer"}
    _unlock_runtime_for_policy_test(state)
    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    state.current_role = "builder"
    save_warroom_goal("sid-auto-build-roles", state)

    blocked = enforce_tool_policy("sid-auto-build-roles", "write_file", {"path": str(tmp_path / "x.py")})
    assert blocked is not None
    assert "real delegated role runtime missing" in blocked
    updated = load_warroom_goal("sid-auto-build-roles")
    assert updated is not None
    assert {"builder", "adversary", "reviewer", "guardian"}.issubset(updated.role_records)
    assert updated.gates["build_role_spawn"] == "gap"
    assert updated.required_action == "blocked_gap"


def test_noncritical_stop_phrase_is_auto_continued_in_final_guard(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, load_warroom_goal

    create_warroom_goal(
        "sid-noncritical-text",
        "ship without approval tennis",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    response = guard_final_response("sid-noncritical-text", "Phase complete. Waiting for approval before live promotion.", closure=True)
    assert "auto_continued" in response
    state = load_warroom_goal("sid-noncritical-text")
    assert state.status == "active"
    assert state.noncritical_pause_attempts[-1]["decision"] == "auto_continued"



def test_goal_completion_output_hardwire_emits_goal_completed(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, load_warroom_goal, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-completion-output",
        "Use plan adversary skill for:\n\nGoal:\nwire completion output\n\nAcceptance:\n- goal completed line\n\nConstraints:\n- worktree only\n\nVerify with:\npytest",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    proof = tmp_path / "proof-packet.md"
    proof.write_text("PROOF PACKET\nTests: PASS\nRole evidence: PASS\n", encoding="utf-8")
    state.proof_packet_path = str(proof)
    save_warroom_goal("sid-completion-output", state)
    guardian = tmp_path / "guardian.txt"
    guardian.write_text("Guardian verdict: PASS\n", encoding="utf-8")
    record_role_output("sid-completion-output", "guardian", evidence_path=str(guardian), verdict="PASS")

    output = guard_final_response("sid-completion-output", "DONE. pytest E2E passed and proof packet written.", closure=True)

    assert output.startswith("GOAL COMPLETED")
    assert "Workflow: strict_plan_adversary" in output
    assert f"Proof packet: {proof}" in output
    assert "Guardian verdict: PASS" in output
    assert "Normal chat fallback: NO" in output
    assert "Original final response:" in output
    state = load_warroom_goal("sid-completion-output")
    assert state.status == "done"
    assert state.gates["proof_packet"] == "pass"
    assert state.gates["e2e_claim"] == "pass"
    assert "GOAL COMPLETED emitted" in state.gate_evidence["completion_output"]
