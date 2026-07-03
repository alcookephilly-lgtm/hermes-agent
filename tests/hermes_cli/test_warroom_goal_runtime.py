from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import time

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
    goal_heading: str = "Goal:",
    acceptance_heading: str = "Acceptance:",
    constraints_heading: str = "Constraints:",
    verify_heading: str = "Verify with:",
) -> str:
    return (
        "Use plan adversary skill for:\n\n"
        f"{goal_heading}\n"
        "build hardwire\n\n"
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
    state.gate_evidence.setdefault("ponytail", ["PONYTAIL_REVIEW:test fixture"])
    return state


def _mark_non_guardian_roles_done_for_final(state, tmp_path: Path):
    role_spawn = tmp_path / "role-spawn-evidence.json"
    role_spawn.write_text('{"records":{}}\n', encoding="utf-8")
    state.role_spawn_evidence_path = str(role_spawn)
    for role in state.required_roles:
        if role in {"controller", "guardian"}:
            continue
        evidence = tmp_path / f"{role}-final-evidence.txt"
        evidence.write_text(f"{role} evidence PASS\n", encoding="utf-8")
        record = state.role_records[role]
        record.update(
            {
                "child_session_id": f"child-{role}",
                "delegation_id": f"delegation-{role}",
                "runtime_kind": "real_child_session",
                "spawn_receipt_only": False,
                "status": "done",
                "current_phase": "done",
                "evidence_path": str(evidence),
                "evidence_truth": {"ok": True, "reason": "test_evidence", "path": str(evidence)},
            }
        )
        state.active_role_run_ids.pop(role, None)
        state.role_records[role] = record
    return state


def _agt_events(home: Path):
    for path in (home / "logs" / "agt_action_gateway.jsonl", home / "agt_action_gateway.jsonl"):
        if path.exists():
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return []



def _fake_background_delegate(monkeypatch):
    calls = []

    def fake_delegate_task(**kwargs):
        calls.append(kwargs)
        parent_agent = kwargs.get("parent_agent")
        return json.dumps(
            {
                "status": "dispatched",
                "delegation_id": f"delegation-{len(calls)}",
                "mode": "background",
                "model": getattr(parent_agent, "model", None),
                "provider": getattr(parent_agent, "provider", None),
            }
        )

    import tools.delegate_tool as delegate_tool

    monkeypatch.setattr(delegate_tool, "delegate_task", fake_delegate_task)
    return calls


def _write_graph_report(path: Path, corpus_root: Path, *, age_seconds: int = 0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Graph Report - "
        f"{corpus_root}  (2026-06-24)\n\n"
        "## Corpus Check\n"
        "- synthetic test fixture\n",
        encoding="utf-8",
    )
    if age_seconds:
        stamp = time.time() - age_seconds
        os.utime(path, (stamp, stamp))
    return path


def test_extract_graph_report_path_converts_windows_path_to_wsl():
    from hermes_cli.warroom_goal import _extract_graph_report_path

    goal_text = (
        _strict_goal()
        + "\ngraphify: Shared graph is at "
        + r"C:\Users\Paul\Shared Repo\graphify-out\GRAPH_REPORT.md"
        + ". Gate=BLOCK: graph stale: age=172470s."
    )

    assert _extract_graph_report_path(goal_text) == Path(
        "/mnt/c/Users/Paul/Shared Repo/graphify-out/GRAPH_REPORT.md"
    )


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


def test_detect_warroom_goal_accepts_exact_strict_headings_only():
    from hermes_cli.warroom_goal import detect_warroom_goal

    strict = detect_warroom_goal(_strict_goal())
    assert strict is not None
    assert strict.workflow == "strict_plan_adversary"
    assert strict.missing_sections == []


@pytest.mark.parametrize("goal_heading", ["Goals:", "Goal -", "Goal for this planning session:", "Objective:"])
def test_detect_warroom_goal_requires_exact_goal_heading(goal_heading):
    from hermes_cli.warroom_goal import detect_warroom_goal

    strict = detect_warroom_goal(_strict_goal(goal_heading=goal_heading))
    assert strict is not None
    assert strict.workflow == "strict_plan_adversary"
    assert strict.missing_sections == ["Goal"]


@pytest.mark.parametrize(
    ("acceptance_heading", "constraints_heading", "verify_heading", "missing"),
    [
        ("Acceptance for this planning session:", "Constraints:", "Verify with:", ["Acceptance"]),
        ("Acceptance criteria:", "Constraints:", "Verify with:", ["Acceptance"]),
        ("Acceptance:", "Boundaries:", "Verify with:", ["Constraints"]),
        ("Acceptance:", "Constraints:", "Verification:", ["Verify with"]),
        ("Acceptance:", "Constraints:", "Commands to run:", ["Verify with"]),
    ],
)
def test_detect_warroom_goal_blocks_strict_heading_variants(acceptance_heading, constraints_heading, verify_heading, missing):
    from hermes_cli.warroom_goal import detect_warroom_goal

    strict = detect_warroom_goal(
        _strict_goal(
            acceptance_heading=acceptance_heading,
            constraints_heading=constraints_heading,
            verify_heading=verify_heading,
        )
    )
    assert strict is not None
    assert strict.workflow == "strict_plan_adversary"
    assert strict.missing_sections == missing


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
    parent_agent = type("ParentAgent", (), {"model": "gpt-5.5", "provider": "openai-codex"})()
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


def test_stale_graphify_report_refreshes_and_continues(hermes_home, tmp_path, monkeypatch):
    from hermes_cli import warroom_goal
    from hermes_cli.warroom_goal import create_warroom_goal

    tracking = tmp_path / "tracking"
    tracking.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    report = _write_graph_report(repo / "graphify-out" / "GRAPH_REPORT.md", repo, age_seconds=90000)
    refresh_calls = []
    calls = _fake_background_delegate(monkeypatch)
    parent_agent = type("ParentAgent", (), {"model": "gpt-5.5", "provider": "openai-codex"})()

    monkeypatch.setattr(warroom_goal, "_repo_root_for", lambda path: repo)
    monkeypatch.setattr(warroom_goal, "_graphify_refresh_command", lambda repo_root: ["graphify-refresh-safe"])

    def fake_run(command, **kwargs):
        refresh_calls.append({"command": list(command), "cwd": kwargs.get("cwd")})
        _write_graph_report(report, repo, age_seconds=0)
        os.utime(report, None)
        return type("Proc", (), {"returncode": 0, "stdout": "refreshed", "stderr": ""})()

    monkeypatch.setattr(warroom_goal.subprocess, "run", fake_run)

    state = create_warroom_goal(
        "sid-graphify-refresh",
        _strict_goal(),
        tracking_dir=str(tracking),
        allowed_mutation_root=str(repo),
        parent_agent=parent_agent,
    )

    assert refresh_calls == [{"command": ["graphify-refresh-safe"], "cwd": str(repo)}]
    assert state.gates["graphify"] == "pass"
    assert state.status == "active"
    assert state.gates["role_spawn"] == "pass"
    assert state.gates["delegate_runtime"] == "pass"
    assert any(item.startswith("GRAPH_REFRESHED:") for item in state.gate_evidence["graphify"])
    assert len(calls) == 3


def test_shared_same_corpus_stale_graphify_report_refreshes_from_shared_root(hermes_home, tmp_path, monkeypatch):
    from hermes_cli import warroom_goal
    from hermes_cli.warroom_goal import create_warroom_goal

    tracking = tmp_path / "tracking"
    tracking.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    shared_root = tmp_path / "Shared Corpus"
    shared_worktree = shared_root / "worktree"
    shared_worktree.mkdir(parents=True)
    shared_report = _write_graph_report(
        shared_root / "graphify-out" / "GRAPH_REPORT.md",
        shared_root,
        age_seconds=169457,
    )
    refresh_command_roots = []
    refresh_calls = []
    calls = _fake_background_delegate(monkeypatch)
    parent_agent = type("ParentAgent", (), {"model": "gpt-5.5", "provider": "openai-codex"})()

    monkeypatch.setattr(warroom_goal, "_repo_root_for", lambda path: repo)

    def fake_refresh_command(refresh_root):
        refresh_command_roots.append(refresh_root)
        return ["graphify-refresh-safe"]

    def fake_run(command, **kwargs):
        refresh_calls.append({"command": list(command), "cwd": kwargs.get("cwd")})
        _write_graph_report(shared_report, shared_root, age_seconds=0)
        os.utime(shared_report, None)
        return type("Proc", (), {"returncode": 0, "stdout": "refreshed", "stderr": ""})()

    monkeypatch.setattr(warroom_goal, "_graphify_refresh_command", fake_refresh_command)
    monkeypatch.setattr(warroom_goal.subprocess, "run", fake_run)

    state = create_warroom_goal(
        "sid-graphify-shared-refresh",
        _strict_goal() + f"\ngraphify: Shared graph is at {shared_report}. Gate=BLOCK: graph stale: age=169457s.",
        tracking_dir=str(tracking),
        allowed_mutation_root=str(shared_worktree),
        parent_agent=parent_agent,
    )

    assert refresh_command_roots
    assert all(root == shared_root for root in refresh_command_roots)
    assert refresh_calls == [{"command": ["graphify-refresh-safe"], "cwd": str(shared_root)}]
    assert state.gates["graphify"] == "pass"
    assert state.status == "active"
    assert state.gates["role_spawn"] == "pass"
    assert state.gates["delegate_runtime"] == "pass"
    assert any(item.startswith("GRAPH_REFRESHED:") for item in state.gate_evidence["graphify"])
    assert len(calls) == 3


def test_explicit_generated_shared_graph_report_refreshes_even_when_repo_outside_corpus(hermes_home, tmp_path, monkeypatch):
    from hermes_cli import warroom_goal
    from hermes_cli.warroom_goal import create_warroom_goal

    tracking = tmp_path / "tracking"
    tracking.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    shared_root = tmp_path / "Shared Corpus"
    shared_report = _write_graph_report(
        shared_root / "graphify-out" / "GRAPH_REPORT.md",
        shared_root,
        age_seconds=169457,
    )
    refresh_calls = []
    calls = _fake_background_delegate(monkeypatch)
    parent_agent = type("ParentAgent", (), {"model": "gpt-5.5", "provider": "openai-codex"})()

    monkeypatch.setattr(warroom_goal, "_repo_root_for", lambda path: repo)
    monkeypatch.setattr(warroom_goal, "_graphify_refresh_command", lambda refresh_root: ["graphify-refresh-safe"])

    def fake_run(command, **kwargs):
        refresh_calls.append({"command": list(command), "cwd": kwargs.get("cwd")})
        _write_graph_report(shared_report, shared_root, age_seconds=0)
        os.utime(shared_report, None)
        return type("Proc", (), {"returncode": 0, "stdout": "refreshed", "stderr": ""})()

    monkeypatch.setattr(warroom_goal.subprocess, "run", fake_run)

    state = create_warroom_goal(
        "sid-graphify-explicit-shared-refresh",
        _strict_goal()
        + f"\ngraphify: Shared graph is at {shared_report}. Gate=PASS only when shared graph + report are fresh."
        + "\nDo not mutate source files.",
        tracking_dir=str(tracking),
        allowed_mutation_root=str(repo),
        parent_agent=parent_agent,
    )

    assert refresh_calls == [{"command": ["graphify-refresh-safe"], "cwd": str(shared_root)}]
    assert state.gates["graphify"] == "pass"
    assert state.status == "active"
    assert any(item.startswith("GRAPH_SHARED_REPORT_SELECTED:") for item in state.gate_evidence["graphify"])
    assert any(item.startswith("GRAPH_REFRESHED:") for item in state.gate_evidence["graphify"])
    assert len(calls) == 3


def test_stale_graphify_no_index_boundary_halts_without_refresh(hermes_home, tmp_path, monkeypatch):
    from hermes_cli import warroom_goal
    from hermes_cli.warroom_goal import create_warroom_goal

    tracking = tmp_path / "tracking"
    tracking.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    _write_graph_report(repo / "graphify-out" / "GRAPH_REPORT.md", repo, age_seconds=90000)
    refresh_calls = []

    monkeypatch.setattr(warroom_goal, "_repo_root_for", lambda path: repo)
    monkeypatch.setattr(warroom_goal, "_graphify_refresh_command", lambda repo_root: ["graphify-refresh-safe"])

    def fail_run(*args, **kwargs):
        refresh_calls.append(args[0] if args else kwargs.get("args"))
        raise AssertionError("graph refresh should not run")

    monkeypatch.setattr(warroom_goal.subprocess, "run", fail_run)

    state = create_warroom_goal(
        "sid-graphify-no-index",
        _strict_goal() + "\nNo-index boundary.",
        tracking_dir=str(tracking),
        allowed_mutation_root=str(repo),
    )

    assert state.status in {"blocked", "gap"}
    assert state.gates["graphify"] == "blocked"
    assert "explicit_no_index_boundary" in (state.last_gap or "")
    assert refresh_calls == []


def test_stale_graphify_refresh_rc0_noop_stays_gap(hermes_home, tmp_path, monkeypatch):
    from hermes_cli import warroom_goal
    from hermes_cli.warroom_goal import create_warroom_goal

    tracking = tmp_path / "tracking"
    tracking.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    report = _write_graph_report(repo / "graphify-out" / "GRAPH_REPORT.md", repo, age_seconds=90000)
    refresh_calls = []
    calls = _fake_background_delegate(monkeypatch)
    parent_agent = type("ParentAgent", (), {"model": "gpt-5.5", "provider": "openai-codex"})()

    monkeypatch.setattr(warroom_goal, "_repo_root_for", lambda path: repo)
    monkeypatch.setattr(warroom_goal, "_graphify_refresh_command", lambda refresh_root: ["graphify-refresh-safe"])

    def fake_run(command, **kwargs):
        refresh_calls.append({"command": list(command), "cwd": kwargs.get("cwd")})
        assert report.exists()
        return type("Proc", (), {"returncode": 0, "stdout": "noop", "stderr": ""})()

    monkeypatch.setattr(warroom_goal.subprocess, "run", fake_run)

    state = create_warroom_goal(
        "sid-graphify-noop-refresh",
        _strict_goal(),
        tracking_dir=str(tracking),
        allowed_mutation_root=str(repo),
        parent_agent=parent_agent,
    )

    assert refresh_calls == [{"command": ["graphify-refresh-safe"], "cwd": str(repo)}]
    assert state.status == "gap"
    assert state.gates["graphify"] == "gap"
    assert "refresh_output_still_stale" in (state.last_gap or "")
    assert state.gates["role_spawn"] != "pass"
    assert state.gates["delegate_runtime"] == "pending"
    assert len(calls) == 0


def test_explicit_non_generated_wrong_corpus_graph_report_gaps(hermes_home, tmp_path, monkeypatch):
    from hermes_cli import warroom_goal
    from hermes_cli.warroom_goal import create_warroom_goal

    tracking = tmp_path / "tracking"
    tracking.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    shared_root = tmp_path / "shared"
    foreign_root = tmp_path / "other"
    shared_report = _write_graph_report(shared_root / "reports" / "GRAPH_REPORT.md", foreign_root, age_seconds=0)
    calls = _fake_background_delegate(monkeypatch)
    parent_agent = type("ParentAgent", (), {"model": "gpt-5.5", "provider": "openai-codex"})()

    monkeypatch.setattr(warroom_goal, "_repo_root_for", lambda path: repo)

    state = create_warroom_goal(
        "sid-graphify-wrong-corpus",
        _strict_goal() + f"\ngraphify: Shared graph is at {shared_report}. Gate=BLOCK: graph stale: age=169457s.",
        tracking_dir=str(tracking),
        allowed_mutation_root=str(repo),
        parent_agent=parent_agent,
    )

    assert state.gates["graphify"] == "gap"
    assert state.status == "gap"
    assert any(item.startswith("GRAPH_NOT_APPLICABLE:") for item in state.gate_evidence["graphify"])
    assert "preferred_report_not_generated_or_header_unparseable" in (state.last_gap or "")
    assert len(calls) == 0


def test_explicit_header_unparseable_graph_report_gaps(hermes_home, tmp_path, monkeypatch):
    from hermes_cli import warroom_goal
    from hermes_cli.warroom_goal import create_warroom_goal

    tracking = tmp_path / "tracking"
    tracking.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    shared_root = tmp_path / "Shared Corpus"
    shared_report = shared_root / "graphify-out" / "GRAPH_REPORT.md"
    shared_report.parent.mkdir(parents=True)
    shared_report.write_text("# Broken Report\n\nNo generated root header here.\n", encoding="utf-8")
    calls = _fake_background_delegate(monkeypatch)
    parent_agent = type("ParentAgent", (), {"model": "gpt-5.5", "provider": "openai-codex"})()
    monkeypatch.setattr(warroom_goal, "_repo_root_for", lambda path: repo)

    state = create_warroom_goal(
        "sid-graphify-header-unparseable",
        _strict_goal() + f"\ngraphify: Shared graph is at {shared_report}. Gate=PASS only when shared graph + report are fresh.",
        tracking_dir=str(tracking),
        allowed_mutation_root=str(repo),
        parent_agent=parent_agent,
    )

    assert state.gates["graphify"] == "gap"
    assert state.status == "gap"
    assert any(item.startswith("GRAPH_REPORT_HEADER_UNPARSEABLE:") for item in state.gate_evidence["graphify"])
    assert "preferred_report_not_generated_or_header_unparseable" in (state.last_gap or "")
    assert len(calls) == 0


def test_no_explicit_graph_wrong_local_corpus_uses_alternate_discovery_with_route_hint(hermes_home, tmp_path, monkeypatch):
    from hermes_cli import warroom_goal
    from hermes_cli.warroom_goal import create_warroom_goal

    tracking = tmp_path / "tracking"
    tracking.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    foreign_root = tmp_path / "foreign"
    local_report = _write_graph_report(repo / "graphify-out" / "GRAPH_REPORT.md", foreign_root, age_seconds=0)
    calls = _fake_background_delegate(monkeypatch)
    parent_agent = type("ParentAgent", (), {"model": "gpt-5.5", "provider": "openai-codex"})()
    monkeypatch.setattr(warroom_goal, "_repo_root_for", lambda path: repo)
    monkeypatch.setattr(
        warroom_goal.shutil,
        "which",
        lambda tool_name: "/bin/mcp2cli" if tool_name == "mcp2cli" else None,
    )

    state = create_warroom_goal(
        "sid-graphify-no-explicit-wrong-local",
        _strict_goal(),
        tracking_dir=str(tracking),
        allowed_mutation_root=str(repo),
        parent_agent=parent_agent,
    )

    assert state.gates["graphify"] == "pass"
    assert state.status == "active"
    assert any(item.startswith(f"GRAPH_NOT_APPLICABLE:{local_report}") for item in state.gate_evidence["graphify"])
    assert "GRAPH_ALTERNATE_DISCOVERY:mcp2cli" in state.gate_evidence["graphify"]
    assert any(item.startswith("SMART_READ_ROUTE_HINT:") for item in state.gate_evidence["graphify"])
    assert "GRAPHIFY_DISCOVERY_PASS:smart-read route available for graph report recovery" in state.gate_evidence["graphify"]
    assert len(calls) == 3


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
        "Use plan adversary skill for:\n\nGoal:\nbuild hardwire\n\nAcceptance:\n- proof\n\nConstraints:\n- worktree only\n\nVerify with:\npytest",
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
    assert state.last_gap == "Missing required strict sections: Goal, Acceptance, Constraints, Verify with"
    assert state.gates["plan"] == "blocked"
    assert state.gates["role_spawn"] == "blocked"
    assert state.required_action is None

    notice = notice_for_state(state)
    assert "GAP: Missing required strict sections: Goal, Acceptance, Constraints, Verify with" in notice
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
    assert blocked == "WARROOM V3 blocked: Missing required strict sections: Goal, Acceptance, Constraints, Verify with"
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
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-final",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    blocked = guard_final_response("sid-final", "DONE. Health check passed.", closure=True)
    assert "blocked" in blocked.lower()
    assert "proof packet" in blocked.lower()

    state.proof_packet_path = str(tmp_path / "proof-packet.md")
    Path(state.proof_packet_path).write_text("Status: PASS\nGuardian verdict: PASS\n", encoding="utf-8")
    _mark_non_guardian_roles_done_for_final(state, tmp_path)
    state.role_records["guardian"]["child_session_id"] = "child-guardian"
    state.role_records["guardian"]["delegation_id"] = "delegation-guardian"
    state.role_records["guardian"]["runtime_kind"] = "real_child_session"
    state.role_records["guardian"]["spawn_receipt_only"] = False
    save_warroom_goal("sid-final", state)
    guardian = tmp_path / "guardian.txt"
    guardian.write_text("Guardian verdict: PASS\n", encoding="utf-8")
    record_role_output("sid-final", "guardian", evidence_path=str(guardian), verdict="PASS")
    blocked = guard_final_response("sid-final", "DONE. Health check passed.", closure=True)
    assert "health check" in blocked.lower()

    ok = guard_final_response("sid-final", "DONE. pytest E2E passed and proof packet written.", closure=True)
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
        if role == "guardian":
            assert record["runtime_kind"] == "scheduler_queue"
            assert record["spawn_receipt_only"] is False
        else:
            assert role == "controller" or record["runtime_kind"] == "spawn_receipt"
            assert role == "controller" or record["spawn_receipt_only"] is True
    assert Path(state.role_spawn_evidence_path).exists()



def test_wave4_stale_async_result_is_quarantined_and_cannot_overwrite_final_state(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import (
        create_warroom_goal,
        load_warroom_goal,
        record_role_output,
        save_warroom_goal,
        warroom_state_hash,
    )

    state = create_warroom_goal(
        "sid-wave4-stale-async",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.status = "active"
    state.role_records["reviewer"] = {
        "role": "reviewer",
        "status": "active_child_work",
        "current_phase": "reviewing",
        "runtime_kind": "real_child_session",
        "child_session_id": "child-reviewer-1",
        "delegation_id": "delegation-reviewer-1",
        "evidence_path": str(tmp_path / "current-reviewer.json"),
        "last_seen_at": "old",
        "last_seen_epoch": 1,
        "stale": False,
        "stale_reason": None,
    }
    old_hash = warroom_state_hash(state)
    final_proof = tmp_path / "final-proof.md"
    final_proof.write_text("final proof stays current\n", encoding="utf-8")
    state.proof_packet_path = str(final_proof)
    state.guardian_pass = True
    state.final_claim_allowed = True
    state.status = "done"
    save_warroom_goal("sid-wave4-stale-async", state)

    late = tmp_path / "late-reviewer.md"
    late.write_text("late stale result\n", encoding="utf-8")
    updated = record_role_output(
        "sid-wave4-stale-async",
        "reviewer",
        evidence_path=str(late),
        status="completed",
        expected_state_hash=old_hash,
        expected_state_version=state.version,
        child_session_id="child-reviewer-1",
        delegation_id="delegation-reviewer-1",
    )
    assert updated is not None

    record = updated.role_records["reviewer"]
    assert record["status"] == "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION"
    assert record["current_phase"] == "quarantined"
    assert record["quarantine_status"] == "quarantined"
    assert record["state_class"] == "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION"
    quarantine = json.loads(Path(record["quarantine_path"]).read_text(encoding="utf-8"))
    assert quarantine["status"] == "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION"
    assert quarantine["state_class"] == "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION"
    assert quarantine["role"] == "reviewer"
    assert quarantine["evidence_path"] == str(late)
    assert quarantine["target_scope"] == str(tmp_path)
    assert "current_state_hash" in quarantine
    assert "rescue/requeue" in quarantine["next_safe_action"]
    assert record["quarantined_evidence_path"] == str(late)
    fresh = load_warroom_goal("sid-wave4-stale-async")
    assert fresh is not None
    assert fresh.status == "done"
    assert fresh.proof_packet_path == str(final_proof)
    assert fresh.final_claim_allowed is True



def test_wave4_heartbeat_updates_real_child_and_receipt_only_cannot_upgrade(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, record_child_progress, save_warroom_goal

    state = create_warroom_goal(
        "sid-wave4-heartbeat",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.role_records["reviewer"] = {
        "role": "reviewer",
        "status": "running",
        "current_phase": "spawned",
        "runtime_kind": "real_child_session",
        "child_session_id": "child-reviewer-heartbeat",
        "delegation_id": "delegation-reviewer-heartbeat",
        "runtime_id": "runtime-reviewer-heartbeat",
        "evidence_path": str(tmp_path / "reviewer-evidence.json"),
        "last_seen_at": "old",
        "last_seen_epoch": 1,
        "stale": True,
        "stale_reason": "old",
    }
    pid_record = next(record for role, record in state.role_records.items() if role != "controller" and str(record.get("runtime_id", "")).startswith("pid:"))
    pid_runtime_id = pid_record["runtime_id"]
    pid_role = pid_record["role"]
    save_warroom_goal("sid-wave4-heartbeat", state)

    updated = record_child_progress(
        "sid-wave4-heartbeat",
        child_session_id="child-reviewer-heartbeat",
        delegation_id="delegation-reviewer-heartbeat",
        phase="running focused tests",
    )
    assert updated is not None
    real = updated.role_records["reviewer"]
    assert real["status"] == "active_child_work"
    assert real["current_phase"] == "running focused tests"
    assert real["stale"] is False
    assert real["last_seen_epoch"] > 1
    assert Path(real["last_heartbeat_path"]).exists()

    updated = record_child_progress(
        "sid-wave4-heartbeat",
        runtime_id=pid_runtime_id,
        phase="heartbeat without child id",
        status="active_child_work",
    )
    assert updated is not None
    receipt = updated.role_records[pid_role]
    assert receipt["status"] == "spawn_receipt_only"
    assert receipt["current_phase"] == "heartbeat without child id"
    assert receipt["runtime_kind"] == "spawn_receipt"
    assert receipt["spawn_receipt_only"] is True



def test_wave4_stalled_role_gets_diagnostic_packet(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, mark_role_stalled, save_warroom_goal

    evidence = tmp_path / "reviewer-evidence.json"
    evidence.write_text("{}\n", encoding="utf-8")
    state = create_warroom_goal(
        "sid-wave4-stalled",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.role_records["reviewer"] = {
        "role": "reviewer",
        "status": "active_child_work",
        "current_phase": "running command",
        "runtime_kind": "real_child_session",
        "runtime_id": "runtime-reviewer-timeout",
        "child_session_id": "child-reviewer-timeout",
        "delegation_id": "delegation-reviewer-timeout",
        "evidence_path": str(evidence),
        "last_seen_at": "2026-06-26T00:00:00Z",
        "last_seen_epoch": 1,
    }
    save_warroom_goal("sid-wave4-stalled", state)

    stalled = mark_role_stalled(
        "sid-wave4-stalled",
        "reviewer",
        runtime_id="runtime-reviewer-timeout",
        child_session_id="child-reviewer-timeout",
        delegation_id="delegation-reviewer-timeout",
        elapsed=301.2,
        current_phase="running command",
        evidence_path=str(evidence),
        next_safe_action="harvest then rescue",
    )
    assert stalled is not None
    record = stalled.role_records["reviewer"]
    assert record["status"] == "stalled"
    diagnostic = json.loads(Path(record["diagnostic_path"]).read_text(encoding="utf-8"))
    assert diagnostic["role"] == "reviewer"
    assert diagnostic["runtime_id"] == "runtime-reviewer-timeout"
    assert diagnostic["child_session_id"] == "child-reviewer-timeout"
    assert diagnostic["delegation_id"] == "delegation-reviewer-timeout"
    assert diagnostic["elapsed"] == 301.2
    assert diagnostic["last_seen_at"] == "2026-06-26T00:00:00Z"
    assert diagnostic["current_phase"] == "running command"
    assert diagnostic["evidence_path"] == str(evidence)
    assert diagnostic["next_safe_action"] == "harvest then rescue"


@pytest.mark.parametrize(
    ("session_id", "goal"),
    [
        ("sid-wave4-adversary-path", "Use adversary skill for: build hardwire"),
        ("sid-wave4-plan-adversary-path", _strict_goal()),
    ],
)
def test_wave4_adversary_and_plan_paths_share_stale_heartbeat_logic(hermes_home, tmp_path, session_id, goal):
    from hermes_cli.warroom_goal import create_warroom_goal, record_child_progress, record_role_output, save_warroom_goal, warroom_state_hash

    state = create_warroom_goal(
        session_id,
        goal,
        tracking_dir=str(tmp_path / session_id),
        allowed_mutation_root=str(tmp_path),
    )
    state.status = "active"
    state.role_records["reviewer"] = {
        "role": "reviewer",
        "status": "running",
        "current_phase": "spawned",
        "runtime_kind": "real_child_session",
        "child_session_id": f"child-{session_id}",
        "delegation_id": f"delegation-{session_id}",
        "evidence_path": str(tmp_path / f"{session_id}-evidence.json"),
        "last_seen_at": "old",
        "last_seen_epoch": 1,
    }
    save_warroom_goal(session_id, state)
    updated = record_child_progress(session_id, child_session_id=f"child-{session_id}", phase="phase-one")
    assert updated is not None
    assert updated.role_records["reviewer"]["status"] == "active_child_work"
    assert updated.role_records["reviewer"]["current_phase"] == "phase-one"

    old_hash = warroom_state_hash(updated)
    updated.status = "done"
    save_warroom_goal(session_id, updated)
    late = tmp_path / f"{session_id}-late.md"
    late.write_text("late\n", encoding="utf-8")
    quarantined = record_role_output(
        session_id,
        "reviewer",
        evidence_path=str(late),
        status="completed",
        expected_state_hash=old_hash,
        expected_state_version=updated.version,
        child_session_id=f"child-{session_id}",
    )
    assert quarantined is not None
    assert quarantined.role_records["reviewer"]["status"] == "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION"
    assert quarantined.role_records["reviewer"]["current_phase"] == "quarantined"
    assert quarantined.role_records["reviewer"]["quarantine_status"] == "quarantined"



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


def test_strict_plan_starts_plan_roles_then_build_roles_after_gates(hermes_home, tmp_path, monkeypatch):
    from hermes_cli.warroom_goal import _native_background_delegate_adapter, create_warroom_goal, record_role_output, save_warroom_goal, start_plan_build_roles_if_ready

    class Parent:
        model = "gpt-5.5"
        provider = "nous"

    parent = Parent()
    calls = _fake_background_delegate(monkeypatch)

    state = create_warroom_goal(
        "sid-plan-sequence",
        "Use plan adversary skill for:\n\nGoal:\nbuild hardwire\n\nAcceptance:\n- proof\n\nConstraints:\n- worktree only\n\nVerify with:\npytest",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
        parent_agent=parent,
    )
    assert set(state.role_records) == {"controller", "plan_builder", "plan_adversary", "plan_reviewer"}
    assert "builder" not in state.role_records

    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    save_warroom_goal("sid-plan-sequence", state)
    for role in ["plan_builder", "plan_adversary", "plan_reviewer"]:
        evidence = tmp_path / f"{role}-evidence.txt"
        evidence.write_text(f"{role} evidence", encoding="utf-8")
        state = record_role_output(
            "sid-plan-sequence",
            role,
            evidence_path=str(evidence),
            status="done",
            delegation_id=state.role_records[role]["delegation_id"],
            expected_role_run_id=state.role_run_ids[role],
        )
    assert state is not None
    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    save_warroom_goal("sid-plan-sequence", state)
    advanced = start_plan_build_roles_if_ready("sid-plan-sequence", adapter=_native_background_delegate_adapter(parent), use_local_process=False)
    assert advanced is not None
    dispatched_roles = [call["goal"].split("Role: ", 1)[1].split("\n", 1)[0] for call in calls]
    assert dispatched_roles == [
        "plan_builder",
        "plan_adversary",
        "plan_reviewer",
        "builder",
        "adversary",
        "reviewer",
    ]
    assert advanced.role_records["guardian"]["status"] == "queued"
    assert advanced.role_queue == ["guardian"]
    assert advanced.gates["build_role_spawn"] in {"pass", "partial_pass_queued"}
    assert advanced.required_action in {None, "continue_scheduler"}
    assert advanced.last_gap is None


def test_fast_adversary_scheduler_caps_three_and_queues_guardian(hermes_home, tmp_path, monkeypatch):
    from hermes_cli.warroom_goal import create_warroom_goal

    class Parent:
        model = "gpt-5.5"
        provider = "nous"

    calls = _fake_background_delegate(monkeypatch)
    state = create_warroom_goal(
        "sid-fast-scheduler",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
        parent_agent=Parent(),
    )

    dispatched_roles = [call["goal"].split("Role: ", 1)[1].split("\n", 1)[0] for call in calls]
    assert dispatched_roles == ["builder", "adversary", "reviewer"]
    assert state.max_active_non_controller_roles == 3
    assert state.role_queue == ["guardian"]
    assert state.role_records["guardian"]["status"] == "queued"
    assert state.role_records["guardian"]["runtime_id"] == "queued"
    assert state.gates["role_spawn"] == "partial_pass_queued"
    assert state.gates["delegate_runtime"] == "pass"
    assert state.status == "active"
    assert state.required_action == "continue_scheduler"
    assert state.last_gap is None


def test_async_capacity_rejection_queues_role_without_gap_or_fallback(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, save_warroom_goal, start_warroom_roles

    state = create_warroom_goal(
        "sid-capacity-queue",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.status = "active"
    state.gates["role_spawn"] = "pending"
    state.gates["delegate_runtime"] = "pending"
    state.required_action = "spawn_roles"
    save_warroom_goal("sid-capacity-queue", state)

    def capacity_full(**kwargs):
        raise RuntimeError("Async delegation capacity reached (3 running). Wait for one to finish")

    updated = start_warroom_roles("sid-capacity-queue", ["reviewer"], adapter=capacity_full, use_local_process=False)
    assert updated is not None
    assert updated.status == "active"
    assert updated.required_action == "continue_scheduler"
    assert updated.last_gap is None
    assert updated.role_spawn_gap is None
    assert "reviewer" in updated.role_queue
    assert updated.role_records["reviewer"]["status"] == "queued"
    assert updated.role_records["reviewer"]["adapter"] == "scheduler_queue"
    assert updated.role_records["reviewer"]["runtime_id"] == "queued"
    assert "spawn-failed" not in json.dumps(updated.role_records["reviewer"])


def test_guardian_starts_serial_after_dependencies_and_proof_packet(hermes_home, tmp_path, monkeypatch):
    from hermes_cli.warroom_goal import _native_background_delegate_adapter, create_warroom_goal, record_role_output, save_warroom_goal, start_warroom_roles

    class Parent:
        model = "gpt-5.5"
        provider = "nous"

    parent = Parent()
    calls = _fake_background_delegate(monkeypatch)
    state = create_warroom_goal(
        "sid-guardian-serial",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
        parent_agent=parent,
    )
    assert [call["goal"].split("Role: ", 1)[1].split("\n", 1)[0] for call in calls] == ["builder", "adversary", "reviewer"]

    for role in ["builder", "adversary", "reviewer"]:
        evidence = tmp_path / f"{role}-evidence.txt"
        evidence.write_text(f"{role} evidence", encoding="utf-8")
        state = record_role_output(
            "sid-guardian-serial",
            role,
            evidence_path=str(evidence),
            status="done",
            delegation_id=state.role_records[role]["delegation_id"],
            expected_role_run_id=state.role_run_ids[role],
        )
    assert state is not None
    state.proof_packet_path = str(tmp_path / "proof-packet.md")
    Path(state.proof_packet_path).write_text("proof packet", encoding="utf-8")
    save_warroom_goal("sid-guardian-serial", state)

    updated = start_warroom_roles("sid-guardian-serial", adapter=_native_background_delegate_adapter(parent), use_local_process=False)
    assert updated is not None
    dispatched_roles = [call["goal"].split("Role: ", 1)[1].split("\n", 1)[0] for call in calls]
    assert dispatched_roles == ["builder", "adversary", "reviewer", "guardian"]
    assert updated.role_queue == []
    assert updated.role_records["guardian"]["status"] == "active_child_work"


def test_stale_async_result_with_old_role_run_id_is_quarantined(hermes_home, tmp_path, monkeypatch):
    from hermes_cli.warroom_goal import create_warroom_goal, record_role_output, save_warroom_goal

    class Parent:
        model = "gpt-5.5"
        provider = "nous"

    _fake_background_delegate(monkeypatch)
    state = create_warroom_goal(
        "sid-stale-role-run-id",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
        parent_agent=Parent(),
    )
    stale_role_run_id = state.role_run_ids["adversary"]
    state.role_run_ids["adversary"] = "role-run-new"
    state.active_role_run_ids["adversary"] = "role-run-new"
    save_warroom_goal("sid-stale-role-run-id", state)

    evidence = tmp_path / "late-adversary.txt"
    evidence.write_text("late adversary evidence", encoding="utf-8")
    updated = record_role_output(
        "sid-stale-role-run-id",
        "adversary",
        evidence_path=str(evidence),
        status="done",
        delegation_id=state.role_records["adversary"]["delegation_id"],
        expected_role_run_id=stale_role_run_id,
    )

    assert updated is not None
    record = updated.role_records["adversary"]
    assert record["status"] == "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION"
    assert record["quarantine_status"] == "quarantined"
    assert "role_run_id" in record["stale_reason"]


def test_warroom_roles_record_controller_model_for_plan_and_adversary(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal

    class Parent:
        model = "gpt-5.5"

    plan = create_warroom_goal(
        "sid-plan-model",
        "Use plan adversary skill for:\n\nGoal:\nbuild hardwire\n\nAcceptance:\n- proof\n\nConstraints:\n- worktree only\n\nVerify with:\npytest",
        tracking_dir=str(tmp_path / "plan"),
        allowed_mutation_root=str(tmp_path),
        parent_agent=Parent(),
    )
    adversary = create_warroom_goal(
        "sid-adversary-model",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path / "adv"),
        allowed_mutation_root=str(tmp_path),
        parent_agent=Parent(),
    )

    assert plan.controller_model == "gpt-5.5"
    assert adversary.controller_model == "gpt-5.5"
    assert {r["model"] for r in plan.role_records.values()} == {"gpt-5.5"}
    assert {r["model"] for r in adversary.role_records.values()} == {"gpt-5.5"}


def test_late_async_role_output_is_quarantined_after_state_advanced(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-stale-async",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.status = "done"
    state.final_claim_allowed = True
    save_warroom_goal("sid-stale-async", state)

    updated = record_role_output(
        "sid-stale-async",
        "adversary",
        evidence_path=str(tmp_path / "late-adversary.txt"),
        status="done",
        verdict="PASS",
    )

    assert updated is not None
    assert updated.status == "done"
    assert updated.final_claim_allowed is True
    assert updated.role_records["adversary"]["status"] == "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION"
    assert updated.role_records["adversary"]["state_class"] == "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION"
    assert updated.role_records["adversary"]["stale"] is True
    assert "async_stale_quarantine" in updated.gate_evidence


def test_receipt_only_role_output_cannot_mark_active_or_completed(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, record_role_output

    state = create_warroom_goal(
        "sid-receipt-output-block",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert state.role_records["builder"]["spawn_receipt_only"] is True

    active = record_role_output(
        "sid-receipt-output-block",
        "builder",
        evidence_path=str(tmp_path / "builder-active.txt"),
        status="active_child_work",
    )
    assert active is not None
    assert active.role_records["builder"]["status"] == "spawn_receipt_only"
    assert active.role_records["builder"]["current_phase"] == "spawn_receipt_only"

    completed = record_role_output(
        "sid-receipt-output-block",
        "builder",
        evidence_path=str(tmp_path / "builder-completed.txt"),
        status="completed",
    )
    assert completed is not None
    assert completed.role_records["builder"]["status"] == "spawn_receipt_only"
    assert "receipt_only_verdict" in completed.gate_evidence

    done = record_role_output(
        "sid-receipt-output-block",
        "builder",
        evidence_path=str(tmp_path / "builder-done.txt"),
        status="done",
    )
    assert done is not None
    assert done.role_records["builder"]["status"] == "spawn_receipt_only"
    assert done.role_records["builder"]["spawn_receipt_only"] is True


def test_remote_vps_target_blocks_local_target_paths(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-remote-vps",
        "Use adversary skill for: build hardwire\nRemote target: vps",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "builder"
    save_warroom_goal("sid-remote-vps", state)

    assert state.remote_target == "vps"
    blocked_read = enforce_tool_policy("sid-remote-vps", "read_file", {"path": "/etc/passwd"})
    blocked_opt = enforce_tool_policy("sid-remote-vps", "read_file", {"path": "/opt/mls-vulture/config"})
    blocked_root = enforce_tool_policy("sid-remote-vps", "search_files", {"path": "/root", "pattern": "*.conf"})
    blocked_shell = enforce_tool_policy("sid-remote-vps", "terminal", {"command": "cat /opt/app/config.yaml"})
    allowed_ssh = enforce_tool_policy("sid-remote-vps", "terminal", {"command": "ssh vps 'cat /etc/passwd'", "workdir": str(tmp_path)})

    assert blocked_read and "ssh vps" in blocked_read
    assert blocked_opt and "ssh vps" in blocked_opt
    assert blocked_root and "ssh vps" in blocked_root
    assert blocked_shell and "ssh vps" in blocked_shell
    assert allowed_ssh is None
    events = _agt_events(hermes_home)
    remote_events = [event for event in events if event.get("remote_target") == "vps"]
    assert remote_events
    for event in remote_events:
        assert event.get("caller") == "hermes_cli.warroom_goal.enforce_tool_policy"
        assert event.get("role") == "builder"
        assert event.get("session_id") == "sid-remote-vps"
        assert event.get("reason")
        assert event.get("decision") in {"allow", "deny"}
        assert "attempted_path" in event and "attempted_command" in event


def test_remote_vps_mutating_ssh_requires_explicit_approval_state(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-remote-vps-mutate",
        "Use adversary skill for: build hardwire\nRemote target: vps",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "builder"
    save_warroom_goal("sid-remote-vps-mutate", state)

    blocked = enforce_tool_policy(
        "sid-remote-vps-mutate",
        "terminal",
        {"command": "ssh vps 'sudo systemctl restart hermes-gateway'", "workdir": str(tmp_path)},
    )
    assert blocked and "explicit approved mutation phase" in blocked

    state.gates["remote_mutation_approval"] = "pass"
    save_warroom_goal("sid-remote-vps-mutate", state)
    allowed = enforce_tool_policy(
        "sid-remote-vps-mutate",
        "terminal",
        {"command": "ssh vps 'sudo systemctl restart hermes-gateway'", "workdir": str(tmp_path)},
    )
    assert allowed is None


def test_local_build_doc_reads_remain_allowed_without_robot_hand_gap(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    doc = tmp_path / "build-note.md"
    doc.write_text("proof note", encoding="utf-8")
    state = create_warroom_goal(
        "sid-local-doc-read",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "controller"
    save_warroom_goal("sid-local-doc-read", state)

    assert enforce_tool_policy("sid-local-doc-read", "read_file", {"path": str(doc)}) is None


def test_robot_hand_discovery_required_before_raw_search_in_adversary_workflow(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-robot-adversary",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "controller"
    save_warroom_goal("sid-robot-adversary", state)

    blocked = enforce_tool_policy("sid-robot-adversary", "search_files", {"path": "/repo", "pattern": "foo"})
    assert blocked and "robot-hand discovery required" in blocked

    state.gate_evidence["robot_hand"] = ["ROBOT_HAND_DISCOVERY_PASS:jcodemunch current"]
    save_warroom_goal("sid-robot-adversary", state)
    assert enforce_tool_policy("sid-robot-adversary", "search_files", {"path": "/repo", "pattern": "foo"}) is None


def test_robot_hand_discovery_required_before_raw_search_in_plan_adversary_workflow(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-robot-plan",
        _strict_goal(),
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "controller"
    save_warroom_goal("sid-robot-plan", state)

    blocked = enforce_tool_policy("sid-robot-plan", "terminal", {"command": "grep -R foo hermes_cli", "workdir": str(tmp_path)})
    assert blocked and "robot-hand discovery required" in blocked

    state.gate_evidence["robot_hand"] = ["SMART_READ_USED:/tmp/plan.md"]
    save_warroom_goal("sid-robot-plan", state)
    assert enforce_tool_policy("sid-robot-plan", "terminal", {"command": "grep -R foo hermes_cli", "workdir": str(tmp_path)}) is None


def test_stale_jcodemunch_and_codegraph_do_not_silently_pass(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    target = tmp_path / "module.py"
    target.write_text("x = 1\n", encoding="utf-8")
    state = create_warroom_goal(
        "sid-stale-index",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "builder"
    state.gate_evidence["robot_hand"] = ["JCODEMUNCH_INDEX_STALE:indexed 2026-06-24"]
    state.gate_evidence["codegraph"] = ["CODEGRAPH_STALE:status says stale"]
    save_warroom_goal("sid-stale-index", state)

    raw_blocked = enforce_tool_policy("sid-stale-index", "search_files", {"path": "/repo", "pattern": "foo"})
    edit_blocked = enforce_tool_policy("sid-stale-index", "write_file", {"path": str(target), "content": "x = 2\n"})
    assert raw_blocked and "stale robot-hand index" in raw_blocked
    assert edit_blocked and "CodeGraph stale" in edit_blocked

    state.gate_evidence["robot_hand"] = ["JCODEMUNCH_STALE_GAP:index unavailable; fallback audited"]
    state.gate_evidence["codegraph"] = ["CODEGRAPH_STALE:status says stale", "CODEGRAPH_SYNCED:status up to date"]
    state.gate_evidence["ponytail"] = ["PONYTAIL_AUDIT:test fixture"]
    save_warroom_goal("sid-stale-index", state)
    assert enforce_tool_policy("sid-stale-index", "search_files", {"path": "/repo", "pattern": "foo"}) is None
    assert enforce_tool_policy("sid-stale-index", "write_file", {"path": str(target), "content": "x = 3\n"}) is None


def test_explicit_robot_hand_gap_permits_raw_fallback_with_audit_record(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-robot-gap",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "controller"
    state.gate_evidence["robot_hand"] = ["ROBOT_HAND_GAP:mcp server unavailable"]
    save_warroom_goal("sid-robot-gap", state)

    assert enforce_tool_policy("sid-robot-gap", "search_files", {"path": "/repo", "pattern": "foo"}) is None
    event = _agt_events(hermes_home)[-1]
    assert event["policy"] == "robot_hand_discovery_required"
    assert event["decision"] == "allow"
    assert event["metadata"]["robot_hand_gap"] == "ROBOT_HAND_GAP"


def test_child_role_cannot_write_parent_owned_proof_state(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, save_warroom_goal

    state = create_warroom_goal(
        "sid-parent-proof",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.current_role = "builder"
    save_warroom_goal("sid-parent-proof", state)

    blocked = enforce_tool_policy("sid-parent-proof", "write_file", {"path": str(tmp_path / "final-proof-packet.md")})
    assert blocked and "controller-owned" in blocked

    state.current_role = "controller"
    save_warroom_goal("sid-parent-proof", state)
    allowed = enforce_tool_policy("sid-parent-proof", "write_file", {"path": str(tmp_path / "final-proof-packet.md")})
    assert allowed is None


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
    assert unlocked.final_claim_allowed is False
    completed = guard_final_response("sid-guardian-unlock", "DONE. pytest E2E passed and proof packet written.", closure=True)
    assert "FINAL BLOCKED" in completed
    assert "role_evidence_gaps" in completed
    from hermes_cli.warroom_goal import load_warroom_goal
    completed_state = load_warroom_goal("sid-guardian-unlock")
    assert completed_state is not None
    assert completed_state.status != "done"
    assert completed_state.gates["proof_packet"] == "pending"
    assert completed_state.gates["e2e_claim"] == "pending"
    assert "completion_output" not in completed_state.gate_evidence


def test_final_claim_requires_current_state_hash_match(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-final-hash",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    proof = tmp_path / "proof-packet.md"
    proof.write_text("tests passed\n", encoding="utf-8")
    state.proof_packet_path = str(proof)
    role_spawn = tmp_path / "role-spawn-evidence.json"
    role_spawn.write_text('{"records":{}}\n', encoding="utf-8")
    state.role_spawn_evidence_path = str(role_spawn)
    for role in state.required_roles:
        if role == "controller":
            continue
        record = state.role_records[role]
        record["child_session_id"] = f"child-{role}"
        record["delegation_id"] = f"delegation-{role}"
        record["runtime_kind"] = "real_child_session"
        record["spawn_receipt_only"] = False
        state.role_records[role] = record
    save_warroom_goal("sid-final-hash", state)

    for role in (role for role in state.required_roles if role not in {"controller", "guardian"}):
        evidence = tmp_path / f"{role}.json"
        evidence.write_text('{"verdict":"PASS"}\n', encoding="utf-8")
        recorded = record_role_output("sid-final-hash", role, evidence_path=str(evidence), status="done")
        assert recorded is not None
        assert recorded.role_records[role]["evidence_truth"]["ok"] is True

    guardian = tmp_path / "guardian.txt"
    guardian.write_text("Guardian verdict: PASS\n", encoding="utf-8")
    unlocked = record_role_output("sid-final-hash", "guardian", evidence_path=str(guardian), verdict="PASS")
    assert unlocked is not None
    assert unlocked.final_claim_state_hash

    unlocked.gate_evidence.setdefault("state_hash_test", []).append("mutated after Guardian PASS")
    save_warroom_goal("sid-final-hash", unlocked)

    blocked = guard_final_response("sid-final-hash", "DONE. pytest E2E passed and proof packet written.", closure=True)
    assert "FINAL BLOCKED" in blocked
    assert "state hash" in blocked
    assert "role_evidence_gaps" not in blocked


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
    normal_response = "DONE. pytest E2E passed."
    assert guard_final_response("sid-spawn-pending", "Working on it.") == "Working on it."
    assert guard_final_response("sid-spawn-pending", normal_response) == normal_response
    assert guard_final_response("sid-spawn-pending", "Working on it.", closure=True) == "Working on it."
    blocked = guard_final_response("sid-spawn-pending", normal_response, closure=True)
    assert "FINAL BLOCKED" in blocked
    assert "required role spawn action is pending" in blocked


def test_normal_chat_final_words_bypass_gap_state(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, save_warroom_goal

    state = create_warroom_goal(
        "sid-gap-normal-chat",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.status = "gap"
    state.required_action = "blocked_gap"
    state.last_gap = "real delegated role runtime missing"
    save_warroom_goal("sid-gap-normal-chat", state)
    normal_response = "DONE. Bug source found. Complete notes written."

    assert guard_final_response("sid-gap-normal-chat", normal_response) == normal_response
    blocked = guard_final_response("sid-gap-normal-chat", normal_response, closure=True)
    assert "FINAL BLOCKED" in blocked
    assert "proof packet" in blocked


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
            "model": state.controller_model or "gpt-5.5",
            "provider": "openai-codex",
        }

    updated = start_warroom_roles("sid-real-child", ["reviewer"], adapter=adapter, use_local_process=False)
    assert updated is not None
    assert updated.gates["role_spawn"] in {"pass", "partial_pass_queued"}
    assert updated.gates["delegate_runtime"] == "pass"
    assert updated.required_action in {None, "continue_scheduler"}
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
    assert "evidence=" in line
    assert "heartbeat=" in line
    assert "parent_progress=" in line
    assert "stale" in line


def test_non_guardian_role_done_requires_real_evidence_file_and_clears_gap_when_resolved(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-role-evidence-truth",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.role_records["reviewer"]["child_session_id"] = "child-reviewer"
    state.role_records["reviewer"]["delegation_id"] = "delegation-reviewer"
    state.role_records["reviewer"]["runtime_kind"] = "real_child_session"
    state.role_records["reviewer"]["spawn_receipt_only"] = False
    save_warroom_goal("sid-role-evidence-truth", state)

    missing = record_role_output(
        "sid-role-evidence-truth",
        "reviewer",
        evidence_path=str(tmp_path / "missing-reviewer.json"),
        status="done",
    )

    assert missing is not None
    assert missing.role_records["reviewer"]["status"] == "evidence_gap"
    assert missing.gates["role_evidence"] == "gap"
    assert "missing_evidence_file" in missing.last_gap

    evidence = tmp_path / "reviewer.json"
    evidence.write_text('{"verdict":"PASS"}\n', encoding="utf-8")
    recorded = record_role_output(
        "sid-role-evidence-truth",
        "reviewer",
        evidence_path=str(evidence),
        status="done",
    )
    assert recorded.role_records["reviewer"]["status"] == "done"
    assert recorded.role_records["reviewer"]["evidence_truth"]["ok"] is True
    assert recorded.gates["role_evidence"] == "pass"
    assert recorded.last_gap is None


def test_role_evidence_gap_clear_does_not_hide_unrelated_gap(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-role-evidence-other-gap",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.role_records["reviewer"]["child_session_id"] = "child-reviewer"
    state.role_records["reviewer"]["delegation_id"] = "delegation-reviewer"
    state.role_records["reviewer"]["runtime_kind"] = "real_child_session"
    state.role_records["reviewer"]["spawn_receipt_only"] = False
    state.gates["role_evidence"] = "gap"
    state.last_gap = "Unrelated parser gap"
    save_warroom_goal("sid-role-evidence-other-gap", state)

    evidence = tmp_path / "reviewer.json"
    evidence.write_text('{"verdict":"PASS"}\n', encoding="utf-8")
    recorded = record_role_output(
        "sid-role-evidence-other-gap",
        "reviewer",
        evidence_path=str(evidence),
        status="done",
    )
    assert recorded.gates["role_evidence"] == "pass"
    assert recorded.last_gap == "Unrelated parser gap"


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


def test_tracked_terminal_proof_persists_stdout_and_exit_code(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, start_warroom_roles

    create_warroom_goal(
        "sid-tracked-terminal-proof",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )

    stdout = "pytest stdout\n1 passed\n"

    def tracked_transport(**kwargs):
        return {
            "adapter": "native_delegate",
            "model": "gpt-5.5",
            "exit_code": 0,
            "stdout": stdout,
            "delegation_id": "delegation-tracked-proof",
            "child_session_id": "child-tracked-proof",
        }

    state = start_warroom_roles("sid-tracked-terminal-proof", ["reviewer"], adapter=tracked_transport, use_local_process=False)
    assert state is not None
    record = state.role_records["reviewer"]
    assert record["status"] == "active_child_work"
    assert record["tracked_terminal_exit_code"] == 0
    assert record["tracked_terminal_stdout"] == stdout
    assert record["tracked_terminal_stdout_bytes"] == len(stdout.encode("utf-8"))
    assert record["tracked_terminal_stdout_sha256"] == hashlib.sha256(stdout.encode("utf-8")).hexdigest()


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
    _mark_non_guardian_roles_done_for_final(state, tmp_path)
    state.role_records["guardian"]["child_session_id"] = "child-guardian"
    state.role_records["guardian"]["delegation_id"] = "delegation-guardian"
    state.role_records["guardian"]["runtime_kind"] = "real_child_session"
    state.role_records["guardian"]["spawn_receipt_only"] = False
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
    pytest.importorskip("acp.schema")
    from types import SimpleNamespace
    from acp_adapter.server import HermesACPAgent
    from hermes_cli.goals import GoalManager
    from hermes_cli.warroom_goal import load_warroom_goal

    server = object.__new__(HermesACPAgent)
    server.session_manager = SimpleNamespace(save_session=lambda session_id: None)
    parent_agent = SimpleNamespace(session_id="sid-acp-global-goal", model="gpt-5.5", provider="openai-codex")
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


def test_warroom_roles_record_actual_delegate_model_for_plan_adversary_roles(hermes_home, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from hermes_cli.warroom_goal import create_warroom_goal

    calls = _fake_background_delegate(monkeypatch)
    parent_agent = SimpleNamespace(session_id="sid-warroom-model", model="gpt-5.5", provider="openai-codex")
    state = create_warroom_goal(
        "sid-warroom-model",
        "prove plan adversary role model inheritance",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
        parent_agent=parent_agent,
    )

    assert len(calls) == 3
    for role in ("plan_builder", "plan_adversary", "plan_reviewer"):
        record = state.role_records[role]
        assert record["model"] == "gpt-5.5"
        assert record["provider"] == "openai-codex"
        assert record["runtime_kind"] == "real_child_session"
        assert record["spawn_receipt_only"] is False


def test_warroom_roles_record_actual_delegate_model_for_fast_adversary_roles(hermes_home, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from hermes_cli.warroom_goal import create_warroom_goal

    calls = _fake_background_delegate(monkeypatch)
    parent_agent = SimpleNamespace(session_id="sid-fast-model", model="gpt-5.5", provider="openai-codex")
    state = create_warroom_goal(
        "sid-fast-model",
        "Use adversary skill for: prove fast adversary role model inheritance",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
        parent_agent=parent_agent,
    )

    assert len(calls) == 3
    assert state.role_queue == ["guardian"]
    assert state.role_records["guardian"]["status"] == "queued"
    for role in ("builder", "adversary", "reviewer"):
        record = state.role_records[role]
        assert record["model"] == "gpt-5.5"
        assert record["provider"] == "openai-codex"
        assert record["runtime_kind"] == "real_child_session"
        assert record["spawn_receipt_only"] is False


def test_warroom_role_dispatch_blocks_null_model_recording(hermes_home, tmp_path, monkeypatch):
    from hermes_cli.warroom_goal import create_warroom_goal, save_warroom_goal, start_warroom_roles

    state = create_warroom_goal(
        "sid-null-model",
        "prove null child model is a recording gap",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.controller_model = "gpt-5.5"
    save_warroom_goal("sid-null-model", state)

    def adapter(**kwargs):
        return {"adapter": "native_delegate", "delegation_id": "delegation-null-model", "runtime_id": "delegation-null-model", "stdout": "spawned"}

    updated = start_warroom_roles("sid-null-model", ["reviewer"], adapter=adapter, use_local_process=False)

    assert updated.status == "gap"
    assert "MODEL_RECORDING_GAP" in (updated.last_gap or "")
    assert updated.gates["delegate_runtime"] == "gap"


def test_warroom_role_dispatch_blocks_gpt54_child_model_mismatch(hermes_home, tmp_path, monkeypatch):
    from hermes_cli.warroom_goal import create_warroom_goal, save_warroom_goal, start_warroom_roles

    state = create_warroom_goal(
        "sid-gpt54-model",
        "prove gpt-5.4 child mismatch is pinning gap",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.controller_model = "gpt-5.5"
    save_warroom_goal("sid-gpt54-model", state)

    def adapter(**kwargs):
        return {
            "adapter": "native_delegate",
            "delegation_id": "delegation-gpt54",
            "runtime_id": "delegation-gpt54",
            "stdout": "spawned",
            "model": "gpt-5.4",
            "provider": "openai-codex",
        }

    updated = start_warroom_roles("sid-gpt54-model", ["reviewer"], adapter=adapter, use_local_process=False)

    assert updated.status == "gap"
    assert "model_inherit_controller_default" in (updated.last_gap or "")
    assert updated.gates["delegate_runtime"] == "gap"



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


def test_plan_build_roles_auto_start_with_parent_agent_no_nudge(hermes_home, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, load_warroom_goal, save_warroom_goal

    calls = _fake_background_delegate(monkeypatch)

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
    _mark_non_guardian_roles_done_for_final(state, tmp_path)
    state.current_role = "builder"
    save_warroom_goal("sid-auto-build-roles", state)

    parent_agent = SimpleNamespace(session_id="sid-auto-build-roles", model="gpt-5.5", provider="openai-codex")
    blocked = enforce_tool_policy(
        "sid-auto-build-roles",
        "terminal",
        {"command": "git status --short", "workdir": str(tmp_path)},
        parent_agent=parent_agent,
    )
    assert blocked is None
    updated = load_warroom_goal("sid-auto-build-roles")
    assert updated is not None
    assert {"builder", "adversary", "reviewer", "guardian"}.issubset(updated.role_records)
    assert updated.gates["build_role_spawn"] == "partial_pass_queued"
    assert updated.gates["delegate_runtime"] == "pass"
    assert updated.required_action == "continue_scheduler"
    assert len(calls) == 3
    assert updated.role_queue == ["guardian"]
    assert updated.role_records["guardian"]["status"] == "queued"
    for role in ("builder", "adversary", "reviewer"):
        assert updated.role_records[role]["runtime_kind"] == "real_child_session"


def test_plan_build_roles_auto_start_without_parent_agent_fails_closed(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, enforce_tool_policy, load_warroom_goal, save_warroom_goal

    state = create_warroom_goal(
        "sid-auto-build-roles-no-parent",
        "ship plan then build",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    assert set(state.role_records) == {"controller", "plan_builder", "plan_adversary", "plan_reviewer"}
    _unlock_runtime_for_policy_test(state)
    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    _mark_non_guardian_roles_done_for_final(state, tmp_path)
    state.current_role = "builder"
    save_warroom_goal("sid-auto-build-roles-no-parent", state)

    blocked = enforce_tool_policy(
        "sid-auto-build-roles-no-parent",
        "write_file",
        {"path": str(tmp_path / "x.py")},
    )
    assert blocked is None
    updated = load_warroom_goal("sid-auto-build-roles-no-parent")
    assert updated is not None
    assert {"builder", "adversary", "reviewer", "guardian"}.issubset(updated.role_records)
    assert updated.gates["build_role_spawn"] == "pass"


@pytest.mark.parametrize(
    ("role", "status", "spawn_receipt_only"),
    [
        ("plan_builder", "missing", False),
        ("plan_builder", "active_child_work", False),
        ("plan_adversary", "done", True),
        ("plan_reviewer", "stalled", False),
    ],
)
def test_plan_to_build_requires_current_accepted_plan_role_outputs(hermes_home, tmp_path, role, status, spawn_receipt_only):
    from hermes_cli.warroom_goal import create_warroom_goal, save_warroom_goal, start_plan_build_roles_if_ready

    state = create_warroom_goal(
        f"sid-plan-barrier-{role}-{status}",
        _strict_goal(),
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    _mark_non_guardian_roles_done_for_final(state, tmp_path)
    if status == "missing":
        state.role_records.pop(role, None)
    else:
        state.role_records[role]["status"] = status
        state.role_records[role]["current_phase"] = status
        state.role_records[role]["spawn_receipt_only"] = spawn_receipt_only
        if spawn_receipt_only:
            state.role_records[role]["child_session_id"] = None
            state.role_records[role]["delegation_id"] = None
        if status == "stalled":
            state.role_records[role]["stale"] = True
            state.role_records[role]["diagnostic_path"] = str(tmp_path / f"{role}-diagnostic.json")
    save_warroom_goal(state.session_id, state)

    updated = start_plan_build_roles_if_ready(state.session_id, adapter=lambda **kwargs: {"delegation_id": "should-not-run"}, use_local_process=False)

    assert updated is not None
    assert "builder" not in updated.role_records
    assert updated.gates["build_role_spawn"] == "blocked"
    assert updated.required_action in {"wait_for_plan_roles", "stalled_diagnostic"}


def test_accepted_plan_outputs_unlock_builder(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, save_warroom_goal, start_plan_build_roles_if_ready

    state = create_warroom_goal(
        "sid-plan-outputs-unlock-builder",
        _strict_goal(),
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    _unlock_runtime_for_policy_test(state)
    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    _mark_non_guardian_roles_done_for_final(state, tmp_path)
    save_warroom_goal("sid-plan-outputs-unlock-builder", state)

    updated = start_plan_build_roles_if_ready("sid-plan-outputs-unlock-builder", adapter=None, use_local_process=True)

    assert updated is not None
    assert {"builder", "adversary", "reviewer", "guardian"}.issubset(updated.role_records)
    assert updated.gates.get("plan_role_outputs") != "waiting"


def test_stalled_required_role_diagnostic_blocks_next_phase(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, mark_role_stalled, save_warroom_goal, start_plan_build_roles_if_ready

    state = create_warroom_goal("sid-stalled-plan-role-blocks", _strict_goal(), tracking_dir=str(tmp_path), allowed_mutation_root=str(tmp_path))
    _unlock_runtime_for_policy_test(state)
    state.gates["plan"] = "pass"
    state.gates["tracking"] = "pass"
    _mark_non_guardian_roles_done_for_final(state, tmp_path)
    save_warroom_goal("sid-stalled-plan-role-blocks", state)

    stalled = mark_role_stalled("sid-stalled-plan-role-blocks", "plan_builder", delegation_id="deleg-plan-builder", elapsed=999, current_phase="waiting")
    assert stalled is not None
    assert stalled.role_records["plan_builder"]["status"] == "stalled"
    assert stalled.role_records["plan_builder"]["diagnostic_path"]

    blocked = start_plan_build_roles_if_ready("sid-stalled-plan-role-blocks", adapter=lambda **kwargs: {"delegation_id": "should-not-run"}, use_local_process=False)
    assert blocked is not None
    assert blocked.status == "gap"
    assert blocked.required_action == "stalled_diagnostic"
    assert blocked.last_gap is not None
    assert "STALLED_DIAGNOSTIC" in blocked.last_gap
    assert "builder" not in blocked.role_records


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
    role_spawn = tmp_path / "role-spawn-evidence.json"
    role_spawn.write_text('{"records":{}}\n', encoding="utf-8")
    state.role_spawn_evidence_path = str(role_spawn)
    for role in ("plan_builder", "plan_adversary", "plan_reviewer"):
        record = state.role_records[role]
        record["child_session_id"] = f"child-{role}"
        record["delegation_id"] = f"delegation-{role}"
        record["runtime_kind"] = "real_child_session"
        record["spawn_receipt_only"] = False
        state.role_records[role] = record
    save_warroom_goal("sid-completion-output", state)
    for role in ("plan_builder", "plan_adversary", "plan_reviewer"):
        role_evidence = tmp_path / f"{role}.json"
        role_evidence.write_text('{"verdict":"PASS"}\n', encoding="utf-8")
        record_role_output("sid-completion-output", role, evidence_path=str(role_evidence), status="done")
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


def test_final_completion_requires_role_and_guardian_evidence_files(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, guard_final_response, record_role_output, save_warroom_goal

    state = create_warroom_goal(
        "sid-final-evidence-proof",
        "Use plan adversary skill for:\n\nGoal:\nwire final proof\n\nAcceptance:\n- proof\n\nConstraints:\n- worktree only\n\nVerify with:\npytest",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    proof = tmp_path / "proof-packet.md"
    proof.write_text("PROOF PACKET\nTests: PASS\nRole evidence: PASS\n", encoding="utf-8")
    state.proof_packet_path = str(proof)
    state.role_spawn_evidence_path = str(tmp_path / "missing-role-spawn-evidence.json")
    save_warroom_goal("sid-final-evidence-proof", state)

    guardian = tmp_path / "guardian.txt"
    guardian.write_text("Guardian verdict: PASS\n", encoding="utf-8")
    record_role_output("sid-final-evidence-proof", "guardian", evidence_path=str(guardian), verdict="PASS")

    blocked = guard_final_response(
        "sid-final-evidence-proof",
        "DONE. pytest E2E passed and proof packet written.",
        closure=True,
    )
    assert "FINAL BLOCKED" in blocked
    assert "role spawn evidence" in blocked
