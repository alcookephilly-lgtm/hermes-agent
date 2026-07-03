import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli import agt_hardwire_manifest as hw

SOURCE_ROOT = Path(__file__).resolve().parents[2]


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True)


@pytest.fixture()
def protected_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    for entry in hw.manifest_entries():
        rel = entry["path"]
        dst = repo / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE_ROOT / rel, dst)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base hardwires")
    return repo


def make_target_branch(repo: Path, *, protected_change: bool) -> str:
    git(repo, "checkout", "-q", "-b", "target")
    if protected_change:
        target = repo / "agent" / "agt_gateway.py"
        target.write_text(target.read_text(encoding="utf-8") + "\n# destructive target change\n", encoding="utf-8")
    else:
        safe = repo / "README.md"
        safe.write_text("safe change\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "target")
    git(repo, "checkout", "-q", "main")
    return "target"


def read_audit(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_manifest_covers_required_agt_hardwire_files_and_both_adversary_workflows():
    entries = {entry["path"]: entry for entry in hw.manifest_entries()}
    required = {
        "agent/agt_gateway.py",
        "agent/chat_completion_helpers.py",
        "cli.py",
        "hermes_cli/warroom_goal.py",
        "tools/delegate_tool.py",
        "tests/agent/test_agt_action_gateway.py",
        "tests/agent/test_codex_ttfb_watchdog.py",
        "tests/cli/test_cli_terminal_response_sanitizer.py",
        "tests/hermes_cli/test_warroom_goal_runtime.py",
        "tests/tools/test_delegate.py",
    }
    assert required.issubset(entries)
    for path in required:
        entry = entries[path]
        assert entry["sha256"]
        assert entry["git_blob_sha"]
        assert entry["reason"]
        assert entry["wave_introduced"]
        assert entry["wave_last_touched"]
    joined_reasons = "\n".join(entry["reason"] for entry in entries.values())
    assert "adversary-skill" in joined_reasons
    assert "plan-adversary-skill" in joined_reasons


def test_safe_update_with_no_protected_diff_is_allowed_and_logged(protected_repo: Path, tmp_path: Path):
    target_ref = make_target_branch(protected_repo, protected_change=False)

    result = hw.guard_native_update_hardwires(
        protected_repo,
        target_ref,
        command="git pull --ff-only origin target",
        caller="test",
        audit_dir=tmp_path / "audit",
    )

    assert result.allowed is True
    assert result.status == hw.SAFE_NO_HARDWIRE_DIFF
    assert result.audit_path is not None
    packet = read_audit(result.audit_path)
    assert packet["status"] == hw.SAFE_NO_HARDWIRE_DIFF
    assert packet["files"] == []


def test_protected_hardwire_overwrite_blocks_by_default_and_writes_audit(protected_repo: Path, tmp_path: Path):
    target_ref = make_target_branch(protected_repo, protected_change=True)

    result = hw.guard_native_update_hardwires(
        protected_repo,
        target_ref,
        command="git reset --hard target",
        caller="test",
        audit_dir=tmp_path / "audit",
    )

    assert result.allowed is False
    assert result.status == hw.BLOCKED_HARDWIRE_OVERWRITE
    assert [risk.path for risk in result.files] == ["agent/agt_gateway.py"]
    assert result.audit_path is not None
    packet = read_audit(result.audit_path)
    assert packet["status"] == hw.BLOCKED_HARDWIRE_OVERWRITE
    assert packet["files"][0]["path"] == "agent/agt_gateway.py"
    assert packet["approval_phrase"] is None


def test_explicit_approval_phrase_allows_overwrite_logs_reason_and_after_sha(protected_repo: Path, tmp_path: Path):
    target_ref = make_target_branch(protected_repo, protected_change=True)

    result = hw.guard_native_update_hardwires(
        protected_repo,
        target_ref,
        command="git checkout target -- agent/agt_gateway.py",
        caller="test",
        approval_phrase=hw.APPROVAL_PHRASE,
        approval_reason="Al approved Wave7 destructive overwrite test",
        audit_dir=tmp_path / "audit",
    )

    assert result.allowed is True
    assert result.status == hw.APPROVED_HARDWIRE_OVERWRITE
    assert result.rollback_ref
    assert result.rollback_patch and result.rollback_patch.exists()
    git(protected_repo, "checkout", target_ref, "--", "agent/agt_gateway.py")
    assert result.audit_path is not None
    hw.finalize_native_update_hardwire_audit(protected_repo, result.audit_path)
    packet = read_audit(result.audit_path)
    assert packet["approval_phrase"] == hw.APPROVAL_PHRASE
    assert packet["approval_reason"] == "Al approved Wave7 destructive overwrite test"
    assert packet["rollback_ref"] == result.rollback_ref
    assert packet["after_sha256"]["agent/agt_gateway.py"]


def test_changed_working_tree_manifest_file_detects_drift(protected_repo: Path, tmp_path: Path):
    (protected_repo / "agent" / "agt_gateway.py").write_text("drift\n", encoding="utf-8")

    result = hw.guard_native_update_hardwires(
        protected_repo,
        "main",
        command="git pull --ff-only origin main",
        caller="test",
        audit_dir=tmp_path / "audit",
    )

    assert result.allowed is False
    assert result.status == hw.MANIFEST_DRIFT
    assert result.files[0].reason == "working-tree sha256 differs from manifest"


def test_changed_manifest_content_detects_drift(monkeypatch, tmp_path: Path):
    altered = tmp_path / "manifest.json"
    data = json.loads(hw.MANIFEST_PATH.read_text(encoding="utf-8"))
    data["protected_files"][0]["reason"] = "tampered"
    altered.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    monkeypatch.setattr(hw, "MANIFEST_PATH", altered)

    drift = hw.inspect_manifest_drift(SOURCE_ROOT)

    assert any(item.reason == "manifest content hash mismatch" for item in drift)


def test_normal_non_hardwire_restore_workflow_is_allowed(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "notes.txt").write_text("normal\n", encoding="utf-8")

    result = hw.guard_restore_hardwires(
        project,
        "notes.txt",
        command="checkpoint restore abc -- notes.txt",
        caller="test",
        audit_dir=tmp_path / "audit",
    )

    assert result.allowed is True
    assert result.status == hw.SAFE_NO_HARDWIRE_DIFF


def test_restore_intersecting_hardwire_file_blocks_by_default(protected_repo: Path, tmp_path: Path):
    result = hw.guard_restore_hardwires(
        protected_repo,
        "agent/agt_gateway.py",
        command="checkpoint restore abc -- agent/agt_gateway.py",
        caller="test",
        audit_dir=tmp_path / "audit",
    )

    assert result.allowed is False
    assert result.status == hw.BLOCKED_HARDWIRE_OVERWRITE
    assert result.files[0].path == "agent/agt_gateway.py"


def test_native_update_blocks_before_checkout_pull_or_reset_can_erase_hardwires(monkeypatch, tmp_path: Path):
    from hermes_cli import main as hermes_main

    repo = protected_repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    for entry in hw.manifest_entries():
        rel = entry["path"]
        dst = repo / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE_ROOT / rel, dst)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    remote = tmp_path / "remote.git"
    git(tmp_path, "clone", "--bare", str(repo), str(remote))
    git(repo, "remote", "add", "origin", str(remote))
    (repo / "agent" / "agt_gateway.py").write_text("remote destructive change\n", encoding="utf-8")
    git(repo, "add", "agent/agt_gateway.py")
    git(repo, "commit", "-qm", "remote destructive")
    git(repo, "push", "-q", "origin", "main")
    git(repo, "reset", "--hard", base_sha)
    git(repo, "checkout", "-q", "-b", "feature")

    monkeypatch.setattr(hermes_main, "PROJECT_ROOT", repo)
    monkeypatch.setattr(hermes_main, "_run_pre_update_backup", lambda args: None)
    monkeypatch.setattr(hermes_main, "_pause_windows_gateways_for_update", lambda: None)
    monkeypatch.setattr(hermes_main, "_resume_windows_gateways_after_update", lambda state: None)
    monkeypatch.setattr(hermes_main, "_discard_lockfile_churn", lambda *args, **kwargs: None)
    monkeypatch.setattr(hermes_main, "_get_origin_url", lambda *args, **kwargs: str(remote))
    monkeypatch.setattr(hermes_main, "_is_fork", lambda *args, **kwargs: False)
    monkeypatch.setenv("HERMES_AGT_HARDWIRE_AUDIT_DIR", str(tmp_path / "audit"))

    with pytest.raises(SystemExit) as exc:
        hermes_main._cmd_update_impl(SimpleNamespace(branch="main", yes=True, force=True), gateway_mode=False)

    assert exc.value.code == 2
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "feature"
    assert (repo / "agent" / "agt_gateway.py").read_bytes() == (SOURCE_ROOT / "agent" / "agt_gateway.py").read_bytes()
    audits = list((tmp_path / "audit").glob("*.json"))
    assert audits
    assert read_audit(audits[-1])["status"] == hw.BLOCKED_HARDWIRE_OVERWRITE


def test_update_yes_does_not_set_hardwire_overwrite_approval_phrase():
    import argparse

    from hermes_cli.subcommands.update import build_update_parser

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    build_update_parser(subparsers, cmd_update=lambda _args: None)

    parsed = parser.parse_args(["update", "--yes"])

    assert parsed.yes is True
    assert parsed.approve_hardwire_overwrite is None

    parsed_with_phrase = parser.parse_args(
        ["update", "--yes", "--approve-hardwire-overwrite", hw.APPROVAL_PHRASE]
    )
    assert parsed_with_phrase.yes is True
    assert parsed_with_phrase.approve_hardwire_overwrite == hw.APPROVAL_PHRASE



def test_update_parser_keeps_safe_work_ledger_and_hardwire_overwrite_separate():
    import argparse
    from hermes_cli.subcommands.update import build_update_parser
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_update_parser(sub, cmd_update=lambda args: None)
    args = parser.parse_args([
        "update",
        "--yes",
        "--safe-work-ledger",
        "ledger.json",
        "--approve-hardwire-overwrite",
        "AL_APPROVES_OVERWRITE_AGT_HARDWIRES",
    ])
    assert args.yes is True
    assert args.safe_work_ledger == "ledger.json"
    assert args.approve_hardwire_overwrite == "AL_APPROVES_OVERWRITE_AGT_HARDWIRES"
