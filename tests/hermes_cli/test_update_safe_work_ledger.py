import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli import main as hermes_main


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.email", "test@example.com")
    git(root, "config", "user.name", "Test")
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    git(root, "add", "tracked.txt")
    git(root, "commit", "-qm", "base")
    base = git(root, "rev-parse", "HEAD").stdout.strip()
    git(root, "update-ref", "refs/remotes/origin/main", base)
    return root


def ledger(tmp_path: Path, *states: str, complete: bool = True, diverged_plan: bool = False) -> Path:
    entries = []
    for state in states:
        entry = {
            "state": state,
            "status": "preserved",
            "restore_proof": complete,
            "test_proof": complete,
            "decision_approval": complete,
        }
        if state == "diverged" and diverged_plan:
            entry["divergence_plan"] = "rebase/cherry-pick/drop plan approved"
        entries.append(entry)
    path = tmp_path / "safe-work-ledger.json"
    path.write_text(json.dumps({"entries": entries}) + "\n", encoding="utf-8")
    return path


def args(path: Path | None = None):
    return SimpleNamespace(branch="main", safe_work_ledger=str(path) if path else None)


def test_unknown_dirty_blocks_before_backup_lockfile_discard_fetch_or_stash(monkeypatch, repo: Path, capsys):
    (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    called: list[str] = []
    monkeypatch.setattr(hermes_main, "PROJECT_ROOT", repo)
    monkeypatch.setattr(hermes_main, "_run_pre_update_backup", lambda _args: called.append("backup"))
    monkeypatch.setattr(hermes_main, "_pause_windows_gateways_for_update", lambda: called.append("gateway_pause"))
    monkeypatch.setattr(hermes_main, "_discard_lockfile_churn", lambda *a, **k: called.append("lockfile_discard"))
    monkeypatch.setattr(hermes_main, "_stash_local_changes_if_needed", lambda *a, **k: called.append("stash"))

    with pytest.raises(SystemExit) as exc:
        hermes_main._cmd_update_impl(SimpleNamespace(branch="main", safe_work_ledger=None, yes=True, force=True), gateway_mode=False)

    assert exc.value.code == 2
    assert called == []
    out = capsys.readouterr().out
    assert "lockfile discard, fetch, stash" in out
    assert "Graphify -> CodeGraph -> jcodemunch/smart-read -> Understand Anything" in out


def test_known_preserved_dirty_routes_forward(repo: Path, tmp_path: Path, capsys):
    (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    hermes_main._enforce_native_update_safe_work_ledger_gate(args(ledger(tmp_path, "dirty")), ["git"], repo)
    assert "Safe Work Ledger accepted" in capsys.readouterr().out


def test_unknown_ahead_blocks_before_fetch(repo: Path):
    (repo / "ahead.txt").write_text("ahead\n", encoding="utf-8")
    git(repo, "add", "ahead.txt")
    git(repo, "commit", "-qm", "ahead")

    with pytest.raises(SystemExit) as exc:
        hermes_main._enforce_native_update_safe_work_ledger_gate(args(None), ["git"], repo)

    assert exc.value.code == 2


def test_known_preserved_ahead_routes_forward(repo: Path, tmp_path: Path):
    (repo / "ahead.txt").write_text("ahead\n", encoding="utf-8")
    git(repo, "add", "ahead.txt")
    git(repo, "commit", "-qm", "ahead")

    hermes_main._enforce_native_update_safe_work_ledger_gate(args(ledger(tmp_path, "ahead")), ["git"], repo)


def test_unknown_diverged_blocks(repo: Path):
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "local.txt").write_text("local\n", encoding="utf-8")
    git(repo, "add", "local.txt")
    git(repo, "commit", "-qm", "local")
    git(repo, "checkout", "-q", "--detach", base)
    (repo / "remote.txt").write_text("remote\n", encoding="utf-8")
    git(repo, "add", "remote.txt")
    git(repo, "commit", "-qm", "remote")
    remote_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    git(repo, "checkout", "-q", "main")
    git(repo, "update-ref", "refs/remotes/origin/main", remote_sha)

    with pytest.raises(SystemExit) as exc:
        hermes_main._enforce_native_update_safe_work_ledger_gate(args(None), ["git"], repo)

    assert exc.value.code == 2


def test_known_preserved_diverged_with_plan_proof_approval_routes_forward(repo: Path, tmp_path: Path):
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "local.txt").write_text("local\n", encoding="utf-8")
    git(repo, "add", "local.txt")
    git(repo, "commit", "-qm", "local")
    git(repo, "checkout", "-q", "--detach", base)
    (repo / "remote.txt").write_text("remote\n", encoding="utf-8")
    git(repo, "add", "remote.txt")
    git(repo, "commit", "-qm", "remote")
    remote_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    git(repo, "checkout", "-q", "main")
    git(repo, "update-ref", "refs/remotes/origin/main", remote_sha)

    hermes_main._enforce_native_update_safe_work_ledger_gate(
        args(ledger(tmp_path, "diverged", diverged_plan=True)), ["git"], repo
    )


def test_unclear_local_work_emits_robot_hand_escalation(repo: Path, capsys):
    (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(SystemExit):
        hermes_main._enforce_native_update_safe_work_ledger_gate(args(None), ["git"], repo)

    assert "Graphify -> CodeGraph -> jcodemunch/smart-read -> Understand Anything" in capsys.readouterr().out



def test_zip_overwrite_path_without_git_requires_safe_work_ledger(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    with pytest.raises(SystemExit) as exc:
        hermes_main._enforce_native_update_zip_safe_work_ledger(args(), tmp_path)
    assert exc.value.code == 2
    out = capsys.readouterr().out
    assert "zip-overwrite" in out
    assert "backup, gateway pause, lockfile discard, fetch, stash, checkout, pull, reset, or ZIP overwrite" in out


def test_zip_overwrite_path_with_preserved_dirty_ledger_routes_forward(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    hermes_main._enforce_native_update_zip_safe_work_ledger(args(ledger(tmp_path, "dirty")), tmp_path)
