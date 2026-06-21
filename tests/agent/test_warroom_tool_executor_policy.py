from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture()
def hermes_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    yield home


def test_warroom_policy_hook_blocks_before_execution_after_tool_search_unwrap(hermes_home, tmp_path):
    from hermes_cli.warroom_goal import create_warroom_goal, save_warroom_goal, enforce_tool_policy

    state = create_warroom_goal(
        "sid-tool",
        "Use adversary skill for: build hardwire",
        tracking_dir=str(tmp_path),
        allowed_mutation_root=str(tmp_path),
    )
    state.current_role = "reviewer"
    save_warroom_goal("sid-tool", state)

    msg = enforce_tool_policy("sid-tool", "patch", {"path": str(tmp_path / "x.py")})
    assert msg is not None
    assert "reviewer" in msg.lower()
