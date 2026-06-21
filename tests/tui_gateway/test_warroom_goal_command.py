from __future__ import annotations

import importlib
import threading
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

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


@pytest.fixture()
def server(hermes_home):
    with patch.dict("sys.modules", {"hermes_cli.env_loader": MagicMock(), "hermes_cli.banner": MagicMock()}):
        mod = importlib.import_module("tui_gateway.server")
        yield mod
        mod._sessions.clear()
        mod._pending.clear()
        mod._answers.clear()


@pytest.fixture()
def session(server):
    sid = f"sid-warroom-tui-{uuid.uuid4().hex}"
    session_key = f"warroom-tui-session-key-{uuid.uuid4().hex}"
    server._sessions[sid] = {
        "session_key": session_key,
        "history": [],
        "history_lock": threading.Lock(),
        "history_version": 0,
        "running": False,
        "attached_images": [],
        "cols": 120,
    }
    return sid, session_key


def _call(server, method, **params):
    return server._methods[method](1, params)


def test_tui_goal_command_dispatch_creates_warroom_state(server, session):
    sid, session_key = session
    r = _call(
        server,
        "command.dispatch",
        name="goal",
        arg="Use adversary skill for: build runtime hardwire",
        session_id=sid,
    )
    result = r["result"]
    assert result["type"] == "send"
    assert result["warroom"] is True
    assert "WARROOM V3" in result["notice"]
    assert "Controller" in result["message"]

    from hermes_cli.warroom_goal import load_warroom_goal
    state = load_warroom_goal(session_key)
    assert state is not None
    assert state.workflow == "fast_adversary"


def test_tui_quoted_goal_example_uses_global_hardwire(server, session):
    sid, session_key = session
    r = _call(
        server,
        "command.dispatch",
        name="goal",
        arg='Example: "/goal Use adversary skill for: nope"',
        session_id=sid,
    )
    assert r["result"]["type"] == "send"
    assert r["result"].get("warroom") is True
    assert "global_plan_adversary" in r["result"]["notice"]

    from hermes_cli.warroom_goal import load_warroom_goal
    assert load_warroom_goal(session_key).workflow == "global_plan_adversary"



def test_tui_warroom_pause_and_resume_control_state(server, session):
    sid, session_key = session
    _call(server, "command.dispatch", name="goal", arg="Use adversary skill for: build runtime hardwire", session_id=sid)

    paused = _call(server, "command.dispatch", name="goal", arg="pause", session_id=sid)["result"]
    assert paused["type"] == "exec"
    assert "WARROOM V3" in paused["output"]

    from hermes_cli.warroom_goal import load_warroom_goal
    assert load_warroom_goal(session_key).status == "halted"

    resumed = _call(server, "command.dispatch", name="goal", arg="resume", session_id=sid)["result"]
    assert resumed["type"] == "send"
    assert resumed["warroom"] is True
    assert "Controller" in resumed["message"]
    assert load_warroom_goal(session_key).status == "active"



def test_tui_warroom_uses_session_cwd_for_mutation_root(server, session, tmp_path, monkeypatch):
    sid, session_key = session
    session_cwd = tmp_path / "session-cwd"
    global_cwd = tmp_path / "global-cwd"
    session_cwd.mkdir()
    global_cwd.mkdir()
    server._sessions[sid]["cwd"] = str(session_cwd)
    monkeypatch.setenv("TERMINAL_CWD", str(global_cwd))

    _call(server, "command.dispatch", name="goal", arg="Use adversary skill for: build runtime hardwire", session_id=sid)

    from hermes_cli.warroom_goal import load_warroom_goal
    state = load_warroom_goal(session_key)
    assert state.allowed_mutation_root == str(session_cwd)
