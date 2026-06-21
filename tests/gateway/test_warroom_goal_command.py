from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

sys.modules.setdefault("dotenv", MagicMock(load_dotenv=lambda *a, **k: None))

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import MessageEvent, MessageType
from gateway.run import GatewayRunner
from gateway.session import SessionSource


class _FakeSessionEntry:
    session_id = "sid-warroom-gateway"


class _FakeSessionStore:
    def __init__(self):
        self.entry = _FakeSessionEntry()

    def get_or_create_session(self, source):
        return self.entry

    def _generate_session_key(self, source):
        return "agent:main:discord:channel:warroom"


class _FakeAdapter:
    def __init__(self):
        self._pending_messages = {}


@pytest.fixture()
def gateway_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    yield home


def _runner():
    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(platforms={Platform.DISCORD: PlatformConfig(enabled=True, token="token")})
    runner.session_store = _FakeSessionStore()
    runner.adapters = {Platform.DISCORD: _FakeAdapter()}
    runner._queued_events = {}
    return runner


def _event(text):
    return MessageEvent(
        text=text,
        message_type=MessageType.TEXT,
        source=SessionSource(platform=Platform.DISCORD, chat_id="chat", chat_type="channel", user_id="user"),
        message_id="msg",
    )


def test_gateway_goal_creates_warroom_state_and_queues_controller(gateway_home):
    runner = _runner()
    import asyncio
    response = asyncio.run(GatewayRunner._handle_goal_command(
        runner,
        _event("/goal Use plan adversary skill for: build hardwire\n\nAcceptance:\n- proof\n\nConstraints:\n- worktree\n\nVerify with:\npytest"),
    ))
    assert "WARROOM V3" in response

    from hermes_cli.warroom_goal import load_warroom_goal
    state = load_warroom_goal("sid-warroom-gateway")
    assert state is not None
    assert state.workflow == "strict_plan_adversary"
    assert runner.adapters[Platform.DISCORD]._pending_messages


def test_gateway_midrun_new_warroom_goal_blocks(gateway_home):
    runner = _runner()
    event = _event("/goal Use adversary skill for: build hardwire")
    import asyncio
    response = asyncio.run(GatewayRunner._handle_goal_command(runner, event))
    assert "WARROOM V3" in response



def test_gateway_warroom_pause_and_resume_control_state(gateway_home):
    import asyncio

    runner = _runner()
    asyncio.run(GatewayRunner._handle_goal_command(runner, _event("/goal Use adversary skill for: build hardwire")))

    paused = asyncio.run(GatewayRunner._handle_goal_command(runner, _event("/goal pause")))
    assert "WARROOM V3" in paused

    from hermes_cli.warroom_goal import load_warroom_goal
    assert load_warroom_goal("sid-warroom-gateway").status == "halted"

    resumed = asyncio.run(GatewayRunner._handle_goal_command(runner, _event("/goal resume")))
    assert "WARROOM V3" in resumed
    assert load_warroom_goal("sid-warroom-gateway").status == "active"
