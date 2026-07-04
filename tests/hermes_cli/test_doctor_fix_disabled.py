from __future__ import annotations

from argparse import Namespace
import contextlib
import io
import sys
import types

import pytest

import hermes_cli.doctor as doctor_mod


def test_doctor_fix_flag_is_warn_only_and_does_not_mutate_env(monkeypatch, tmp_path):
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir(parents=True)
    config_path = hermes_home / "config.yaml"
    env_path = hermes_home / ".env"
    config_path.write_text("agent:\n  max_turns: 400\n", encoding="utf-8")
    env_path.write_text(
        "OPENAI_API_KEY=placeholder\nHERMES_MAX_ITERATIONS=90\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(doctor_mod, "HERMES_HOME", hermes_home)
    monkeypatch.setattr(doctor_mod, "get_hermes_home", lambda: hermes_home)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("HERMES_MAX_ITERATIONS", "400")

    fake_model_tools = types.SimpleNamespace(
        check_tool_availability=lambda *a, **kw: (_ for _ in ()).throw(SystemExit(0)),
        TOOLSET_REQUIREMENTS={},
    )
    monkeypatch.setitem(sys.modules, "model_tools", fake_model_tools)

    before_config = config_path.read_text(encoding="utf-8")
    before_env = env_path.read_text(encoding="utf-8")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        doctor_mod.run_doctor(Namespace(fix=True, ack=None))

    out = buf.getvalue()
    assert "doctor --fix is disabled by local safety policy" in out
    assert "HERMES_MAX_ITERATIONS=90" in out
    assert "run 'hermes doctor --fix'" not in out
    assert config_path.read_text(encoding="utf-8") == before_config
    assert env_path.read_text(encoding="utf-8") == before_env
