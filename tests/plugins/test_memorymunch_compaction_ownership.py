from __future__ import annotations

import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_INIT = REPO_ROOT / "contrib" / "plugins" / "memorymunch" / "__init__.py"


def _load_memorymunch_module():
    spec = importlib.util.spec_from_file_location("memorymunch_plugin_compaction_test", PLUGIN_INIT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _provider(monkeypatch, tmp_path: Path, *, enable: bool = True, compaction: str | None = None):
    mm = _load_memorymunch_module()
    if enable:
        monkeypatch.setenv("HERMES_MEMORYMUNCH_ENABLE", "1")
    else:
        monkeypatch.delenv("HERMES_MEMORYMUNCH_ENABLE", raising=False)
    if compaction is None:
        monkeypatch.delenv("HERMES_MEMORYMUNCH_COMPACTION_ENABLE", raising=False)
    else:
        monkeypatch.setenv("HERMES_MEMORYMUNCH_COMPACTION_ENABLE", compaction)
    provider = mm.MemoryMunchProvider()
    provider.initialize("sess-test", hermes_home=str(tmp_path / "hermes-home"))
    return provider


def test_memorymunch_plugin_does_not_own_compaction_when_plugin_disabled(monkeypatch, tmp_path):
    provider = _provider(monkeypatch, tmp_path, enable=False)

    result = provider.build_source_of_truth_compaction(
        [{"role": "user", "content": "live query"}],
        last_user_message="live query",
        session_id="sess-test",
    )

    assert result == []


def test_memorymunch_plugin_owns_compaction_when_plugin_enabled(monkeypatch, tmp_path):
    provider = _provider(monkeypatch, tmp_path, enable=True)

    result = provider.build_source_of_truth_compaction(
        [{"role": "user", "content": "live query"}],
        last_user_message="live query",
        session_id="sess-test",
    )

    joined = "\n".join(str(row.get("content", "")) for row in result)
    assert result
    assert "MemoryMunch/Graphify source-of-truth compaction checkpoint" in joined
    assert "live query" in joined


def test_memorymunch_compaction_can_be_explicitly_disabled_while_plugin_stays_on(monkeypatch, tmp_path):
    provider = _provider(monkeypatch, tmp_path, enable=True, compaction="0")

    result = provider.build_source_of_truth_compaction(
        [{"role": "user", "content": "live query"}],
        last_user_message="live query",
        session_id="sess-test",
    )

    assert result == []
