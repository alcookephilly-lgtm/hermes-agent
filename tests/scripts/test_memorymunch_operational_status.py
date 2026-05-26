import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "memorymunch_operational_status.py"


def load_status_script():
    spec = importlib.util.spec_from_file_location("memorymunch_operational_status_under_test", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_completed_capture_without_attempted_counts_as_recovered_firing():
    status = load_status_script()
    rows = [
        {"event": "turn_completed"},
        {"event": "live_capture_completed", "exchange_id": "conv::ok"},
    ]

    result = status.latest_capture_ok(rows)

    assert result["ok"] is True
    assert result["state"] == "completed_without_attempted"
    assert result["telemetry_warning"] == "missing_live_capture_attempted"


def test_later_failed_capture_overrides_older_completed_capture():
    status = load_status_script()
    rows = [
        {"event": "live_capture_completed", "exchange_id": "conv::old"},
        {"event": "live_capture_failed", "error": "boom"},
    ]

    result = status.latest_capture_ok(rows)

    assert result["ok"] is False
    assert result["state"] == "failed"


def test_runtime_plugin_drift_is_a_production_blocker(tmp_path):
    status = load_status_script()
    runtime = tmp_path / "runtime.py"
    vendored = tmp_path / "vendored.py"
    runtime.write_text("old sanitizer\n", encoding="utf-8")
    vendored.write_text("new sanitizer\n", encoding="utf-8")

    result = status.plugin_parity(runtime, vendored)

    assert result["ok"] is False
    assert result["runtime_sha256"] != result["vendored_sha256"]
    assert result["gap"] == "runtime_plugin_drift"


def test_live_briefing_contradictions_are_production_blockers():
    status = load_status_script()
    briefing = """
    <memorymunch-briefing>MemoryMunch audit query</memorymunch-briefing>
    <memorymunch-briefing>Kipbo Mortgage email and fulfilled eschatology theology atom</memorymunch-briefing>
    """

    result = status.detect_live_briefing_contradictions(briefing)

    assert result["ok"] is False
    assert "duplicate_memorymunch_briefing" in result["gaps"]
    assert "unrelated_activation_atom_in_technical_query" in result["gaps"]


def test_live_briefing_gate_fails_without_completed_turn():
    status = load_status_script()

    result = status.latest_turn_briefing_state([{"event": "turn_started"}])

    assert result["ok"] is False
    assert "latest_turn_missing" in result["gaps"]


def test_live_briefing_gate_scans_nested_latest_turn_rows():
    status = load_status_script()
    rows = [
        {"event": "turn_started"},
        {
            "event": "turn_completed",
            "nested": {
                "briefing": "<memorymunch-briefing>Hermes audit</memorymunch-briefing><memorymunch-briefing>theology</memorymunch-briefing>"
            },
        },
    ]

    result = status.latest_turn_briefing_state(rows)

    assert result["ok"] is False
    assert "duplicate_memorymunch_briefing" in result["gaps"]
    assert "unrelated_activation_atom_in_technical_query" in result["gaps"]


def test_plugin_hardwire_state_recognizes_three_lane_telemetry(tmp_path):
    status = load_status_script()
    plugin = tmp_path / "plugin.py"
    plugin.write_text(
        "MEMORYMUNCH_HARDWIRE_LIVE_WRITES = True\n"
        "MEMORYMUNCH_HARDWIRE_CAPTURE_LIVE = True\n"
        "MEMORYMUNCH_HARDWIRE_JANITOR_LIVE = True\n"
        "telemetry_lanes=prompt:curator+gateway/in_turn,background:capture+janitor/post_turn,status:checker+ledger/proof\n"
        "live_db_write=true live_vault_write=true capture_live_write=on janitor_live_mutation=on\n",
        encoding="utf-8",
    )

    result = status.plugin_hardwire_state(plugin)

    assert result["ok"] is True
    assert result["three_lane_telemetry"] is True
    assert result["telemetry_truth_string"] is True


def test_memorymunch_lane_status_splits_prompt_background_and_status():
    status = load_status_script()
    rows = [
        {"event": "turn_started"},
        {"event": "curator_model_completed"},
        {"event": "turn_completed"},
        {"event": "live_capture_attempted"},
        {"event": "live_capture_completed"},
        {"event": "janitor_cycle_completed", "status": "APPLIED", "live_db_write": True, "live_vault_write": False, "vault_archive_status": "no_archive_actions_requested"},
    ]

    result = status.memorymunch_lane_status(rows, {"three_lane_telemetry": True})

    assert result["prompt_lanes"]["curator_in_turn"] is True
    assert result["background_write_lanes"]["capture_post_turn"]["ok"] is True
    assert result["background_write_lanes"]["janitor_post_turn"]["ok"] is True
    assert result["status_reporting"]["turn_completed_is_ledger_only"] is True
    assert result["status_reporting"]["write_truth_events"] == ["live_capture_completed", "janitor_cycle_completed"]
