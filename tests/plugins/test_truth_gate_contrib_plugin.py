import importlib.util
import sys
from pathlib import Path
import tempfile

PLUGIN_DIR = Path(__file__).resolve().parents[2] / "contrib" / "plugins" / "truth_gate"
VENDOR_HASH = "7e946f473cba16c4500590143eea1260bbe2dcb1e70719cc74ef4a971ab5958a"


CANONICAL_TEXT = '''OUTPUT:
Tool result cited.

TRUTH:
| Claim | Proof | Verified |
|---|---|---|
| plugin adapter shape is under test | tests/plugins/test_truth_gate_contrib_plugin.py | YES |

GAP:
| ID | Gap | Fillable | Missing proof | Next read-test-action | Blocks PASS |
|---|---|---|---|---|---|
| G1 | nothing blocking | NO | none | none | NO |

STATE_NEXT:
| State / Next |
|---|
| idle / await review |

BUILD METRICS GATE:
| Metric | Required | Actual | Pass/Fail |
|---|---:|---:|---|
| GAPS_FILLED | 100% | 100% | PASS |
| DISCOVERY | 100% | 100% | PASS |
| BUILD_CONFIDENCE | >=95% | 100% | PASS |
| METRICS_GATE | PASS only if all above pass | PASS | PASS |

BEHAVIOR_FAIL:
| ID | Failure | Proof | Blocks PASS |
|---|---|---|---|
| BF1 | none | no blocking behavior failure | NO |
'''


def load_plugin():
    spec = importlib.util.spec_from_file_location("contrib_truth_gate_plugin_under_test", PLUGIN_DIR / "__init__.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_vendor_hash_mismatch_blocks_transform_output():
    mod = load_plugin()
    setattr(mod, "_stop_mod", None)
    mod.SOURCE_HASHES["truth-stop-gate.py"] = "0" * 64
    try:
        out = mod.transform_llm_output("unsafe original text", session_id="hash-check")
        assert "TRUTH GATE BLOCK" in out
        assert "plugin unavailable" in out
        assert "unsafe original text" not in out
    finally:
        setattr(mod, "_stop_mod", None)
        mod.SOURCE_HASHES["truth-stop-gate.py"] = VENDOR_HASH


def test_vendor_hash_mismatch_fails_closed():
    mod = load_plugin()
    setattr(mod, "_stop_mod", None)
    mod.SOURCE_HASHES["truth-stop-gate.py"] = "0" * 64
    try:
        try:
            mod.validate_response("unproven final answer", session_id="hash-check")
        except RuntimeError as exc:
            assert "hash mismatch" in str(exc)
        else:
            raise AssertionError("expected hash mismatch RuntimeError")
    finally:
        setattr(mod, "_stop_mod", None)
        mod.SOURCE_HASHES["truth-stop-gate.py"] = VENDOR_HASH


def test_valid_canonical_output_first_grid_passes_unchanged_without_packet():
    mod = load_plugin()
    with tempfile.TemporaryDirectory() as td:
        state = Path(td)
        out = mod.transform_llm_output(response_text=CANONICAL_TEXT, session_id="valid", state_dir=str(state))
        assert out == CANONICAL_TEXT
        assert not any((state / "packets").glob("*.json"))


def test_retired_ledger_truth_format_fails_with_canonical_violation():
    mod = load_plugin()
    retired = '''Yes.

TRUTH:
ID: T1
Claim: old ledger shape
Proof: old proof
Verified: YES

GAP:
| ID | Gap | Fillable | Missing proof | Next read-test-action | Blocks PASS |
|---|---|---|---|---|---|
| G1 | none | NO | none | none | NO |

STATE_NEXT:
| State / Next |
|---|
| idle / await instruction |

BUILD METRICS GATE:
| Metric | Required | Actual | Pass/Fail |
|---|---:|---:|---|
| GAPS_FILLED | 100% | 100% | PASS |
| DISCOVERY | 100% | 100% | PASS |
| BUILD_CONFIDENCE | >=95% | 100% | PASS |
| METRICS_GATE | PASS only if all above pass | PASS | PASS |

BEHAVIOR_FAIL:
| ID | Failure | Proof | Blocks PASS |
|---|---|---|---|
| BF1 | none | no blocking behavior failure | NO |
'''
    with tempfile.TemporaryDirectory() as td:
        result = mod.validate_response(retired, session_id="retired", state_dir=td)
        rules = {v["rule"] for v in result["violations"]}
        assert "evidence.schema.output-header.required-first" in rules
        assert "evidence.schema.v3.fake-key-value-grid" in rules
        assert result["ok"] is False


def test_duplicate_truth_gate_sections_fail():
    mod = load_plugin()
    dup = CANONICAL_TEXT + "\n\nTRUTH:\n| Claim | Proof | Verified |\n|---|---|---|\n| duplicate | proof | YES |\n"
    with tempfile.TemporaryDirectory() as td:
        result = mod.validate_response(dup, session_id="dup", state_dir=td)
        assert any(v["rule"] == "evidence.schema.duplicate-section" for v in result["violations"])


def test_invalid_answer_visible_repair_is_single_canonical_output_schema():
    mod = load_plugin()
    with tempfile.TemporaryDirectory() as td:
        state = Path(td)
        original = "I fixed it completely."
        out = mod.transform_llm_output(
            response_text=original,
            session_id="s1",
            model="m",
            platform="cli",
            state_dir=str(state),
        )
        assert out.startswith("OUTPUT:\n")
        assert original in out
        assert "REDACTED_EXCERPT" not in out
        assert "TRUTH GATE VISIBLE REPAIR" not in out
        assert "TRUTH_PROVEN" not in out
        assert "TRUTH_PARTIAL" not in out
        assert "Ledger anchor" not in out
        assert out.count("\nTRUTH:\n") == 1
        assert out.count("\nBUILD METRICS GATE:\n") == 1
        assert out.rstrip().endswith("| BF1 | none | visible repair preserved original answer and emitted one canonical schema | NO |")
        assert any((state / "packets").glob("*.json"))
        assert not (state / "rewrite-required-flags" / "s1.json").exists()
        assert not (state / "inactive-correction.flag").exists()
        assert not (state / "inactive-correction-flags" / "s1.flag").exists()
        assert not (state / "inactive-correction-stuck.flag").exists()


def test_missing_output_header_fails():
    mod = load_plugin()
    no_output = CANONICAL_TEXT.replace("OUTPUT:\n", "", 1)
    with tempfile.TemporaryDirectory() as td:
        result = mod.validate_response(no_output, session_id="no-output", state_dir=td)
        assert any(v["rule"] == "evidence.schema.output-header.required-first" for v in result["violations"])


def test_wrong_section_order_fails():
    mod = load_plugin()
    wrong = CANONICAL_TEXT.replace("STATE_NEXT:\n| State / Next |\n|---|\n| idle / await review |\n\nBUILD METRICS GATE:", "BUILD METRICS GATE:", 1)
    wrong = wrong.replace("BEHAVIOR_FAIL:", "STATE_NEXT:\n| State / Next |\n|---|\n| idle / await review |\n\nBEHAVIOR_FAIL:", 1)
    with tempfile.TemporaryDirectory() as td:
        result = mod.validate_response(wrong, session_id="order", state_dir=td)
        assert any(v["rule"] == "evidence.schema.section-order" for v in result["violations"])


def test_wrong_build_metrics_gate_rows_fail():
    mod = load_plugin()
    bad = CANONICAL_TEXT.replace("| DISCOVERY | 100% | 100% | PASS |\n", "")
    with tempfile.TemporaryDirectory() as td:
        result = mod.validate_response(bad, session_id="metrics", state_dir=td)
        assert any(v["rule"] == "evidence.schema.metrics-gate.row-missing" and v.get("match") == "DISCOVERY" for v in result["violations"])


def test_missing_behavior_fail_fails():
    mod = load_plugin()
    bad = CANONICAL_TEXT.split("\nBEHAVIOR_FAIL:\n", 1)[0] + "\n"
    with tempfile.TemporaryDirectory() as td:
        result = mod.validate_response(bad, session_id="bf", state_dir=td)
        assert any(v["rule"] == "evidence.schema.canonical-section-missing" and v.get("match") == "BEHAVIOR_FAIL" for v in result["violations"])


def test_packet_contract_visible_repair_not_block_only():
    mod = load_plugin()
    with tempfile.TemporaryDirectory() as td:
        result = mod.validate_response("unproven final answer", session_id="s2", state_dir=td)
        packet = result.get("packet") or {}
        assert packet["enforcement_mode"] == "front_door_prompt_inject_validate_visible_repair"
        assert packet["correction_enabled"] is True
        assert "truth_gate_exact_auto_rewrite_parity" not in packet
        assert "Side-output paths are intentionally exempt" in packet["gap"]


def test_pre_llm_call_injects_single_canonical_template_scope():
    mod = load_plugin()
    out = mod.pre_llm_call(session_id="s3", platform="telegram")
    ctx = out["context"]
    assert "TRUTH GATE ACTIVE -- mechanical" in ctx
    assert "TRUTH FOOTER REQUIRED ON EVERY FINAL ASSISTANT ANSWER" in ctx
    assert "OUTPUT:" in ctx
    assert "CANONICAL FINAL TEMPLATE" in ctx
    assert "SAME CANONICAL TEMPLATE" in ctx
    assert "BUILD METRICS GATE:" in ctx
    assert "TRUTH_PROVEN" in ctx  # banned text appears only in the do-not-use rule
    assert "ledger-style TRUTH" in ctx
    assert "Does NOT apply to side outputs" in ctx


def test_status_reports_front_door_yes_side_doors_no():
    mod = load_plugin()
    status = mod.get_status()
    assert status["front_door"]["agent_final_response"] == "yes"
    assert status["side_doors"]["raw_tool_stdout"] == "no"
    assert status["side_doors"]["no_agent_cron_stdout"] == "no"
    assert status["side_doors"]["direct_send_message"] == "no"
    assert status["side_doors"]["system_platform_messages"] == "no"
    assert status["trigger_metric"] == "front_door_yes_and_violation_count_gt_0"
    assert status["enforcement_mode"] == "front_door_prompt_inject_validate_visible_repair"
    assert status["correction_enabled"] is True
    assert status["front_door"]["pre_llm_template_injection"] == "yes"
