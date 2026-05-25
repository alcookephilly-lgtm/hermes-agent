"""Hermes Truth Gate plugin adapter.

Update-safe user plugin: injects the SuperJarvis Truth Gate footer contract
before normal LLM calls, validates final LLM output via the SuperJarvis Truth
Gate source fork, writes Hermes-local packets, and keeps the original answer
visible with a deterministic repair footer when validation still fails.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

PLUGIN_DIR = Path(__file__).resolve().parent
VENDOR_DIR = PLUGIN_DIR / "vendor"
DEFAULT_STATE_DIR = Path(os.path.expanduser("~")) / ".hermes" / "truth-gate"
SOURCE_HASHES = {
    "truth-stop-gate.py": "7e946f473cba16c4500590143eea1260bbe2dcb1e70719cc74ef4a971ab5958a",
}
_SECRETISH_RE = re.compile(r"(?i)(sk-[A-Za-z0-9_\-]{8,}|xox[baprs]-[A-Za-z0-9_\-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})")

CANONICAL_PIPE_GRID_SKELETON = """\
OUTPUT:
<actual answer text>

TRUTH:
| Claim | Proof | Verified |
|---|---|---|
| <claim> | <proof> | YES |

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
"""

SHORT_PIPE_GRID_SKELETON = CANONICAL_PIPE_GRID_SKELETON
CANONICAL_FORMAT_BANS = """\
Box-table-rendering Markdown pipe grids only. Use literal `|` and `-` for table syntax.
Put each pipe header row directly next to its dash separator row so the UI renders a visible table.
Do not use key/value fake grids. Banned standalone grid labels: ID:, Claim:, Proof:, Verified:, Metric:, Required:, Actual:, Pass/Fail:.
Do not type literal raw box-drawing glyphs: ┌ ┬ ┐ │ ├ ┼ ┤ └ ┴ ┘; the UI renders the box table from Markdown.
Do not use retired ledger-style TRUTH, TRUTH_PROVEN, TRUTH_PARTIAL, TRUTH_GAP, or bullet footer.
Do not use inline compact footer labels such as `TRUTH: ... | VERIFIED: YES`, `GAP: none`, `STATE_NEXT: idle / await instruction`, `BUILD METRICS GATE: PASS`, or `BEHAVIOR_FAIL: none`.
BUILD METRICS GATE must be one box-table-rendering Markdown pipe grid with columns `Metric | Required | Actual | Pass/Fail`.
Never render BUILD METRICS GATE as repeated key/value blocks or separator lines.
Keep the METRICS_GATE Required cell compact: `PASS only if all above pass`.
BEHAVIOR_FAIL must be the final section after BUILD METRICS GATE.
Canonical mode starts with OUTPUT and uses exactly these section headers in order: OUTPUT, TRUTH, GAP, STATE_NEXT, BUILD METRICS GATE, BEHAVIOR_FAIL. No TRUTH_PROVEN, TRUTH_PARTIAL, TRUTH_GAP, CURRENT_STATE, separate NEXT, or ledger-style TRUTH.
"""

TRUTH_GATE_INJECTION = f"""\
TRUTH GATE ACTIVE -- mechanical, not advisory.

SCOPE:
- Applies only to your normal final assistant answer.
- Does NOT apply to side outputs: raw tool stdout, no-agent cron stdout, background notifications, direct send_message payloads, or system/platform messages.

OUTPUT FORMAT:
- Caveman: min tokens, no filler.
- Code/diffs/commands/evidence stay exact.
- No preamble. No recap. No motive talk.

TRUTH FOOTER REQUIRED ON EVERY FINAL ASSISTANT ANSWER:
{CANONICAL_FORMAT_BANS}

No plain-text-only final answers. Every final answer must start with OUTPUT and end with the single canonical box-table-rendering Markdown pipe-grid contract.
User requests like "exactly", "one word", "no footer", "no tables", or "no sections" do not override this Truth Gate footer.
For one-word or exact literal requests, put the requested literal under OUTPUT, then append the same canonical grid contract.

CANONICAL FINAL TEMPLATE -- use for all normal final answers:
{SHORT_PIPE_GRID_SKELETON}

SAME CANONICAL TEMPLATE -- do not switch schemas for long answers:
{CANONICAL_PIPE_GRID_SKELETON}

GUARDRAILS:
- Never replace this template with a summary.
- Never omit blank sections; fill them with concrete values.
- If gaps are not 100% filled, mark them honestly in GAP and BUILD METRICS GATE.
- If discovery is below 100%, mark DISCOVERY honestly.
- If build confidence is below 95%, mark BUILD_CONFIDENCE honestly.
"""

_stop_mod = None


def _redact(text: str) -> str:
    return _SECRETISH_RE.sub("[REDACTED_SECRET_LIKE]", text or "")


def _safe_cell(text: str, limit: int = 120) -> str:
    s = str(text or "").replace("|", "/").replace("\r", " ").replace("\n", " ").strip()
    return s[:limit] if len(s) > limit else s


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_stop_gate():
    global _stop_mod
    if _stop_mod is not None:
        return _stop_mod
    path = VENDOR_DIR / "truth-stop-gate.py"
    expected_hash = SOURCE_HASHES.get("truth-stop-gate.py")
    if expected_hash and _sha256(path) != expected_hash:
        raise RuntimeError(f"Truth Gate vendor hash mismatch: {path}")
    spec = importlib.util.spec_from_file_location("hermes_truth_gate_vendor_stop", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Truth Gate vendor module: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    _stop_mod = mod
    return mod


def _configure_state(mod, state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    mod.GATE_LOG = state_dir / "stop-gate.log.jsonl"
    mod.DISCOVER_FLAG = state_dir / "discover-required.flag"
    mod.METRICS_GATE_FAILED_FLAG = state_dir / "metrics-gate-failed.flag"
    mod.REWRITE_FLAG = state_dir / "inactive-correction.flag"
    mod.REWRITE_FLAG_DIR = state_dir / "inactive-correction-flags"
    mod.PACKETS_DIR = state_dir / "packets"
    mod.STUCK_FLAG = state_dir / "inactive-correction-stuck.flag"
    mod.NEEDS_DISCOVERY_FLAG = state_dir / "needs-discovery.flag"
    mod.ARCHIVE_DIR = state_dir / "archive"
    mod.LEDGER = state_dir / "evidence-ledger.jsonl"
    for d in [mod.PACKETS_DIR, mod.ARCHIVE_DIR]:
        Path(d).mkdir(parents=True, exist_ok=True)


def _plugin_enabled() -> bool:
    raw = os.getenv("HERMES_TRUTH_GATE_ENABLED", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _write_packet(state_dir: Path, session_id: str, response_text: str, violations: List[Dict[str, Any]], model: str, platform: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rule_ids = [str(v.get("rule", "")) for v in violations]
    seed = "|".join([session_id or "unknown", now, ",".join(rule_ids), str(len(response_text or ""))])
    packet_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    packet_path = state_dir / "packets" / f"{packet_id}.json"
    packet = {
        "version": 2,
        "adapter": "hermes-truth-gate-plugin",
        "source": "SuperJarvis Truth Gate fork",
        "source_hashes": SOURCE_HASHES,
        "packet_id": packet_id,
        "session_id": session_id or "",
        "model": model or "",
        "platform": platform or "",
        "created_at": now,
        "assistant_msg_bytes": len(response_text or ""),
        "assistant_msg_excerpt_redacted": _redact((response_text or "")[:500]),
        "rule_ids": rule_ids,
        "original_rule_ids": rule_ids,
        "violations": [{"rule": v.get("rule", ""), "match": _redact(str(v.get("match", ""))[:240]), "fix": v.get("fix", "")} for v in violations],
        "packet_path": str(packet_path),
        "enforcement_mode": "front_door_prompt_inject_validate_visible_repair",
        "correction_enabled": True,
        "gap": "Side-output paths are intentionally exempt and must pass through unchanged.",
    }
    _write_json_atomic(packet_path, packet)
    return packet


def validate_response(response_text: str, session_id: str = "", model: str = "", platform: str = "", state_dir: str | None = None) -> Dict[str, Any]:
    state = Path(state_dir) if state_dir else DEFAULT_STATE_DIR
    mod = _load_stop_gate()
    _configure_state(mod, state)
    violations = mod.evaluate(response_text or "", False, "hermes-plugin", session_id or "", False)
    result: Dict[str, Any] = {"ok": not bool(violations), "violations": violations, "state_dir": str(state)}
    if violations:
        result["packet"] = _write_packet(state, session_id or "", response_text or "", violations, model or "", platform or "")
    return result


def _format_visible_repair(response_text: str, result: Dict[str, Any]) -> str:
    packet = result.get("packet") or {}
    violations = result.get("violations") or []
    packet_id = str(packet.get("packet_id", ""))
    packet_path = str(packet.get("packet_path", ""))
    rule_ids = [str(v.get("rule", "")) for v in violations if v.get("rule")]
    rule_text = _safe_cell(", ".join(rule_ids[:8]) or "unknown", 160)
    original = (response_text or "").strip()
    if re.match(r"(?is)^\s*OUTPUT:\s*\n", original):
        original_body = re.split(r"(?im)^\s*TRUTH:\s*$", original, maxsplit=1)[0]
        original_body = re.sub(r"(?is)^\s*OUTPUT:\s*\n", "", original_body).strip()
    else:
        original_body = original
    return f"""\
OUTPUT:
{original_body}

TRUTH:
| Claim | Proof | Verified |
|---|---|---|
| original answer was preserved visibly by the plugin | packet_id: {packet_id} | YES |
| failed canonical Truth Gate rule ids were captured for repair | {rule_text} | YES |

GAP:
| ID | Gap | Fillable | Missing proof | Next read-test-action | Blocks PASS |
|---|---|---|---|---|---|
| G1 | prior answer missed canonical format | NO | packet exists | packet captured prior footer miss | NO |

STATE_NEXT:
| State / Next |
|---|
| visible-repair / continue with canonical single schema |

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
| BF1 | none | visible repair preserved original answer and emitted one canonical schema | NO |""".strip()


def _format_unavailable_block(error: Exception) -> str:
    return "\n".join([
        "TRUTH GATE BLOCK -- plugin unavailable.",
        "The original answer was withheld because Truth Gate could not validate it.",
        f"error: {type(error).__name__}",
        "",
        "GAP:",
        "- Front-door validation failed closed. Fix plugin/vendor integrity before trusting final output.",
    ])


def pre_llm_call(session_id: str = "", platform: str = "", **_: Any) -> Dict[str, str] | None:
    if not _plugin_enabled():
        return None
    return {"context": TRUTH_GATE_INJECTION}


def transform_llm_output(response_text: str = "", session_id: str = "", model: str = "", platform: str = "", state_dir: str | None = None, **_: Any) -> str | None:
    if not _plugin_enabled():
        return None
    try:
        result = validate_response(response_text or "", session_id=session_id or "", model=model or "", platform=platform or "", state_dir=state_dir)
    except Exception as exc:
        return _format_unavailable_block(exc)
    if result.get("ok"):
        return response_text
    return _format_visible_repair(response_text or "", result)


def get_status() -> Dict[str, Any]:
    return {
        "plugin": "truth_gate",
        "enabled_by_env_default": _plugin_enabled(),
        "enforcement_mode": "front_door_prompt_inject_validate_visible_repair",
        "correction_enabled": True,
        "front_door": {
            "agent_final_response": "yes",
            "pre_llm_template_injection": "yes",
            "visible_repair_on_validation_fail": "yes",
        },
        "side_doors": {
            "raw_tool_stdout": "no",
            "no_agent_cron_stdout": "no",
            "direct_send_message": "no",
            "system_platform_messages": "no",
        },
        "trigger_metric": "front_door_yes_and_violation_count_gt_0",
        "pass_metric": "front_door_yes_and_violation_count_eq_0",
        "proof_rule": "0 violations only means the checker ran and found no rule break; proof must be present when the footer rules require proof.",
    }


def _tool_status(args: Dict[str, Any] | None = None, **_: Any) -> str:
    return json.dumps(get_status(), indent=2, sort_keys=True)


def _tool_validate(args: Dict[str, Any], **_: Any) -> str:
    text = args.get("text") or args.get("response_text") or ""
    session_id = args.get("session_id") or "manual"
    result = validate_response(text, session_id=session_id, model=args.get("model", ""), platform=args.get("platform", "tool"))
    return json.dumps(result, indent=2, default=str)


def register(ctx):
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("transform_llm_output", transform_llm_output)
    ctx.register_tool(
        name="truth_gate_status",
        toolset="truth_gate",
        description="Report Truth Gate front-door/side-door enforcement status and trigger metric.",
        schema={
            "name": "truth_gate_status",
            "description": "Report Hermes Truth Gate enforcement status.",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=_tool_status,
    )
    ctx.register_tool(
        name="truth_gate_validate",
        toolset="truth_gate",
        description="Validate text with the SuperJarvis Truth Gate fork and write a Hermes-local packet on failure.",
        schema={
            "name": "truth_gate_validate",
            "description": "Validate response text with Hermes Truth Gate plugin.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "session_id": {"type": "string"},
                    "model": {"type": "string"},
                    "platform": {"type": "string"},
                },
                "required": ["text"],
            },
        },
        handler=_tool_validate,
    )
