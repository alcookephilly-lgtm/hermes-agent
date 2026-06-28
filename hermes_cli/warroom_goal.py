"""Runtime-enforced Warroom /goal workflows.

This module is intentionally code-level enforcement, not prompt polish. It
recognizes the legacy Warroom trigger phrases and also treats every non-control
/goal payload as a Warroom workflow. Generic /goal fallback is intentionally
removed: slash /goal either creates Controller state and role-spawn evidence, or
blocks with an explicit GAP.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.agt_gateway import agt_action_gateway

FAST_TRIGGER = "Use adversary skill for:"
STRICT_TRIGGER = "Use plan adversary skill for:"
GLOBAL_TRIGGER = "Global slash /goal:"
STATE_VERSION = 3
WARROOM_PLAN_WORKFLOWS = {"strict_plan_adversary", "global_plan_adversary"}
ROLE_STALE_AFTER_SECONDS = 300.0
GRAPHIFY_STALE_AFTER_SECONDS = 24 * 3600.0
TRACKING_DOC_SUFFIXES = {"", ".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".log"}
REAL_DELEGATED_RUNTIME_GAP = (
    "real delegated role runtime missing: spawn_receipt_only receipts do not prove role execution; "
    "local_process pid receipts are spawn_receipt_only"
)
GRAPH_REPORT_PATH_RE = re.compile(
    r"(?P<path>(?:[A-Za-z]:[\\/]|/)[^`\"'\r\n]*?graphify-out[\\/]GRAPH_REPORT\.md)"
)
GRAPH_REPORT_HEADER_RE = re.compile(r"^# Graph Report - (?P<root>.+?)\s+\((?P<stamp>\d{4}-\d{2}-\d{2})\)\s*$")


def _sha256_file_optional(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _git_output(args: List[str], cwd: Path) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=1,
            check=False,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    return out or None


def _repo_root_for(path: Path) -> Optional[Path]:
    for parent in [path.parent, *path.parents]:
        if (parent / ".git").exists():
            return parent
    root = _git_output(["rev-parse", "--show-toplevel"], path.parent)
    return Path(root) if root else None


def _short_commit(value: Optional[str]) -> str:
    return value[:12] if value else "unknown"


_LOADED_CODE_PATH = Path(__file__).resolve()
_LOADED_CODE_SHA256 = _sha256_file_optional(_LOADED_CODE_PATH)
_LOADED_REPO_ROOT = _repo_root_for(_LOADED_CODE_PATH)
_LOADED_GIT_HEAD = _git_output(["rev-parse", "HEAD"], _LOADED_REPO_ROOT) if _LOADED_REPO_ROOT else None


def runtime_drift_status() -> Dict[str, Any]:
    """Compare the code imported into this process with the repo on disk."""
    current_file_sha = _sha256_file_optional(_LOADED_CODE_PATH)
    current_repo_head = _git_output(["rev-parse", "HEAD"], _LOADED_REPO_ROOT) if _LOADED_REPO_ROOT else None
    reasons: List[str] = []
    if _LOADED_GIT_HEAD and current_repo_head and _LOADED_GIT_HEAD != current_repo_head:
        reasons.append("repo_head_mismatch")
    if _LOADED_CODE_SHA256 and current_file_sha and _LOADED_CODE_SHA256 != current_file_sha:
        reasons.append("loaded_file_changed_on_disk")
    return {
        "loaded_code_commit": _LOADED_GIT_HEAD,
        "repo_head_commit": current_repo_head,
        "stale": bool(reasons),
        "stale_reasons": reasons,
        "loaded_code_path": str(_LOADED_CODE_PATH),
        "repo_path": str(_LOADED_REPO_ROOT) if _LOADED_REPO_ROOT else "unknown",
        "loaded_code_sha256": _LOADED_CODE_SHA256,
        "current_file_sha256": current_file_sha,
    }


def runtime_drift_line() -> str:
    status = runtime_drift_status()
    reasons = ",".join(status["stale_reasons"]) if status["stale_reasons"] else "none"
    stale = "yes" if status["stale"] else "no"
    return (
        "Runtime drift: "
        f"loaded_code_commit={_short_commit(status['loaded_code_commit'])} "
        f"repo_HEAD={_short_commit(status['repo_head_commit'])} "
        f"stale={stale} "
        f"reasons={reasons} "
        f"loaded_code_path={status['loaded_code_path']} "
        f"repo_path={status['repo_path']}"
    )


def _role_delegate_goal(state: "WarroomGoalState", role: str, role_card_path: str, evidence_path: str) -> str:
    try:
        role_card_text = Path(role_card_path).read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        role_card_text = f"<role card read failed: {exc}>"
    return (
        "[WARROOM V3 ROLE DISPATCH]\n"
        f"Role: {role}\n"
        f"Workflow: {state.workflow}\n"
        f"Parent session: {state.session_id}\n"
        f"Controller model: {state.controller_model or 'unknown'}\n"
        f"Tracking dir: {state.tracking_dir or ''}\n"
        f"Allowed mutation root: {state.allowed_mutation_root or ''}\n"
        f"Evidence path: {evidence_path}\n\n"
        + (
            "Remote target guard: target=vps. Do not inspect local /etc, /opt, or /root "
            "as target files; use ssh vps for remote target reads.\n\n"
            if state.remote_target == "vps"
            else ""
        )
        + "Follow the role card exactly. If you perform or verify work, write concise evidence to the evidence path.\n"
        "Do not claim final completion; Guardian/final gate owns closure.\n\n"
        f"Goal:\n{state.original_goal}\n\n"
        f"Role card ({role_card_path}):\n{role_card_text}"
    )


def _native_background_delegate_adapter(parent_agent: Any):
    def _adapter(*, role: str, role_card_path: str, evidence_path: str, state: "WarroomGoalState") -> Dict[str, Any]:
        from tools.delegate_tool import delegate_task

        raw = delegate_task(
            goal=_role_delegate_goal(state, role, role_card_path, evidence_path),
            context=(
                "Warroom runtime role dispatch. Return role-specific findings/evidence only. "
                "Parent Controller remains source of orchestration truth."
            ),
            toolsets=["terminal", "file", "search", "session_search"],
            role="leaf",
            background=True,
            parent_agent=parent_agent,
        )
        try:
            payload = json.loads(raw)
        except Exception as exc:
            raise RuntimeError(f"native delegate returned non-JSON response: {raw!r}") from exc
        if payload.get("error"):
            raise RuntimeError(str(payload.get("error")))
        delegation_id = str(payload.get("delegation_id") or "").strip()
        if not delegation_id:
            raise RuntimeError(f"native delegate did not return delegation_id: {payload}")
        child_model = payload.get("model") or getattr(parent_agent, "model", None)
        child_provider = payload.get("provider") or getattr(parent_agent, "provider", None)
        return {
            "adapter": "native_delegate_background",
            "delegation_id": delegation_id,
            "runtime_id": delegation_id,
            "model": child_model,
            "provider": child_provider,
            "exit_code": 0,
            "stdout": raw,
            "json_payload": payload,
            "current_phase": "background_dispatched",
        }

    return _adapter

FAST_ROLES = ["controller", "builder", "adversary", "reviewer", "guardian"]
PLAN_ROLES = ["controller", "plan_builder", "plan_adversary", "plan_reviewer"]
BUILD_ROLES = ["builder", "adversary", "reviewer", "guardian"]
STRICT_ROLES = PLAN_ROLES
STRICT_ALL_ROLES = PLAN_ROLES + BUILD_ROLES
ALL_ROLES = [
    "controller",
    "plan_builder",
    "plan_adversary",
    "plan_reviewer",
    "builder",
    "adversary",
    "reviewer",
    "guardian",
]

REQUIRED_SECTION_INTENTS = ("Acceptance", "Constraints", "Verify with")
HEADING_PREFIX_RE = re.compile(r"^\s*(?:#{1,6}\s+|[-*+]\s+|\d+[.)]\s+)")
MUTATING_TOOLS = {"write_file", "patch", "skill_manage"}
READ_ONLY_RECOVERY_TOOLS = {"read_file", "search_files", "session_search", "skill_view", "skills_list"}
READ_ONLY_PROCESS_ACTIONS = {"list", "poll", "log", "wait"}
ROBOT_HAND_CURRENT_MARKERS = (
    "ROBOT_HAND_DISCOVERY_PASS",
    "GRAPHIFY_DISCOVERY_PASS",
    "JCODEMUNCH_INDEX_CURRENT",
    "CODEGRAPH_INDEX_CURRENT",
    "CODEGRAPH_SYNCED",
    "SMART_READ_USED",
    "JDOCMUNCH_USED",
)
ROBOT_HAND_NAMED_GAPS = (
    "ROBOT_HAND_GAP",
    "JCODEMUNCH_STALE_GAP",
    "GRAPHIFY_STALE_BLOCK",
    "CODEGRAPH_STALE_GAP",
)
ROBOT_HAND_STALE_MARKERS = (
    "JCODEMUNCH_INDEX_STALE",
    "JCODEMUNCH_STALE_GAP",
    "GRAPHIFY_STALE_BLOCK",
    "CODEGRAPH_STALE",
    "CODEGRAPH_STALE_GAP",
)
PONYTAIL_TOOL_NAME = "cli-anything-ponytail-mcp"
PONYTAIL_TOOL_PATH = "/home/alcoo/.local/bin/cli-anything-ponytail-mcp"
PONYTAIL_RETRY_TEMPLATE = "cli-anything-ponytail-mcp review --target <path>"
PONYTAIL_PROOF_MARKERS = (
    "PONYTAIL_REVIEW",
    "PONYTAIL_AUDIT",
    "PONYTAIL_DEBT",
    "PONYTAIL_GAIN",
    "PONYTAIL_NOT_APPLICABLE",
    "PONYTAIL_GAP",
)
PONYTAIL_WRONG_TOOL_RE = re.compile(r"(?:^|[\s;&|])(?:ponytail|ponytail-mcp)(?:\s|$)")
CONTROLLER_SIDE_EFFECT_MARKER = "CONTROLLER_SIDE_EFFECT_DETECTED"
CONTROLLER_SIDE_EFFECT_APPROVAL_MARKERS = (
    "CONTROLLER_SOURCE_MUTATION_APPROVED",
    "BUILDER_REPLAY_VERIFIED",
    "BUILDER_REPLAY_APPROVED",
)
FINAL_CLAIM_RE = re.compile(r"\b(done|fixed|complete|completed|shipped|hardwired)\b", re.I)
NEGATED_CLAIM_RE = re.compile(r"\b(not|no|isn[’\']t|is not|still|remain(?:s|ing)?|open|failed|blocked|gap)\b", re.I)
E2E_CLAIM_RE = re.compile(r"\be2e\b|end[- ]to[- ]end", re.I)
HEALTH_ONLY_RE = re.compile(r"health check|/health|status endpoint", re.I)
E2E_EVIDENCE_RE = re.compile(r"pytest|playwright|browser|selenium|end[- ]to[- ]end test|e2e test", re.I)
SAFE_TERMINAL_REDIRECT_RE = re.compile(r"(?:^|[\s;&|])\d?>\s*/dev/null\b|(?:^|[\s;&|])\d?>&\d\b")
FILE_TERMINAL_REDIRECT_RE = re.compile(r"(?:^|[\s;&|])\d?>>?\s*\S")
DESTRUCTIVE_TERMINAL_RE = re.compile(
    r"\b(rm\s+-|mv\s+|cp\s+|touch\s+|mkdir\s+|chmod\s+|chown\s+|sed\s+-i|git\s+(?:reset|clean|checkout|restore)\b|python\b.*\b(write|write_text|write_bytes|unlink|remove|rmtree)\b|tee\s+|>>\s*\S|>\s*\S)",
    re.I,
)
ADMIN_MUTATING_TERMINAL_RE = re.compile(
    r"""
    \b(
        systemctl\s+(?:start|stop|restart|reload|enable|disable|mask|unmask)\b
        |service\s+(?:\S+\s+)?(?:start|stop|restart|reload|enable|disable|mask|unmask)\b
        |docker\s+(?:(?:start|stop|restart|rm|rmi|run|build|pull|push)\b|compose\s+(?:up|down|restart)\b)
        |kubectl\s+(?:apply|delete|patch|create|scale|set|rollout\s+restart)\b
        |(?:apt|apt-get|dnf|yum|pip|npm)\s+(?:install|remove|purge|upgrade|update|uninstall)\b
        |git\s+(?:push|commit|merge|rebase|cherry-pick|am|apply)\b
        |(?:^|[;&|]|['\"])\s*(?:kill|pkill|killall)\b
    )
    """,
    re.I | re.X,
)
EXECUTE_CODE_WRITE_RE = re.compile(r"\b(open\(.+['\"]w|write_text\(|write_bytes\(|shutil\.rmtree|os\.remove|Path\(.+\)\.unlink)", re.I)
RAW_DISCOVERY_TERMINAL_RE = re.compile(r"\b(grep|rg|find|cat|head|tail)\b", re.I)
ALLOWED_HALT_REASONS = [
    "explicit_user_stop",
    "credentials_or_physical_access",
    "destructive_rollback_or_user_data_risk",
    "scope_expansion",
    "dependency_unavailable_after_alternatives",
    "confidence_below_95",
]
NONCRITICAL_HALT_REASONS = [
    "approval_phase",
    "plan_gate_phrase",
    "tracking_gate_phrase",
    "live_promotion_phrase",
    "internal_reviewer_handoff",
    "guardian_handoff",
    "normal_milestone_boundary",
]
NONCRITICAL_HALT_TEXT_PATTERNS = [
    ("approval_phase", re.compile(r"\b(wait|pause|stop|halt)\b.*\b(approval|approve|permission)\b", re.I)),
    ("plan_gate_phrase", re.compile(r"\b(plan|tracking)\b.*\b(approval|approve|gate phrase|sign[- ]off)\b", re.I)),
    ("live_promotion_phrase", re.compile(r"\b(live promotion|promote live|promotion approval|approval phrase)\b", re.I)),
    ("internal_reviewer_handoff", re.compile(r"\b(reviewer handoff|waiting for reviewer|send to reviewer)\b", re.I)),
    ("guardian_handoff", re.compile(r"\b(guardian handoff|waiting for guardian|send to guardian)\b", re.I)),
    ("normal_milestone_boundary", re.compile(r"\b(milestone boundary|phase complete|phase boundary|ready for next phase)\b", re.I)),
]


@dataclass(frozen=True)
class WarroomDetection:
    workflow: str
    trigger: str
    body: str
    missing_sections: List[str] = field(default_factory=list)


@dataclass
class WarroomGoalState:
    version: int = STATE_VERSION
    workflow: str = ""
    status: str = "active"  # active | blocked | halted | gap | done
    original_goal: str = ""
    trigger: str = ""
    session_id: str = ""
    parent_session_id: Optional[str] = None
    created_at: float = 0.0
    updated_at: float = 0.0
    controller_active: bool = True
    controller_model: Optional[str] = None
    remote_target: Optional[str] = None
    current_role: Optional[str] = "controller"
    required_roles: List[str] = field(default_factory=list)
    required_action: Optional[str] = "spawn_roles"
    roles_started: Dict[str, bool] = field(default_factory=dict)
    role_records: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    role_spawn_attempts: List[Dict[str, Any]] = field(default_factory=list)
    role_spawn_adapter: Optional[str] = None
    role_spawn_evidence_path: Optional[str] = None
    role_spawn_gap: Optional[str] = None
    role_cards: Dict[str, str] = field(default_factory=dict)
    gates: Dict[str, str] = field(default_factory=dict)
    gate_evidence: Dict[str, List[str]] = field(default_factory=dict)
    plan_packet_path: Optional[str] = None
    tracking_dir: Optional[str] = None
    proof_packet_path: Optional[str] = None
    guardian_verdict_path: Optional[str] = None
    guardian_pass: bool = False
    allowed_mutation_root: Optional[str] = None
    denied_mutation_roots: List[str] = field(default_factory=list)
    delegate_runtime_checked: bool = True
    delegate_runtime_available: bool = False
    last_gap: Optional[str] = None
    halt_reason: Optional[str] = None
    allowed_halt_reasons: List[str] = field(default_factory=lambda: list(ALLOWED_HALT_REASONS))
    halt_policy_enforced: bool = True
    noncritical_pause_attempts: List[Dict[str, Any]] = field(default_factory=list)
    cleanup_gap: Optional[str] = None
    final_claim_allowed: bool = False
    final_claim_state_hash: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "WarroomGoalState":
        data = json.loads(raw)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def status_line(self) -> str:
        refresh_role_runtime_status(self)
        active_bits = []
        for role, record in sorted(self.role_records.items()):
            status = record.get("status") or "unknown"
            child_session = record.get("child_session_id") or record.get("delegation_id") or record.get("runtime_id") or "none"
            last_seen = record.get("last_seen_at") or "unknown"
            phase = record.get("current_phase") or status
            stale = "stale" if record.get("stale") else "not-stale"
            active_bits.append(f"{role}:{status}:{child_session}:last_seen={last_seen}:phase={phase}:{stale}")
        progress = "; ".join(active_bits) if active_bits else "no role records"
        return (
            f"WARROOM V3 {self.workflow}: {self.status} (role={self.current_role or 'none'}) "
            f"{runtime_drift_line()} progress=[{progress}]"
        )


def _final_claim_state_hash(state: WarroomGoalState) -> str:
    """Stable hash of the state a Guardian PASS unlocked for final claims."""
    payload = asdict(state)
    for volatile in ("created_at", "updated_at", "final_claim_state_hash"):
        payload.pop(volatile, None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def refresh_role_runtime_status(state: WarroomGoalState, *, now: Optional[float] = None) -> WarroomGoalState:
    """Annotate role records with live/stale runtime state.

    ``pid:*`` records are spawn receipts only. They become ``stale_dead_pid``
    when the process is gone. Real delegated work must carry a
    ``child_session_id`` or ``delegation_id`` and is marked stale when its
    heartbeat ages out.
    """
    current = time.time() if now is None else now
    for role, record in (state.role_records or {}).items():
        runtime_id = str(record.get("runtime_id") or "")
        record.setdefault("current_phase", record.get("status") or "unknown")
        if runtime_id.startswith("pid:"):
            record["spawn_receipt_only"] = True
            record.setdefault("runtime_kind", "spawn_receipt")
            try:
                alive = _pid_is_alive(int(runtime_id.split(":", 1)[1]))
            except Exception:
                alive = False
            record["stale"] = not alive
            record["stale_reason"] = None if alive else "stale/dead pid"
            if not alive and record.get("status") in {"spawned", "spawn_receipt_only", "running"}:
                record["status"] = "stale_dead_pid"
                record["current_phase"] = "stale_dead_pid"
            continue

        if record.get("child_session_id") or record.get("delegation_id"):
            record.setdefault("runtime_kind", "real_child_session")
            record["spawn_receipt_only"] = False
            last_seen_raw = record.get("last_seen_epoch") or record.get("last_seen_ts")
            if not isinstance(last_seen_raw, (int, float)):
                last_seen_raw = current
                record["last_seen_epoch"] = last_seen_raw
            stale = current - float(last_seen_raw) > ROLE_STALE_AFTER_SECONDS
            record["stale"] = stale
            record["stale_reason"] = "child session heartbeat stale" if stale else None
            if stale and record.get("status") in {"spawned", "running", "active_child_work"}:
                record["status"] = "stalled"
                record["current_phase"] = "stalled"
            elif record.get("status") in {"spawned", "running"} and not stale:
                record["status"] = "active_child_work"
                record["current_phase"] = record.get("current_phase") or "active_child_work"
            continue

        record.setdefault("runtime_kind", "unknown")
    return state


_DB_CACHE: Dict[str, Any] = {}


def _normalize_heading(line: str) -> str:
    text = (line or "").strip()
    while True:
        updated = re.sub(r"^\s*(?:#{1,6}\s*|[-*+]\s*|\d+[.)]\s*)", "", text)
        if updated == text:
            break
        text = updated
    text = text.casefold()
    text = re.sub(r"[\W_]+", " ", text)
    return " ".join(text.split())


def _classify_heading_intent(line: str) -> Optional[str]:
    stripped = (line or "").strip()
    if not stripped or (":" not in stripped and not HEADING_PREFIX_RE.match(line or "")):
        return None
    normalized = _normalize_heading(line)
    if not normalized:
        return None
    if normalized.startswith("verify with"):
        return "Verify with"
    if normalized.startswith("test with") or normalized in {"verification", "commands to run", "proof commands"}:
        return "Verify with"
    if normalized in {"acceptance", "acceptance criteria", "accepted when", "done when"}:
        return "Acceptance"
    if normalized in {"constraints", "constraint", "boundaries", "limitations", "requirements"}:
        return "Constraints"
    return None


def _missing_required_heading_intents(body: str) -> List[str]:
    present = {
        intent
        for intent in (_classify_heading_intent(line) for line in (body or "").splitlines())
        if intent
    }
    return [intent for intent in REQUIRED_SECTION_INTENTS if intent not in present]


def _meta_key(session_id: str) -> str:
    return f"warroom_goal:{session_id}"


def _get_session_db() -> Optional[Any]:
    try:
        from hermes_constants import get_hermes_home
        from hermes_state import SessionDB

        home = str(get_hermes_home())
    except Exception:
        return None
    if home in _DB_CACHE:
        return _DB_CACHE[home]
    try:
        db = SessionDB()
    except Exception:
        return None
    _DB_CACHE[home] = db
    return db


def detect_warroom_goal(arg: str) -> Optional[WarroomDetection]:
    """Return Warroom workflow detection for every non-control /goal payload.

    Slash command handlers pass the text after ``/goal`` here. The two legacy
    trigger phrases keep their exact role semantics. Any other non-empty text is
    the global hardwire path: plan roles start first, build roles wait for
    plan/tracking gates, and normal GoalManager fallback is unreachable.
    """
    raw = (arg or "").strip()
    if raw.startswith(FAST_TRIGGER):
        body = raw[len(FAST_TRIGGER):].strip()
        if not body:
            return WarroomDetection("fast_adversary", FAST_TRIGGER, body, ["Goal body"])
        return WarroomDetection("fast_adversary", FAST_TRIGGER, body, [])
    if raw.startswith(STRICT_TRIGGER):
        body = raw[len(STRICT_TRIGGER):].strip()
        missing = _missing_required_heading_intents(body)
        if not body:
            missing.insert(0, "Goal body")
        return WarroomDetection("strict_plan_adversary", STRICT_TRIGGER, body, missing)
    if raw:
        return WarroomDetection("global_plan_adversary", GLOBAL_TRIGGER, raw, [])
    return WarroomDetection("global_plan_adversary", GLOBAL_TRIGGER, raw, ["Goal body"])


def split_goal_slash_text(text: str) -> Optional[str]:
    """Extract the payload from a literal /goal message, or None if not /goal."""
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not re.match(r"^/goal(?:\s|$)", stripped, re.I):
        return None
    return stripped[5:].strip()


def handle_global_goal_slash(
    session_id: str,
    text: str,
    *,
    tracking_dir: Optional[str] = None,
    allowed_mutation_root: Optional[str] = None,
    parent_agent: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """Pre-model global /goal router for surfaces without slash dispatch.

    Returns None when ``text`` is not a literal /goal command. Otherwise returns
    a dict with user-facing ``response`` and optional ``kickoff`` prompt. No LLM
    call is needed to enforce the command.
    """
    arg = split_goal_slash_text(text)
    if arg is None:
        return None
    lower = arg.strip().lower()
    if lower in {"status", "pause", "resume", "clear", "stop", "done"}:
        if lower == "status":
            state = load_warroom_goal(session_id)
            return {"handled": True, "response": state.status_line() if state else "No active Warroom /goal.", "state": state, "kickoff": None}
        if lower == "pause":
            state = halt_warroom_goal(session_id, reason="/goal pause")
            return {"handled": True, "response": state.status_line() if state else "No active Warroom /goal.", "state": state, "kickoff": None}
        if lower == "resume":
            state = resume_warroom_goal(session_id)
            kickoff = controller_kickoff_prompt(state) if state else None
            return {"handled": True, "response": state.status_line() if state else "No active Warroom /goal.", "state": state, "kickoff": kickoff}
        state = halt_warroom_goal(session_id, reason=f"/goal {lower}")
        return {"handled": True, "response": state.status_line() if state else "No active Warroom /goal.", "state": state, "kickoff": None}
    try:
        state = create_warroom_goal(
            session_id,
            arg,
            tracking_dir=tracking_dir,
            allowed_mutation_root=allowed_mutation_root,
            parent_agent=parent_agent,
        )
        return {
            "handled": True,
            "response": notice_for_state(state),
            "state": state,
            "kickoff": controller_kickoff_prompt(state) if state.status not in {"blocked", "gap"} else None,
        }
    except Exception as exc:
        return {"handled": True, "response": f"WARROOM V3 GAP: /goal hardwire failed before model fallback: {exc}", "state": None, "kickoff": None}


def load_warroom_goal(session_id: str) -> Optional[WarroomGoalState]:
    if not session_id:
        return None
    db = _get_session_db()
    if db is None:
        return None
    try:
        raw = db.get_meta(_meta_key(session_id))
    except Exception:
        return None
    if not raw:
        return None
    try:
        return WarroomGoalState.from_json(raw)
    except Exception:
        return None


def save_warroom_goal(session_id: str, state: WarroomGoalState) -> None:
    if not session_id:
        return
    state.session_id = session_id
    state.updated_at = time.time()
    db = _get_session_db()
    if db is None:
        return
    agt_action_gateway(
        action="proof_state.write",
        caller="hermes_cli.warroom_goal.save_warroom_goal",
        policies=("parent_owned_proof_write",),
        target=_meta_key(session_id),
        state={"current_role": state.current_role, "status": state.status},
        metadata={"role": "controller", "proof_or_state_write": True},
    )
    try:
        db.set_meta(_meta_key(session_id), state.to_json())
    except Exception:
        pass


def mark_controller_kickoff_consumed(session_id: str, mechanism: str) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    state.gates["controller_kickoff"] = "pass"
    state.gate_evidence.setdefault("controller_kickoff", []).append(mechanism)
    save_warroom_goal(session_id, state)
    return state


def _default_tracking_dir() -> str:
    return str(Path.cwd() / ".warroom")


def _default_denied_roots() -> List[str]:
    roots = ["/home/alcoo/.hermes/skills", "/mnt/c/Users/paulcooke1976/CLAUDE CONFIGS/skills"]
    try:
        from agent.skill_utils import get_skill_directories

        roots.extend(str(p) for p in get_skill_directories())
    except Exception:
        pass
    out: List[str] = []
    for root in roots:
        try:
            resolved = str(Path(root).expanduser().resolve())
        except Exception:
            resolved = root
        if resolved not in out:
            out.append(resolved)
    return out


def _role_cards_for(tracking_dir: str) -> Dict[str, str]:
    tracking_base = Path(tracking_dir) / "role-cards"
    package_base = Path(__file__).resolve().parent / "warroom_role_cards"
    cards: Dict[str, str] = {}
    for role in ALL_ROLES:
        filename = f"{role.replace('_', '-')}.md"
        tracking_card = tracking_base / filename
        package_card = package_base / filename
        cards[role] = str(tracking_card if tracking_card.exists() else package_card)
    return cards


def _shared_context_pack_path(tracking_dir: Optional[str], role_card_path: str) -> Optional[str]:
    card_path = Path(role_card_path)
    if card_path.exists():
        try:
            for line in card_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lower().startswith("use shared context pack:"):
                    target = line.split(":", 1)[1].strip()
                    if not target:
                        break
                    resolved = (card_path.parent / target).expanduser().resolve()
                    return str(resolved)
        except Exception:
            pass
    if tracking_dir:
        shared = Path(tracking_dir) / "shared-context-pack.md"
        if shared.exists():
            return str(shared)
    return None


def _role_policy_metadata(role: str) -> Dict[str, Any]:
    if role == "builder":
        return {
            "toolset_profile": "edit/test",
            "mutation_profile": "source-mutation-allowed",
            "source_mutation_allowed": True,
        }
    if role in {"controller", "plan_builder"}:
        return {
            "toolset_profile": "docs-only",
            "mutation_profile": "tracking-docs-only" if role == "controller" else "docs-only",
            "source_mutation_allowed": False,
        }
    if role in {"adversary", "reviewer", "guardian", "plan_adversary", "plan_reviewer"}:
        return {
            "toolset_profile": "read/test/review",
            "mutation_profile": "read-only",
            "source_mutation_allowed": False,
        }
    return {"source_mutation_allowed": False}


def _annotate_role_record(record: Dict[str, Any], *, state: WarroomGoalState, role: str, role_card_path: str) -> Dict[str, Any]:
    record.update(_role_policy_metadata(role))
    record.setdefault("model", state.controller_model)
    shared_context_pack_path = _shared_context_pack_path(state.tracking_dir, role_card_path)
    if shared_context_pack_path:
        record["shared_context_pack_path"] = shared_context_pack_path
    return record


def _utc_stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _role_spawn_dir(state: WarroomGoalState) -> Path:
    base = Path(state.tracking_dir or _default_tracking_dir()) / "role-spawn-evidence"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def warroom_state_hash(state: WarroomGoalState) -> str:
    """Stable hash used to reject late async writes against stale state."""
    payload = asdict(state)
    # ``updated_at`` is persistence bookkeeping. It should not make an
    # otherwise unchanged state reject its own async result.
    payload["updated_at"] = 0.0
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _role_from_record(state: WarroomGoalState, record: Dict[str, Any]) -> str:
    for role, candidate in (state.role_records or {}).items():
        if candidate is record:
            return role
    return str(record.get("role") or "unknown")


def _write_role_heartbeat(state: WarroomGoalState, record: Dict[str, Any]) -> Optional[str]:
    tracking_dir = Path(state.tracking_dir or "") if state.tracking_dir else None
    if tracking_dir is None:
        return None
    try:
        role = _role_from_record(state, record)
        stamp = str(record.get("last_seen_at") or _utc_stamp()).replace(":", "").replace("-", "")
        path = tracking_dir / "heartbeats" / f"{role}-{stamp}.json"
        _write_json(
            path,
            {
                "event": "heartbeat",
                "role": role,
                "status": record.get("status"),
                "current_phase": record.get("current_phase"),
                "child_session_id": record.get("child_session_id"),
                "delegation_id": record.get("delegation_id"),
                "runtime_id": record.get("runtime_id"),
                "evidence_path": record.get("evidence_path"),
                "last_seen_at": record.get("last_seen_at"),
                "last_seen_epoch": record.get("last_seen_epoch"),
                "spawn_receipt_only": record.get("spawn_receipt_only"),
                "state_hash": warroom_state_hash(state),
            },
        )
        return str(path)
    except Exception:
        return None


def _write_async_quarantine(
    state: WarroomGoalState,
    *,
    role: str,
    evidence_path: str,
    status: str,
    current_hash: str,
    expected_hash: Optional[str],
    expected_version: Optional[int],
    dispatch_ts: Optional[str] = None,
    target_scope: Optional[str] = None,
) -> str:
    tracking_dir = Path(state.tracking_dir or _default_tracking_dir())
    stamp = _utc_stamp().replace(":", "").replace("-", "")
    path = tracking_dir / "quarantine" / f"{role}-{stamp}.json"
    _write_json(
        path,
        {
            "event": "stale_async_result",
            "status": "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION",
            "state_class": "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION",
            "role": role,
            "dispatch_timestamp": dispatch_ts,
            "requested_status": status,
            "evidence_path": evidence_path,
            "target_scope": target_scope or state.allowed_mutation_root or state.tracking_dir,
            "state_version": state.version,
            "expected_state_version": expected_version,
            "current_state_hash": current_hash,
            "expected_state_hash": expected_hash,
            "next_safe_action": "Treat late output as stale; harvest ledger/log/diff/current state, then rescue/requeue or Builder replay before accepting it.",
        },
    )
    return str(path)


def mark_role_stalled(
    session_id: str,
    role: str,
    *,
    runtime_id: Optional[str] = None,
    child_session_id: Optional[str] = None,
    delegation_id: Optional[str] = None,
    elapsed: Optional[float] = None,
    current_phase: Optional[str] = None,
    evidence_path: Optional[str] = None,
    next_safe_action: str = "Harvest ledger/log/diff/current state; rescue/requeue is primary before accepting more source changes.",
) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    record: Dict[str, Any] = dict(state.role_records.get(role) or {"role": role})
    now = _utc_stamp()
    record.update(
        {
            "role": role,
            "status": "stalled",
            "current_phase": current_phase or record.get("current_phase") or "stalled",
            "runtime_id": runtime_id or record.get("runtime_id"),
            "child_session_id": child_session_id or record.get("child_session_id"),
            "delegation_id": delegation_id or record.get("delegation_id"),
            "last_seen_at": record.get("last_seen_at") or now,
            "last_seen_epoch": record.get("last_seen_epoch") or time.time(),
            "evidence_path": evidence_path or record.get("evidence_path"),
            "stale": True,
            "stale_reason": "stalled timeout",
        }
    )
    tracking_dir = Path(state.tracking_dir or _default_tracking_dir())
    diag_path = tracking_dir / "diagnostics" / f"{role}-stalled-{now.replace(':', '').replace('-', '')}.json"
    _write_json(
        diag_path,
        {
            "event": "timeout_diagnostic",
            "role": role,
            "runtime_id": record.get("runtime_id"),
            "child_session_id": record.get("child_session_id"),
            "delegation_id": record.get("delegation_id"),
            "elapsed": elapsed,
            "last_seen_at": record.get("last_seen_at"),
            "current_phase": record.get("current_phase"),
            "evidence_path": record.get("evidence_path"),
            "next_safe_action": next_safe_action,
        },
    )
    record["diagnostic_path"] = str(diag_path)
    state.role_records[role] = record
    save_warroom_goal(session_id, state)
    return state


def _role_record(
    *,
    role: str,
    status: str,
    role_card_path: str,
    adapter: str,
    runtime_id: str,
    evidence_path: str,
    exit_code: Optional[int] = None,
    error: Optional[str] = None,
    child_session_id: Optional[str] = None,
    delegation_id: Optional[str] = None,
    runtime_kind: Optional[str] = None,
    current_phase: Optional[str] = None,
    spawn_receipt_only: Optional[bool] = None,
) -> Dict[str, Any]:
    now = _utc_stamp()
    now_epoch = time.time()
    inferred_kind = runtime_kind or ("real_child_session" if child_session_id or delegation_id else ("spawn_receipt" if str(runtime_id).startswith("pid:") else adapter))
    record: Dict[str, Any] = {
        "role": role,
        "status": status,
        "role_card_path": role_card_path,
        "role_card_sha256": _sha256_file(role_card_path) if Path(role_card_path).exists() else None,
        "adapter": adapter,
        "runtime_id": runtime_id,
        "runtime_kind": inferred_kind,
        "child_session_id": child_session_id,
        "delegation_id": delegation_id,
        "spawn_receipt_only": bool(spawn_receipt_only) if spawn_receipt_only is not None else inferred_kind == "spawn_receipt",
        "current_phase": current_phase or status,
        "started_at": now,
        "last_seen_at": now,
        "last_seen_epoch": now_epoch,
        "evidence_path": evidence_path,
        "exit_code": exit_code,
        "stale": False,
        "stale_reason": None,
    }
    if error:
        record["error"] = error
    return record


def _spawn_local_role_process(state: WarroomGoalState, role: str, role_card_path: str, evidence_path: str) -> Dict[str, Any]:
    cmd = [
        sys.executable,
        "-m",
        "hermes_cli.warroom_role_worker",
        "--role",
        role,
        "--role-card",
        role_card_path,
        "--evidence",
        evidence_path,
        "--tracking-dir",
        state.tracking_dir or "",
        "--worktree-root",
        state.allowed_mutation_root or "",
        "--hold-seconds",
        "2",
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=state.allowed_mutation_root or None,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"adapter": "local_process", "runtime_id": f"pid:{proc.pid}", "pid": proc.pid, "exit_code": None}


def _start_roles_for_state(
    state: WarroomGoalState,
    roles: Optional[List[str]] = None,
    *,
    adapter: Optional[Any] = None,
    use_local_process: bool = True,
) -> WarroomGoalState:
    roles_to_start = roles or list(state.required_roles)
    evidence_dir = _role_spawn_dir(state)
    aggregate_path = evidence_dir / "role-spawn-evidence.json"
    state.role_spawn_evidence_path = str(aggregate_path)
    state.gates.setdefault("role_spawn", "pending")
    relevant_roles = set(roles_to_start) | set(state.required_roles)
    require_real_non_controller_runtime = any(role != "controller" for role in roles_to_start)

    missing_cards: List[str] = []
    failed_roles: List[str] = []
    for role in roles_to_start:
        role_card_path = state.role_cards.get(role) or _role_cards_for(state.tracking_dir or _default_tracking_dir()).get(role, "")
        if not role_card_path or not Path(role_card_path).exists():
            missing_cards.append(role)
            evidence_path = str(evidence_dir / f"{role}.json")
            state.role_records[role] = _annotate_role_record(
                {
                    "role": role,
                    "status": "gap",
                    "role_card_path": role_card_path,
                    "role_card_sha256": None,
                    "adapter": "gap",
                    "runtime_id": "missing-role-card",
                    "started_at": _utc_stamp(),
                    "last_seen_at": _utc_stamp(),
                    "evidence_path": evidence_path,
                    "exit_code": None,
                    "error": "missing role card",
                },
                state=state,
                role=role,
                role_card_path=role_card_path,
            )
            continue

        evidence_path = str(evidence_dir / f"{role}.json")
        if role == "controller":
            record = _role_record(
                role=role,
                status="running",
                role_card_path=role_card_path,
                adapter="controller_state",
                runtime_id=state.session_id,
                evidence_path=evidence_path,
            )
            record = _annotate_role_record(record, state=state, role=role, role_card_path=role_card_path)
            _write_json(Path(evidence_path), {"record": record, "event": "controller_state_created"})
        else:
            try:
                child_session_id: Optional[str] = None
                delegation_id: Optional[str] = None
                runtime_kind: Optional[str] = None
                current_phase: Optional[str] = None
                spawn_receipt_only: Optional[bool] = None
                role_dispatch_decision = agt_action_gateway(
                    action="warroom.role_dispatch",
                    caller="hermes_cli.warroom_goal._start_roles_for_state",
                    policies=("model_inherit_controller_default",),
                    target=role,
                    state={"controller_model": state.controller_model, "workflow": state.workflow},
                    metadata={
                        "role": role,
                        "parent_model": state.controller_model,
                        "child_model": state.controller_model,
                        "role_card_path": role_card_path,
                    },
                )
                if role_dispatch_decision.blocked:
                    raise RuntimeError(role_dispatch_decision.error_message())
                if adapter is not None:
                    result = adapter(role=role, role_card_path=role_card_path, evidence_path=evidence_path, state=state)
                    adapter_name = str(result.get("adapter") or "native_delegate")
                    child_session_id = result.get("child_session_id") or result.get("session_id")
                    delegation_id = result.get("delegation_id")
                    runtime_id = str(result.get("runtime_id") or delegation_id or child_session_id or result.get("pid") or "unknown")
                    exit_code = result.get("exit_code")
                    current_phase = str(result.get("current_phase") or result.get("phase") or "active_child_work")
                    stdout_empty = not str(result.get("stdout") or result.get("output") or "").strip()
                    json_payload = result.get("json_payload") or result.get("payload") or result.get("result")
                    structured_payload = bool(json_payload or child_session_id or delegation_id)
                    artifact = result.get("artifact") or result.get("artifact_path")
                    artifact_exists = bool(artifact and Path(str(artifact)).exists())
                    if exit_code == 0 and stdout_empty and not structured_payload and not artifact_exists:
                        raise RuntimeError("INCOMPLETE_TRANSPORT: rc=0 with empty stdout, no JSON payload, and no artifact")
                    runtime_kind = "real_child_session" if child_session_id or delegation_id else None
                    spawn_receipt_only = False if runtime_kind == "real_child_session" else None
                    actual_child_model = str(result.get("model") or "") if isinstance(result, dict) else ""
                    actual_child_provider = str(result.get("provider") or "") if isinstance(result, dict) else ""
                    if not actual_child_model:
                        raise RuntimeError("MODEL_RECORDING_GAP: role dispatch did not return actual child model")
                    actual_model_decision = agt_action_gateway(
                        action="warroom.role_dispatch",
                        caller="hermes_cli.warroom_goal._start_roles_for_state",
                        policies=("model_inherit_controller_default",),
                        target=role,
                        state={"controller_model": state.controller_model, "workflow": state.workflow},
                        metadata={
                            "role": role,
                            "parent_model": state.controller_model,
                            "child_model": actual_child_model,
                            "child_provider": actual_child_provider,
                            "delegation_id": delegation_id,
                            "child_session_id": child_session_id,
                        },
                    )
                    if actual_model_decision.blocked:
                        raise RuntimeError(actual_model_decision.error_message())
                elif use_local_process:
                    result = _spawn_local_role_process(state, role, role_card_path, evidence_path)
                    adapter_name = str(result["adapter"])
                    runtime_id = str(result["runtime_id"])
                    exit_code = result.get("exit_code")
                    runtime_kind = "spawn_receipt"
                    current_phase = "spawn_receipt_only"
                    spawn_receipt_only = True
                else:
                    raise RuntimeError("no native_delegate or local_process adapter available")
                proof_decision = agt_action_gateway(
                    action="warroom.role_execution_proof",
                    caller="hermes_cli.warroom_goal._start_roles_for_state",
                    policies=("no_receipt_only_role_start_as_execution_proof",),
                    target=role,
                    state={"workflow": state.workflow, "status": state.status},
                    metadata={
                        "role": role,
                        "runtime_kind": runtime_kind,
                        "evidence_type": runtime_kind,
                        "execution_proof": True,
                    },
                )
                if proof_decision.blocked:
                    state.gate_evidence.setdefault("receipt_only_verdict", []).append(proof_decision.error_message())
                record = _role_record(
                    role=role,
                    status="active_child_work" if runtime_kind == "real_child_session" else "spawn_receipt_only",
                    role_card_path=role_card_path,
                    adapter=adapter_name,
                    runtime_id=runtime_id,
                    evidence_path=evidence_path,
                    exit_code=exit_code,
                    child_session_id=str(child_session_id) if child_session_id else None,
                    delegation_id=str(delegation_id) if delegation_id else None,
                    runtime_kind=runtime_kind,
                    current_phase=current_phase,
                    spawn_receipt_only=spawn_receipt_only,
                )
                if isinstance(result, dict) and result.get("model"):
                    record["model"] = str(result.get("model"))
                if isinstance(result, dict) and result.get("provider"):
                    record["provider"] = str(result.get("provider"))
                if isinstance(result, dict):
                    stdout_text = str(result.get("stdout") or result.get("output") or "")
                    stderr_text = str(result.get("stderr") or "")
                    record["tracked_terminal_exit_code"] = exit_code
                    record["tracked_terminal_stdout_bytes"] = len(stdout_text.encode("utf-8", errors="replace"))
                    record["tracked_terminal_stdout_sha256"] = _sha256_text(stdout_text)
                    if stdout_text:
                        record["tracked_terminal_stdout"] = stdout_text
                    if stderr_text:
                        record["tracked_terminal_stderr"] = stderr_text
                        record["tracked_terminal_stderr_sha256"] = _sha256_text(stderr_text)
                record = _annotate_role_record(record, state=state, role=role, role_card_path=role_card_path)
                if not Path(evidence_path).exists():
                    _write_json(Path(evidence_path), {"record": record, "event": "role_spawned"})
            except Exception as exc:
                failed_roles.append(f"{role}: {exc}")
                record = _role_record(
                    role=role,
                    status="gap",
                    role_card_path=role_card_path,
                    adapter="gap",
                    runtime_id="spawn-failed",
                    evidence_path=evidence_path,
                    error=str(exc),
                )
                record = _annotate_role_record(record, state=state, role=role, role_card_path=role_card_path)
                _write_json(Path(evidence_path), {"record": record, "event": "role_spawn_failed"})
        state.role_records[role] = record
        state.roles_started[role] = record.get("status") in {"running", "spawned", "spawn_receipt_only", "active_child_work", "done"}
        state.role_spawn_attempts.append({
            "role": role,
            "status": record.get("status"),
            "adapter": record.get("adapter"),
            "runtime_id": record.get("runtime_id"),
            "evidence_path": record.get("evidence_path"),
            "at": record.get("started_at"),
        })

    if missing_cards or failed_roles:
        state.status = "gap"
        state.gates["role_cards"] = "blocked" if missing_cards else state.gates.get("role_cards", "pass")
        state.gates["role_spawn"] = "gap"
        state.gates["delegate_runtime"] = "gap"
        gap_bits = []
        if missing_cards:
            gap_bits.append("missing role card(s): " + ", ".join(missing_cards))
        if failed_roles:
            gap_bits.append("failed spawn role(s): " + ", ".join(failed_roles))
        state.role_spawn_gap = "; ".join(gap_bits)
        state.last_gap = state.role_spawn_gap
        state.required_action = "blocked_gap"
    else:
        state.gates["role_cards"] = "pass"
        adapters = {str(r.get("adapter") or "") for r in state.role_records.values()}
        real_non_controller_children = any(
            role != "controller" and (record.get("child_session_id") or record.get("delegation_id"))
            for role, record in state.role_records.items()
            if role in relevant_roles
        )
        delegate_runtime_gate = "pass"
        if not real_non_controller_children and adapters and adapters <= {"controller_state", "local_process"}:
            delegate_runtime_gate = "stub_only"
        elif not real_non_controller_children:
            delegate_runtime_gate = "gap"

        if require_real_non_controller_runtime and not real_non_controller_children:
            state.status = "gap"
            state.gates["role_spawn"] = "gap"
            state.gates["delegate_runtime"] = delegate_runtime_gate
            state.delegate_runtime_available = False
            state.gate_evidence.setdefault("delegate_runtime", []).append(REAL_DELEGATED_RUNTIME_GAP)
            state.role_spawn_gap = REAL_DELEGATED_RUNTIME_GAP
            state.last_gap = REAL_DELEGATED_RUNTIME_GAP
            state.required_action = "blocked_gap"
        else:
            state.gates["role_spawn"] = "pass"
            state.gates["delegate_runtime"] = delegate_runtime_gate
            state.delegate_runtime_available = delegate_runtime_gate == "pass"
            state.required_action = None
            state.role_spawn_gap = None
            state.last_gap = None
            if state.status == "gap":
                state.status = "active"
        state.role_spawn_adapter = "mixed" if len({r.get("adapter") for r in state.role_records.values()}) > 1 else next(iter(state.role_records.values())).get("adapter")
    _write_json(aggregate_path, {"session_id": state.session_id, "workflow": state.workflow, "records": state.role_records})
    return state


def start_warroom_roles(
    session_id: str,
    roles: Optional[List[str]] = None,
    *,
    adapter: Optional[Any] = None,
    use_local_process: bool = True,
) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    state = _start_roles_for_state(state, roles, adapter=adapter, use_local_process=use_local_process)
    save_warroom_goal(session_id, state)
    return state


def record_child_progress(
    session_id: str,
    *,
    child_session_id: Optional[str] = None,
    delegation_id: Optional[str] = None,
    runtime_id: Optional[str] = None,
    phase: Optional[str] = None,
    status: str = "active_child_work",
) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    child_session_id = str(child_session_id or "").strip() or None
    delegation_id = str(delegation_id or "").strip() or None
    runtime_id = str(runtime_id or "").strip() or None
    if not any((child_session_id, delegation_id, runtime_id)):
        return None

    matched_record: Optional[Dict[str, Any]] = None
    for record in (state.role_records or {}).values():
        if child_session_id and str(record.get("child_session_id") or "") == child_session_id:
            matched_record = record
            break
        if delegation_id and str(record.get("delegation_id") or "") == delegation_id:
            matched_record = record
            break
        if runtime_id and str(record.get("runtime_id") or "") == runtime_id:
            matched_record = record
            break
    if matched_record is None:
        return None

    now_epoch = time.time()
    matched_record["last_seen_at"] = _utc_stamp()
    matched_record["last_seen_epoch"] = now_epoch
    if child_session_id:
        matched_record["child_session_id"] = child_session_id
    if delegation_id:
        matched_record["delegation_id"] = delegation_id
    if runtime_id and not matched_record.get("runtime_id"):
        matched_record["runtime_id"] = runtime_id

    has_real_child = bool(matched_record.get("child_session_id") or matched_record.get("delegation_id"))
    if has_real_child:
        matched_record["status"] = status or matched_record.get("status") or "active_child_work"
        matched_record["runtime_kind"] = "real_child_session"
        matched_record["spawn_receipt_only"] = False
        matched_record["stale"] = False
        matched_record["stale_reason"] = None
    else:
        # A heartbeat keyed only by pid/runtime receipt is spawn proof, not
        # delegated work. It may refresh observation metadata, but it must not
        # promote the role to active_child_work/completed.
        matched_record.setdefault("status", "spawn_receipt_only")
        if matched_record.get("status") in {"active_child_work", "completed", "done"}:
            matched_record["status"] = "spawn_receipt_only"
        matched_record["runtime_kind"] = "spawn_receipt"
        matched_record["spawn_receipt_only"] = True
    matched_record["current_phase"] = phase or matched_record.get("current_phase") or matched_record["status"]
    heartbeat_path = _write_role_heartbeat(state, matched_record)
    if heartbeat_path:
        matched_record["last_heartbeat_path"] = heartbeat_path
    save_warroom_goal(session_id, state)
    return state


def start_plan_build_roles_if_ready(
    session_id: str,
    *,
    adapter: Optional[Any] = None,
    use_local_process: bool = True,
) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    if state.workflow not in WARROOM_PLAN_WORKFLOWS:
        return state
    if state.gates.get("plan") != "pass" or state.gates.get("tracking") != "pass":
        state.gates["build_role_spawn"] = "blocked"
        save_warroom_goal(session_id, state)
        return state
    for role in BUILD_ROLES:
        if role not in state.required_roles:
            state.required_roles.append(role)
            state.roles_started.setdefault(role, False)
            state.role_cards[role] = _role_cards_for(state.tracking_dir or _default_tracking_dir())[role]
    state.required_action = "spawn_roles"
    state = _start_roles_for_state(state, BUILD_ROLES, adapter=adapter, use_local_process=use_local_process)
    state.gates["build_role_spawn"] = state.gates.get("role_spawn", "pending")
    save_warroom_goal(session_id, state)
    return state


def record_role_output(
    session_id: str,
    role: str,
    *,
    evidence_path: str,
    status: str = "done",
    verdict: Optional[str] = None,
    expected_state_hash: Optional[str] = None,
    expected_state_version: Optional[int] = None,
    child_session_id: Optional[str] = None,
    delegation_id: Optional[str] = None,
    current_phase: Optional[str] = None,
) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    record: Dict[str, Any] = dict(state.role_records.get(role) or {})
    if child_session_id:
        record["child_session_id"] = child_session_id
    if delegation_id:
        record["delegation_id"] = delegation_id
    current_hash = warroom_state_hash(state)
    stale_async = False
    if expected_state_version is not None and expected_state_version != state.version:
        stale_async = True
    if expected_state_hash is not None and expected_state_hash != current_hash:
        stale_async = True
    if role != "controller" and (state.status in {"done", "halted"} or stale_async):
        decision = agt_action_gateway(
            action="async_result.accept",
            caller="hermes_cli.warroom_goal.record_role_output",
            policies=("stale_async_quarantine",),
            target=role,
            state={"status": state.status, "workflow": state.workflow},
            metadata={
                "role": role,
                "state_hash": expected_state_hash or f"role-output:{role}:late",
                "dispatch_state_hash": expected_state_hash or "role-output-before-terminal-state",
                "current_state_hash": current_hash,
            },
        )
        quarantine_path = _write_async_quarantine(
            state,
            role=role,
            evidence_path=evidence_path,
            status=status,
            current_hash=current_hash,
            expected_hash=expected_state_hash,
            expected_version=expected_state_version,
            dispatch_ts=record.get("dispatch_timestamp") or record.get("created_at") or record.get("last_seen_at"),
            target_scope=record.get("target_scope") or state.allowed_mutation_root or state.tracking_dir,
        )
        record.update({
            "role": role,
            "status": "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION",
            "current_phase": "quarantined",
            "state_class": "STALE_SUPERSEDED_BY_CURRENT_VERIFICATION",
            "quarantine_status": "quarantined",
            "quarantine_path": quarantine_path,
            "quarantined_evidence_path": evidence_path,
            "stale": True,
            "stale_reason": "state hash/version advanced before async result arrived" if stale_async else f"state already advanced to {state.status}",
            "last_seen_at": _utc_stamp(),
            "last_seen_epoch": time.time(),
        })
        state.role_records[role] = record
        state.gate_evidence.setdefault("async_stale_quarantine", []).append(
            f"{role}: stale after state={state.status}; {decision.error_message()}"
        )
        save_warroom_goal(session_id, state)
        return state
    requested_status = str(status or "").strip() or "done"
    receipt_only = bool(record.get("spawn_receipt_only")) or str(record.get("runtime_kind") or "") in {
        "spawn_receipt",
        "local_process",
    }
    has_real_runtime = bool(record.get("child_session_id") or record.get("delegation_id"))
    if role != "controller" and receipt_only and not has_real_runtime and requested_status in {"active_child_work", "completed"}:
        decision = agt_action_gateway(
            action="warroom.role_execution_proof",
            caller="hermes_cli.warroom_goal.record_role_output",
            policies=("no_receipt_only_role_start_as_execution_proof",),
            target=role,
            state={"workflow": state.workflow, "status": state.status},
            metadata={
                "role": role,
                "runtime_kind": record.get("runtime_kind") or "spawn_receipt",
                "evidence_type": record.get("runtime_kind") or "spawn_receipt",
                "execution_proof": True,
                "requested_status": requested_status,
            },
        )
        record.update({
            "role": role,
            "status": "spawn_receipt_only",
            "current_phase": "spawn_receipt_only",
            "spawn_receipt_only": True,
            "last_seen_at": _utc_stamp(),
            "evidence_path": evidence_path,
        })
        state.role_records[role] = record
        state.gate_evidence.setdefault("receipt_only_verdict", []).append(decision.error_message())
        save_warroom_goal(session_id, state)
        return state

    record.update({
        "role": role,
        "status": requested_status,
        "current_phase": current_phase or requested_status,
        "last_seen_at": _utc_stamp(),
        "last_seen_epoch": time.time(),
        "evidence_path": evidence_path,
        "state_hash": current_hash,
        "stale": False,
        "stale_reason": None,
    })
    if record.get("child_session_id") or record.get("delegation_id"):
        record["runtime_kind"] = "real_child_session"
        record["spawn_receipt_only"] = False
    state.role_records[role] = record
    if role == "guardian":
        state.guardian_verdict_path = evidence_path
        evidence_file = Path(evidence_path)
        evidence_text = evidence_file.read_text(encoding="utf-8", errors="replace") if evidence_file.exists() else ""
        verdict_pass = str(verdict or "").upper() == "PASS" and "PASS" in evidence_text.upper() and "GUARDIAN" in evidence_text.upper()
        state.guardian_pass = verdict_pass
        state.final_claim_allowed = state.guardian_pass and bool(state.proof_packet_path and Path(state.proof_packet_path).exists())
        state.gates["guardian"] = "pass" if state.guardian_pass else "blocked"
        state.final_claim_state_hash = _final_claim_state_hash(state) if state.final_claim_allowed else None
        if not state.guardian_pass:
            state.last_gap = "Guardian PASS evidence missing or invalid"
    save_warroom_goal(session_id, state)
    return state


def apply_halt_policy(session_id: str, *, reason: str, detail: str = "") -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    normalized = reason.strip().lower().replace(" ", "_").replace("/stop", "explicit_user_stop")
    if normalized in NONCRITICAL_HALT_REASONS:
        state.noncritical_pause_attempts.append({"reason": normalized, "detail": detail, "decision": "auto_continued", "at": _utc_stamp()})
        state.status = "active"
        state.gate_evidence.setdefault("halt_policy", []).append(f"auto_continued:{normalized}")
        save_warroom_goal(session_id, state)
        return state
    if normalized in ALLOWED_HALT_REASONS:
        return halt_warroom_goal(session_id, reason=normalized)
    state.status = "gap"
    state.last_gap = f"Unclassified halt reason requires Controller classification: {reason}"
    state.halt_reason = normalized
    save_warroom_goal(session_id, state)
    return state


def _path_inside(path: str, root: str) -> bool:
    try:
        p = Path(path).expanduser().resolve()
        r = Path(root).expanduser().resolve()
        return p == r or r in p.parents
    except Exception:
        return False


def _detect_remote_target(text: str) -> Optional[str]:
    lowered = (text or "").lower()
    if re.search(r"\b(remote target|target)\s*[:=]?\s*vps\b", lowered) or re.search(r"\bvps\b", lowered):
        return "vps"
    return None


def _is_protected_local_target_path(path: str) -> bool:
    try:
        resolved = str(Path(path).expanduser().resolve())
    except Exception:
        resolved = str(path or "")
    return resolved == "/etc" or resolved.startswith("/etc/") or resolved == "/opt" or resolved.startswith("/opt/") or resolved == "/root" or resolved.startswith("/root/")


def _terminal_uses_remote_ssh(command: str) -> bool:
    return "ssh vps" in command or "ssh root@srv1336035.hstgr.cloud" in command


def _remote_mutation_approved(state: WarroomGoalState) -> bool:
    evidence = _state_evidence_strings(state)
    return state.gates.get("remote_mutation_approval") == "pass" or any(
        "REMOTE_MUTATION_APPROVED" in item for item in evidence
    )


def _remote_command_touches_protected_local_path(command: str) -> bool:
    return bool(re.search(r"(?<![\w./-])/(?:etc|opt|root)(?:/|\b)", command or ""))


def _state_evidence_strings(state: WarroomGoalState) -> List[str]:
    items: List[str] = []
    for value in state.gate_evidence.values():
        if isinstance(value, list):
            items.extend(str(item) for item in value)
        elif value is not None:
            items.append(str(value))
    return items


def _evidence_contains(state: WarroomGoalState, markers: tuple[str, ...]) -> bool:
    evidence = _state_evidence_strings(state)
    return any(marker in item for item in evidence for marker in markers)


def _first_evidence_marker(state: WarroomGoalState, markers: tuple[str, ...]) -> Optional[str]:
    for item in _state_evidence_strings(state):
        for marker in markers:
            if marker in item:
                return marker
    return None


def _ponytail_available() -> bool:
    return bool(shutil.which(PONYTAIL_TOOL_NAME) or Path(PONYTAIL_TOOL_PATH).exists())


def _ponytail_proof_present(state: WarroomGoalState) -> bool:
    return _evidence_contains(state, PONYTAIL_PROOF_MARKERS)


def _ponytail_policy_decision(state: WarroomGoalState, tool_name: str, args: Dict[str, Any], mutating: bool) -> Optional[str]:
    command = str(args.get("command") or "")
    if tool_name == "terminal" and PONYTAIL_WRONG_TOOL_RE.search(command):
        decision = agt_action_gateway(
            action="ponytail.route",
            caller="hermes_cli.warroom_goal.enforce_tool_policy",
            policies=("ponytail_wrong_tool_path",),
            target=command,
            state={"workflow": state.workflow, "current_role": state.current_role},
            metadata={
                "session_id": state.session_id,
                "role": state.current_role,
                "tool_name": tool_name,
                "ponytail_wrong_tool_path": True,
                "route_hint": "Use cli-anything-ponytail-mcp through the CLI-Anything wrapper.",
                "correct_tool_path": PONYTAIL_TOOL_PATH,
                "retry_command_template": PONYTAIL_RETRY_TEMPLATE,
            },
        )
        return decision.error_message()
    if not mutating or not _ponytail_available() or _controller_tracking_doc_allowed(state, tool_name, args):
        return None
    decision = agt_action_gateway(
        action="code_mutation.ponytail_gate",
        caller="hermes_cli.warroom_goal.enforce_tool_policy",
        policies=("ponytail_required_for_code_write",),
        target=str(args.get("path") or args.get("command") or ""),
        state={"workflow": state.workflow, "current_role": state.current_role},
        metadata={
            "session_id": state.session_id,
            "role": state.current_role,
            "tool_name": tool_name,
            "code_mutation": True,
            "ponytail_available": True,
            "ponytail_proof_present": _ponytail_proof_present(state),
            "route_hint": "Record PONYTAIL_REVIEW/AUDIT/DEBT/GAIN, PONYTAIL_NOT_APPLICABLE, or PONYTAIL_GAP before code write.",
            "correct_tool_path": PONYTAIL_TOOL_PATH,
            "retry_command_template": PONYTAIL_RETRY_TEMPLATE,
        },
    )
    if decision.blocked:
        return decision.error_message()
    return None


def _git_status_paths(root: Path) -> Optional[set[str]]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    paths: set[str] = set()
    for line in proc.stdout.splitlines():
        if len(line) > 3:
            paths.add(line[3:].split(" -> ")[-1])
    return paths


def _file_snapshot(root: Path) -> set[str]:
    paths: set[str] = set()
    try:
        for path in root.rglob("*"):
            if ".git" in path.parts or not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            paths.add(f"{path.relative_to(root)}:{stat.st_size}:{int(stat.st_mtime)}")
    except Exception:
        return set()
    return paths


def _worktree_snapshot(root: Path) -> Dict[str, Any]:
    root = root.expanduser().resolve()
    git_paths = _git_status_paths(root)
    if git_paths is not None:
        return {"kind": "git", "root": str(root), "paths": sorted(git_paths)}
    return {"kind": "files", "root": str(root), "paths": sorted(_file_snapshot(root))}


def _controller_side_effect_bypass(state: WarroomGoalState) -> bool:
    return _evidence_contains(state, CONTROLLER_SIDE_EFFECT_APPROVAL_MARKERS)


def _controller_command_wrapper_tool(tool_name: str, args: Dict[str, Any]) -> bool:
    if tool_name in {"terminal", "delegate_task"}:
        return True
    return tool_name == "process" and str(args.get("action") or "") not in READ_ONLY_PROCESS_ACTIONS


def controller_side_effect_snapshot(session_id: str, tool_name: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    state = load_warroom_goal(session_id)
    if state is None or state.current_role != "controller" or not state.allowed_mutation_root:
        return None
    if not _controller_command_wrapper_tool(tool_name, args) or _controller_side_effect_bypass(state):
        return None
    try:
        root = Path(state.allowed_mutation_root).expanduser().resolve()
    except Exception:
        return None
    if not root.exists():
        return None
    snap = _worktree_snapshot(root)
    snap.update({"session_id": session_id, "tool_name": tool_name})
    return snap


def _side_effect_path_allowed(state: WarroomGoalState, root: Path, rel: str) -> bool:
    try:
        abs_path = (root / rel.split(":", 1)[0]).resolve()
    except Exception:
        abs_path = root / rel.split(":", 1)[0]
    return bool(state.tracking_dir and _path_inside(str(abs_path), state.tracking_dir)) or _parent_owned_proof_state_path(state, str(abs_path))


def controller_side_effect_check(session_id: str, snapshot: Optional[Dict[str, Any]], result: Any) -> Any:
    if not snapshot:
        return result
    state = load_warroom_goal(session_id)
    if state is None or _controller_side_effect_bypass(state):
        return result
    root = Path(str(snapshot.get("root") or "")).expanduser()
    before = set(snapshot.get("paths") or [])
    after_snapshot = _worktree_snapshot(root)
    offenders = sorted(p for p in set(after_snapshot.get("paths") or []) - before if not _side_effect_path_allowed(state, root, p))
    if not offenders:
        return result
    decision = agt_action_gateway(
        action="controller.command_wrapper.after_diff",
        caller="hermes_cli.warroom_goal.controller_side_effect_check",
        policies=("controller_side_effect_gate",),
        target=str(root),
        state={"workflow": state.workflow, "current_role": state.current_role},
        metadata={
            "session_id": state.session_id,
            "role": state.current_role,
            "controller_side_effect_detected": True,
            "changed_paths": offenders,
            "state_hash": warroom_state_hash(state),
        },
    )
    msg = f"{CONTROLLER_SIDE_EFFECT_MARKER}: {', '.join(offenders[:8])}; {decision.error_message()}"
    state.status = "gap"
    state.gates["controller_side_effect"] = "blocked"
    state.last_gap = msg
    state.final_claim_allowed = False
    state.final_claim_state_hash = None
    state.gate_evidence.setdefault("controller_side_effect", []).append(msg)
    save_warroom_goal(session_id, state)
    if isinstance(result, str):
        return result.rstrip() + "\n\n" + msg
    return {"result": result, "error": msg}


def _is_safe_local_doc_read(state: WarroomGoalState, tool_name: str, args: Dict[str, Any]) -> bool:
    if tool_name not in {"read_file", "search_files"}:
        return False
    path_text = str(args.get("path") or "")
    if not path_text:
        return False
    try:
        path = Path(path_text).expanduser().resolve()
    except Exception:
        return False
    roots = [state.tracking_dir, state.allowed_mutation_root]
    if not any(root and _path_inside(str(path), str(root)) for root in roots):
        return False
    if tool_name == "search_files":
        return True
    suffix = path.suffix.lower()
    return suffix in TRACKING_DOC_SUFFIXES or "graphify-out" in str(path)


def _is_raw_discovery_tool(tool_name: str, args: Dict[str, Any]) -> bool:
    if tool_name in {"read_file", "search_files"}:
        return True
    if tool_name == "terminal":
        command = str(args.get("command") or "")
        if _terminal_uses_remote_ssh(command):
            return False
        return bool(RAW_DISCOVERY_TERMINAL_RE.search(command))
    return False


def _robot_hand_discovery_decision(
    state: WarroomGoalState,
    tool_name: str,
    args: Dict[str, Any],
) -> Optional[str]:
    if state.workflow not in {"fast_adversary", "strict_plan_adversary", "global_plan_adversary"}:
        return None
    if not _is_raw_discovery_tool(tool_name, args) or _is_safe_local_doc_read(state, tool_name, args):
        return None
    named_gap = _first_evidence_marker(state, ROBOT_HAND_NAMED_GAPS)
    decision = agt_action_gateway(
        action="raw_discovery_fallback",
        caller="hermes_cli.warroom_goal.enforce_tool_policy",
        policies=("robot_hand_discovery_required",),
        target=str(args.get("path") or args.get("pattern") or args.get("command") or ""),
        state={"workflow": state.workflow, "current_role": state.current_role},
        metadata={
            "session_id": state.session_id,
            "role": state.current_role,
            "tool_name": tool_name,
            "raw_discovery": True,
            "robot_hand_current": _evidence_contains(state, ROBOT_HAND_CURRENT_MARKERS),
            "robot_hand_stale": _evidence_contains(state, ROBOT_HAND_STALE_MARKERS),
            "robot_hand_gap": named_gap or "",
            "attempted_path": str(args.get("path") or ""),
            "attempted_command": str(args.get("command") or ""),
        },
    )
    if decision.blocked:
        return decision.error_message()
    return None


def _codegraph_before_edit_decision(state: WarroomGoalState, tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    if state.workflow not in {"fast_adversary", "strict_plan_adversary", "global_plan_adversary"}:
        return None
    if not _tool_mutates(tool_name, args):
        return None
    decision = agt_action_gateway(
        action="code_mutation",
        caller="hermes_cli.warroom_goal.enforce_tool_policy",
        policies=("codegraph_current_before_edit",),
        target=str(args.get("path") or args.get("command") or ""),
        state={"workflow": state.workflow, "current_role": state.current_role},
        metadata={
            "session_id": state.session_id,
            "role": state.current_role,
            "tool_name": tool_name,
            "code_mutation": True,
            "codegraph_stale": _evidence_contains(state, ("CODEGRAPH_STALE", "CODEGRAPH_STALE_GAP")),
            "codegraph_current": _evidence_contains(state, ("CODEGRAPH_INDEX_CURRENT",)),
            "codegraph_synced": _evidence_contains(state, ("CODEGRAPH_SYNCED",)),
            "attempted_path": str(args.get("path") or ""),
            "attempted_command": str(args.get("command") or ""),
        },
    )
    if decision.blocked:
        return decision.error_message()
    return None


def _remote_target_local_path_block(state: WarroomGoalState, tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    if state.remote_target != "vps":
        return None
    if tool_name in {"read_file", "write_file", "patch", "search_files"}:
        path = str(args.get("path") or "")
        if path and _is_protected_local_target_path(path):
            return "WARROOM V3 blocked: remote target is vps; local /etc, /opt, and /root are not target files. Use ssh vps."
    if tool_name == "terminal":
        command = str(args.get("command") or "")
        if _terminal_uses_remote_ssh(command):
            if _terminal_mutates(args) and not _remote_mutation_approved(state):
                return "WARROOM V3 blocked: remote target vps mutation requires explicit approved mutation phase."
            return None
        if _remote_command_touches_protected_local_path(command):
            return "WARROOM V3 blocked: remote target is vps; terminal access to /etc, /opt, or /root must go through ssh vps."
    return None


def _remote_target_policy_decision(state: WarroomGoalState, tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    if state.remote_target != "vps":
        return None
    path = str(args.get("path") or "")
    command = str(args.get("command") or "")
    protected_local = bool(path and _is_protected_local_target_path(path)) or _remote_command_touches_protected_local_path(command)
    remote_mutation = tool_name == "terminal" and _terminal_uses_remote_ssh(command) and _terminal_mutates(args)
    remote_attempt = protected_local or remote_mutation or (tool_name == "terminal" and _terminal_uses_remote_ssh(command))
    if not remote_attempt:
        return None
    decision = agt_action_gateway(
        action="remote_target_access",
        caller="hermes_cli.warroom_goal.enforce_tool_policy",
        policies=("remote_target_requires_ssh", "remote_mutation_requires_approval"),
        target=path or command,
        state={"remote_target": state.remote_target, "current_role": state.current_role},
        metadata={
            "session_id": state.session_id,
            "remote_target": state.remote_target,
            "role": state.current_role,
            "tool_name": tool_name,
            "path": path,
            "command": command,
            "attempted_path": path,
            "attempted_command": command,
            "protected_local_target": protected_local,
            "remote_mutation": remote_mutation,
            "remote_mutation_approved": _remote_mutation_approved(state),
        },
    )
    if decision.blocked:
        return decision.error_message()
    return None


def _parent_owned_proof_state_path(state: WarroomGoalState, path: str) -> bool:
    if not path or not state.tracking_dir or not _path_inside(path, state.tracking_dir):
        return False
    name = Path(path).name.lower()
    return any(token in name for token in ("proof", "state", "guardian", "verdict", "role-spawn-evidence"))


def _controller_tracking_doc_allowed(state: WarroomGoalState, tool_name: str, args: Dict[str, Any]) -> bool:
    if state.current_role != "controller" or tool_name not in {"write_file", "patch"}:
        return False
    path = _path_arg(tool_name, args)
    if not path or not state.tracking_dir or not _path_inside(path, state.tracking_dir):
        return False
    return Path(path).suffix.lower() in TRACKING_DOC_SUFFIXES


def _normalize_graph_report_path(path_text: str) -> str:
    if re.match(r"^[A-Za-z]:[\\/]", path_text or ""):
        drive = path_text[0].lower()
        suffix = path_text[2:].replace("\\", "/").lstrip("/")
        return f"/mnt/{drive}/{suffix}"
    return path_text


def _extract_graph_report_path(goal_text: str) -> Optional[Path]:
    match = GRAPH_REPORT_PATH_RE.search(goal_text or "")
    if not match:
        return None
    path_text = _normalize_graph_report_path(match.group("path"))
    try:
        return Path(path_text).expanduser().resolve()
    except Exception:
        return Path(path_text).expanduser()


def _parse_graph_report_header(report_path: Path) -> tuple[Optional[str], Optional[str]]:
    try:
        with report_path.open("r", encoding="utf-8", errors="replace") as fh:
            header = fh.readline().strip()
    except Exception:
        return None, None
    match = GRAPH_REPORT_HEADER_RE.match(header)
    if not match:
        return None, None
    return match.group("root").strip(), match.group("stamp")


def _graphify_alternatives(repo_root: Path, *, preferred_report: Optional[Path] = None) -> List[str]:
    alternatives: List[str] = []
    local_report = _graphify_generated_report_path(repo_root)
    if local_report.exists() and (preferred_report is None or local_report != preferred_report):
        alternatives.append(f"GRAPH_ALTERNATE_PATH:{local_report}")
    for tool_name in ("mcp2cli", "graphify", "cli-anything-jcodemunch-mcp", "cli-anything-smart-read-mcp"):
        if shutil.which(tool_name):
            alternatives.append(f"GRAPH_ALTERNATE_DISCOVERY:{tool_name}")
            break
    return alternatives


def _graphify_generated_report_path(root: Path) -> Path:
    try:
        return (root / "graphify-out" / "GRAPH_REPORT.md").resolve()
    except Exception:
        return root / "graphify-out" / "GRAPH_REPORT.md"


def _graphify_refresh_command(refresh_root: Path) -> Optional[List[str]]:
    safe_script = refresh_root / "scripts" / "graphify-update-safe.py"
    if safe_script.exists():
        return [sys.executable, str(safe_script)]
    graphify_bin = shutil.which("graphify")
    if graphify_bin:
        return [graphify_bin, "update"]
    return None


def _graphify_covers_target(corpus_root: Optional[str], *, repo_root: Path, allowed_path: Path) -> bool:
    return bool(corpus_root) and (
        _path_inside(str(repo_root), str(corpus_root)) or _path_inside(str(allowed_path), str(corpus_root))
    )


def _graphify_refresh_root(corpus_root: Optional[str], *, fallback_root: Path) -> Path:
    if not corpus_root:
        return fallback_root
    try:
        return Path(corpus_root).expanduser().resolve()
    except Exception:
        return Path(corpus_root).expanduser()


def _is_generated_graphify_output(report_path: Path, refresh_root: Path) -> bool:
    try:
        return report_path.resolve() == _graphify_generated_report_path(refresh_root)
    except Exception:
        return report_path == refresh_root / "graphify-out" / "GRAPH_REPORT.md"


def _graphify_refresh_block_reason(goal_text: str, *, report_path: Path, refresh_root: Path) -> Optional[str]:
    normalized = (goal_text or "").lower()
    if (
        "no-index" in normalized
        or "no index" in normalized
        or "no indexing" in normalized
        or "no-mutation" in normalized
        or "no mutation" in normalized
        or "do not mutate" in normalized
    ):
        return "GRAPH_REFRESH_EXCEPTION:explicit_no_index_no_mutation_boundary"
    if not _is_generated_graphify_output(report_path, refresh_root):
        return "GRAPH_REFRESH_EXCEPTION:destructive_delete_uninit_risk_non_generated_output"
    sensitive_parts = {"secret", "secrets", "credential", "credentials", "vault", ".ssh", ".aws"}
    if any(part.lower() in sensitive_parts for part in report_path.parts):
        return "GRAPH_REFRESH_EXCEPTION:secrets_credentials_risk"
    if _graphify_refresh_command(refresh_root) is None:
        return "GRAPH_REFRESH_EXCEPTION:no_safe_refresh_path"
    return None


def _refresh_graphify_report(refresh_root: Path, report_path: Path) -> tuple[bool, List[str]]:
    command = _graphify_refresh_command(refresh_root)
    if not command:
        return False, ["GRAPH_REFRESH_EXCEPTION:no_safe_refresh_path"]
    try:
        proc = subprocess.run(
            command,
            cwd=str(refresh_root),
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
    except Exception as exc:
        return False, [f"GRAPH_REFRESH_EXCEPTION:refresh_failed:{exc}"]
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"rc={proc.returncode}"
        return False, [f"GRAPH_REFRESH_EXCEPTION:refresh_failed:{tail}"]
    if not report_path.exists():
        return False, ["GRAPH_REFRESH_EXCEPTION:refresh_missing_output"]
    return True, [f"GRAPH_REFRESHED:{report_path}", f"GRAPH_REFRESH_COMMAND:{' '.join(command)}"]


def _evaluate_graphify_gate(goal_text: str, *, allowed_root: str, now: Optional[float] = None) -> Dict[str, Any]:
    current = time.time() if now is None else now
    allowed_path = Path(allowed_root or Path.cwd()).expanduser().resolve()
    repo_root = _repo_root_for(allowed_path) or allowed_path
    preferred_report = _extract_graph_report_path(goal_text)
    local_report = _graphify_generated_report_path(repo_root)
    candidates: List[Path] = []
    for candidate in (preferred_report, local_report):
        if candidate is None:
            continue
        if all(existing != candidate for existing in candidates):
            candidates.append(candidate)

    evidence: List[str] = []
    selected_report: Optional[Path] = None
    selected_corpus: Optional[str] = None
    saw_wrong_corpus = False
    for candidate in candidates:
        if not candidate.exists():
            continue
        corpus_root, _stamp = _parse_graph_report_header(candidate)
        covers_repo = _graphify_covers_target(corpus_root, repo_root=repo_root, allowed_path=allowed_path)
        if covers_repo:
            selected_report = candidate
            selected_corpus = corpus_root
            if preferred_report is not None and candidate != preferred_report:
                evidence.append(f"GRAPH_ALTERNATE_PATH:{candidate}")
            break
        if corpus_root:
            saw_wrong_corpus = True
            evidence.append(f"GRAPH_NOT_APPLICABLE:{candidate} corpus={corpus_root} repo={repo_root}")
        else:
            evidence.append(f"GRAPH_REPORT_HEADER_UNPARSEABLE:{candidate}")

    if selected_report is None:
        alternatives = _graphify_alternatives(repo_root, preferred_report=preferred_report)
        if saw_wrong_corpus:
            if alternatives:
                return {"gate": "pass", "status": "active", "evidence": evidence + alternatives}
            gap = "GRAPH_REFRESH_EXCEPTION:wrong_corpus_no_alternate"
            return {
                "gate": "gap",
                "status": "gap",
                "evidence": evidence + [gap],
                "last_gap": gap,
                "required_action": "blocked_gap",
            }
        if alternatives:
            return {"gate": "pass", "status": "active", "evidence": evidence + alternatives}
        gap = "GRAPH_REFRESH_EXCEPTION:no_report_no_alternate"
        return {
            "gate": "gap",
            "status": "gap",
            "evidence": evidence + [gap],
            "last_gap": gap,
            "required_action": "blocked_gap",
        }

    age_seconds = max(0, int(current - selected_report.stat().st_mtime))
    evidence.extend(
        [
            f"GRAPH_REPORT_PATH:{selected_report}",
            f"GRAPH_REPORT_CORPUS:{selected_corpus or 'unknown'}",
            f"GRAPH_REPORT_AGE_SECONDS:{age_seconds}",
        ]
    )
    if age_seconds <= GRAPHIFY_STALE_AFTER_SECONDS:
        evidence.append("GRAPH_REPORT_FRESH")
        return {"gate": "pass", "status": "active", "evidence": evidence}

    refresh_root = _graphify_refresh_root(selected_corpus, fallback_root=repo_root)
    evidence.append(f"GRAPH_REFRESH_ROOT:{refresh_root}")

    block_reason = _graphify_refresh_block_reason(goal_text, report_path=selected_report, refresh_root=refresh_root)
    if block_reason:
        return {
            "gate": "blocked",
            "status": "blocked",
            "evidence": evidence + [block_reason],
            "last_gap": block_reason,
            "required_action": "blocked_gap",
        }

    refreshed, refresh_evidence = _refresh_graphify_report(refresh_root, selected_report)
    evidence.extend(refresh_evidence)
    if not refreshed:
        gap = refresh_evidence[-1] if refresh_evidence else "GRAPH_REFRESH_EXCEPTION:refresh_failed"
        return {
            "gate": "gap",
            "status": "gap",
            "evidence": evidence,
            "last_gap": gap,
            "required_action": "blocked_gap",
        }

    if not selected_report.exists():
        gap = "GRAPH_REFRESH_EXCEPTION:refresh_missing_output"
        return {
            "gate": "gap",
            "status": "gap",
            "evidence": evidence + [gap],
            "last_gap": gap,
            "required_action": "blocked_gap",
        }

    refreshed_corpus, _refreshed_stamp = _parse_graph_report_header(selected_report)
    if not refreshed_corpus:
        gap = "GRAPH_REFRESH_EXCEPTION:refresh_output_header_unparseable"
        return {
            "gate": "gap",
            "status": "gap",
            "evidence": evidence + [gap],
            "last_gap": gap,
            "required_action": "blocked_gap",
        }
    if not _graphify_covers_target(refreshed_corpus, repo_root=repo_root, allowed_path=allowed_path):
        gap = "GRAPH_REFRESH_EXCEPTION:refresh_output_wrong_corpus"
        return {
            "gate": "gap",
            "status": "gap",
            "evidence": evidence + [gap],
            "last_gap": gap,
            "required_action": "blocked_gap",
        }

    refreshed_age = max(0, int(time.time() - selected_report.stat().st_mtime))
    evidence.append(f"GRAPH_REPORT_AGE_SECONDS:{refreshed_age}")
    if refreshed_age > GRAPHIFY_STALE_AFTER_SECONDS:
        gap = "GRAPH_REFRESH_EXCEPTION:refresh_output_still_stale"
        return {
            "gate": "gap",
            "status": "gap",
            "evidence": evidence + [gap],
            "last_gap": gap,
            "required_action": "blocked_gap",
        }
    return {"gate": "pass", "status": "active", "evidence": evidence}


def create_warroom_goal(
    session_id: str,
    arg: str,
    *,
    tracking_dir: Optional[str] = None,
    allowed_mutation_root: Optional[str] = None,
    parent_agent: Optional[Any] = None,
) -> WarroomGoalState:
    detection = detect_warroom_goal(arg)
    if detection is None:
        raise ValueError("not a Warroom /goal trigger")
    # Global /goal supersedes the legacy GoalManager loop. Clear any standing
    # GoalManager row for this session so old turn budgets/post-turn judges
    # cannot keep running beside Warroom state.
    try:
        from hermes_cli.goals import clear_goal as _clear_legacy_goal
        _clear_legacy_goal(session_id)
    except Exception:
        pass
    now = time.time()
    tracking = tracking_dir or _default_tracking_dir()
    allowed_root = allowed_mutation_root or os.getenv("TERMINAL_CWD") or str(Path.cwd())
    controller_model = str(getattr(parent_agent, "model", "") or "") or None
    remote_target = _detect_remote_target(detection.body)
    graphify_gate = _evaluate_graphify_gate(detection.body, allowed_root=allowed_root, now=now)
    roles = list(FAST_ROLES if detection.workflow == "fast_adversary" else STRICT_ROLES)

    cards = _role_cards_for(tracking)
    role_cards_ok = all(Path(cards[role]).exists() for role in roles)
    gates = {
        "graphify": graphify_gate.get("gate", "pending"),
        "plan": "pass" if detection.workflow == "fast_adversary" else "pending",
        "tracking": "pass" if Path(tracking).exists() else "blocked",
        "role_cards": "pass" if role_cards_ok else "blocked",
        "controller_active": "pass",
        "delegate_runtime": "pending",
        "role_spawn": "pending",
        "proof_packet": "pending",
        "e2e_claim": "pending",
    }
    status = "active"
    last_gap = None
    required_action = "spawn_roles"
    if detection.missing_sections:
        status = "blocked"
        gates["plan"] = "blocked"
        gates["role_spawn"] = "blocked"
        last_gap = "Missing required strict sections: " + ", ".join(detection.missing_sections)
        required_action = None
    elif graphify_gate.get("status") in {"blocked", "gap"}:
        status = str(graphify_gate.get("status"))
        gates["role_spawn"] = "blocked" if status == "blocked" else "gap"
        last_gap = graphify_gate.get("last_gap") or last_gap
        required_action = graphify_gate.get("required_action") or "blocked_gap"
    elif not role_cards_ok:
        status = "blocked"
        last_gap = "Missing required role card(s)"
    state = WarroomGoalState(
        workflow=detection.workflow,
        status=status,
        original_goal=detection.body,
        trigger=detection.trigger,
        session_id=session_id,
        created_at=now,
        updated_at=now,
        controller_active=True,
        controller_model=controller_model,
        remote_target=remote_target,
        current_role="controller",
        required_roles=roles,
        required_action=required_action,
        roles_started={role: role == "controller" for role in roles},
        role_cards={role: cards[role] for role in roles},
        gates=gates,
        gate_evidence={
            "controller_active": ["runtime created Warroom state"],
            "graphify": list(graphify_gate.get("evidence") or []),
        },
        tracking_dir=tracking,
        allowed_mutation_root=allowed_root,
        denied_mutation_roots=_default_denied_roots(),
        delegate_runtime_checked=True,
        delegate_runtime_available=False,
        last_gap=last_gap,
        final_claim_allowed=False,
    )
    if state.status == "active":
        role_adapter = _native_background_delegate_adapter(parent_agent) if parent_agent is not None else None
        state = _start_roles_for_state(state, adapter=role_adapter, use_local_process=parent_agent is None)
    save_warroom_goal(session_id, state)
    return state


def controller_kickoff_prompt(state: WarroomGoalState) -> str:
    roles = ", ".join(state.required_roles)
    gate_line = "BLOCKED" if state.status in {"blocked", "gap"} else "ACTIVE"
    gap = f"\nGAP: {state.last_gap}" if state.last_gap else ""
    return (
        "[WARROOM V3 CONTROLLER]\n"
        f"Workflow: {state.workflow}\n"
        f"Status: {gate_line}\n"
        f"Required roles: {roles}\n"
        "Controller owns orchestration. Builder is the only mutation role. "
        "Reviewers/adversaries return findings only. Do not claim done without proof packet.\n"
        f"Goal:\n{state.original_goal}"
        f"{gap}"
    )


def notice_for_state(state: WarroomGoalState) -> str:
    if state.status in {"blocked", "gap"} and state.last_gap:
        return (
            f"WARROOM V3 {state.workflow} enforced state created.\n"
            f"Status: {state.status}. Controller active.\n"
            f"{runtime_drift_line()}\n"
            f"GAP: {state.last_gap}"
        )
    return (
        f"WARROOM V3 {state.workflow} enforced state created.\n"
        f"Status: {state.status}. Controller active.\n"
        f"{runtime_drift_line()}\n"
        "Required roles are spawned with persisted evidence or workflow blocks with explicit GAP."
    )


def copy_warroom_goal(old_session_id: str, new_session_id: str, *, reason: str = "session-split") -> Optional[WarroomGoalState]:
    state = load_warroom_goal(old_session_id)
    if state is None:
        return None
    existing_child = load_warroom_goal(new_session_id)
    if existing_child is not None and existing_child.updated_at >= state.updated_at:
        existing_child.gate_evidence.setdefault("session_migration", []).append(
            f"{reason}: kept newer child state; parent not copied over child"
        )
        save_warroom_goal(new_session_id, existing_child)
        return existing_child
    state.parent_session_id = old_session_id
    state.session_id = new_session_id
    state.gate_evidence.setdefault("session_migration", []).append(reason)
    save_warroom_goal(new_session_id, state)
    return state


def halt_warroom_goal(session_id: str, *, reason: str) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    state.status = "halted"
    state.halt_reason = reason
    cleanup_gaps: List[str] = []
    for role, record in state.role_records.items():
        if record.get("status") in {"running", "spawned"}:
            runtime_id = str(record.get("runtime_id") or "")
            if runtime_id.startswith("pid:"):
                try:
                    os.kill(int(runtime_id.split(":", 1)[1]), 15)
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    cleanup_gaps.append(f"{role}:{exc}")
            record["status"] = "halted"
            record["last_seen_at"] = _utc_stamp()
    if cleanup_gaps:
        state.cleanup_gap = "; ".join(cleanup_gaps)
        state.gate_evidence.setdefault("role_cleanup", []).append("cleanup_gap:" + state.cleanup_gap)
    else:
        state.gate_evidence.setdefault("role_cleanup", []).append("halted_or_already_exited")
    save_warroom_goal(session_id, state)
    return state


def resume_warroom_goal(session_id: str) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    if state.status == "halted":
        state.status = "active"
        state.halt_reason = None
        save_warroom_goal(session_id, state)
    return state


def _path_arg(tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    if tool_name in {"write_file", "patch"}:
        return str(args.get("path") or "") or None
    if tool_name == "skill_manage":
        return "/home/alcoo/.hermes/skills"
    return None


def _parser_block_reason(state: WarroomGoalState) -> Optional[str]:
    if state.status == "blocked" and state.last_gap and state.last_gap.startswith("Missing required strict sections: "):
        return state.last_gap
    return None


def _terminal_mutates(args: Dict[str, Any]) -> bool:
    cmd = str(args.get("command") or "")
    sanitized = SAFE_TERMINAL_REDIRECT_RE.sub(" ", cmd)
    return bool(
        DESTRUCTIVE_TERMINAL_RE.search(sanitized)
        or ADMIN_MUTATING_TERMINAL_RE.search(sanitized)
        or FILE_TERMINAL_REDIRECT_RE.search(sanitized)
    )


def _execute_code_mutates(args: Dict[str, Any]) -> bool:
    code = str(args.get("code") or "")
    return bool(EXECUTE_CODE_WRITE_RE.search(code))


def _tool_mutates(tool_name: str, args: Dict[str, Any]) -> bool:
    if tool_name == "terminal":
        return _terminal_mutates(args)
    if tool_name in {"execute_code", "delegate_task"}:
        return True
    if tool_name == "process":
        return str(args.get("action") or "") not in READ_ONLY_PROCESS_ACTIONS
    return tool_name in MUTATING_TOOLS


def _read_only_recovery_tool_allowed(tool_name: str, args: Dict[str, Any]) -> bool:
    if tool_name in READ_ONLY_RECOVERY_TOOLS:
        return True
    if tool_name == "terminal":
        return not _terminal_mutates(args)
    if tool_name == "process":
        return str(args.get("action") or "") in READ_ONLY_PROCESS_ACTIONS
    return False


def _plan_build_roles_missing(state: WarroomGoalState) -> bool:
    if state.workflow not in WARROOM_PLAN_WORKFLOWS:
        return False
    return any(role not in state.role_records for role in BUILD_ROLES)


def _auto_start_build_roles_if_ready(session_id: str, state: WarroomGoalState) -> WarroomGoalState:
    if (
        state.workflow in WARROOM_PLAN_WORKFLOWS
        and state.gates.get("plan") == "pass"
        and state.gates.get("tracking") == "pass"
        and _plan_build_roles_missing(state)
    ):
        started = start_plan_build_roles_if_ready(session_id)
        if started is not None:
            return started
    return state


def _record_noncritical_halt_text(session_id: str, response: str) -> Optional[WarroomGoalState]:
    for reason, pattern in NONCRITICAL_HALT_TEXT_PATTERNS:
        if pattern.search(response or ""):
            return apply_halt_policy(session_id, reason=reason, detail="final_response_text")
    return None


def enforce_tool_policy(session_id: str, tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    state = load_warroom_goal(session_id)
    if state is None or state.status == "done":
        return None
    if state.status in {"halted", "gap"}:
        if _read_only_recovery_tool_allowed(tool_name, args):
            return None
        if _tool_mutates(tool_name, args) and state.current_role not in {"builder", "controller", None}:
            agt_action_gateway(
                action="code_mutation",
                caller="hermes_cli.warroom_goal.enforce_tool_policy",
                policies=("builder_only_code_mutation",),
                target=str(args.get("path") or args.get("command") or ""),
                state={"current_role": state.current_role, "status": state.status},
                metadata={"role": state.current_role, "code_mutation": True, "tool_name": tool_name},
            )
            return f"WARROOM V3 blocked: role {state.current_role or 'none'} cannot mutate code. Builder is the only mutation role."
        return f"WARROOM V3 blocked: workflow is {state.status} ({state.halt_reason or state.last_gap or 'no reason recorded'})."
    parser_block_reason = _parser_block_reason(state)
    if parser_block_reason:
        if _tool_mutates(tool_name, args):
            return f"WARROOM V3 blocked: {parser_block_reason}"
        return None
    state = _auto_start_build_roles_if_ready(session_id, state)
    if state.status in {"halted", "gap"}:
        if _read_only_recovery_tool_allowed(tool_name, args):
            return None
        if _tool_mutates(tool_name, args) and state.current_role not in {"builder", "controller", None}:
            agt_action_gateway(
                action="code_mutation",
                caller="hermes_cli.warroom_goal.enforce_tool_policy",
                policies=("builder_only_code_mutation",),
                target=str(args.get("path") or args.get("command") or ""),
                state={"current_role": state.current_role, "status": state.status},
                metadata={"role": state.current_role, "code_mutation": True, "tool_name": tool_name},
            )
            return f"WARROOM V3 blocked: role {state.current_role or 'none'} cannot mutate code. Builder is the only mutation role."
        return f"WARROOM V3 blocked: workflow is {state.status} ({state.halt_reason or state.last_gap or 'no reason recorded'})."
    if state.required_action == "spawn_roles":
        return "WARROOM V3 blocked: required role spawn action is pending; normal chat/tool fallback denied."

    remote_policy = _remote_target_policy_decision(state, tool_name, args)
    if remote_policy:
        return remote_policy
    remote_block = _remote_target_local_path_block(state, tool_name, args)
    if remote_block:
        return remote_block

    mutating = _tool_mutates(tool_name, args)
    ponytail_block = _ponytail_policy_decision(state, tool_name, args, mutating)
    if ponytail_block:
        return ponytail_block
    if mutating and state.current_role not in {"builder", "controller", None}:
        return f"WARROOM V3 blocked: role {state.current_role or 'none'} cannot mutate code. Builder is the only mutation role."

    robot_hand_block = _robot_hand_discovery_decision(state, tool_name, args)
    if robot_hand_block:
        return robot_hand_block

    if mutating:
        codegraph_block = _codegraph_before_edit_decision(state, tool_name, args)
        if codegraph_block:
            return codegraph_block
    # Terminal can be read-only proof work for Controller. Only mutating shell
    # commands are builder-only; execute_code remains mutation-capable because
    # arbitrary Python is too broad for role-policy proof.
    if tool_name == "delegate_task":
        if state.current_role not in {"controller", None}:
            return f"WARROOM V3 blocked: role {state.current_role} cannot spawn delegate_task. Controller owns orchestration."
        if state.gates.get("role_spawn") != "pass":
            state.status = "gap"
            state.gates["role_spawn"] = "gap"
            state.gates["delegate_runtime"] = "gap"
            state.role_spawn_gap = state.role_spawn_gap or REAL_DELEGATED_RUNTIME_GAP
            state.last_gap = state.role_spawn_gap
            state.required_action = "blocked_gap"
            save_warroom_goal(session_id, state)
            return f"WARROOM V3 GAP: {state.last_gap}"
        return None

    if not mutating:
        return None

    if _controller_tracking_doc_allowed(state, tool_name, args):
        return None

    if state.current_role != "builder":
        return f"WARROOM V3 blocked: role {state.current_role or 'none'} cannot mutate code. Builder is the only mutation role."
    if state.gates.get("tracking") != "pass":
        return "WARROOM V3 blocked: tracking gate is not PASS."
    if state.workflow in WARROOM_PLAN_WORKFLOWS and state.gates.get("plan") != "pass":
        return "WARROOM V3 blocked: plan gate is not PASS for workflow."

    if tool_name == "terminal":
        workdir = str(args.get("workdir") or state.allowed_mutation_root or "")
        if state.allowed_mutation_root and not _path_inside(workdir, state.allowed_mutation_root):
            return f"WARROOM V3 blocked: terminal workdir outside allowed worktree root {state.allowed_mutation_root}."
    if tool_name == "execute_code":
        return "WARROOM V3 blocked: execute_code is not allowed during Warroom hardwire; use file/patch tools under Builder policy."

    path = _path_arg(tool_name, args)
    if path and _parent_owned_proof_state_path(state, path) and state.current_role != "controller":
        agt_action_gateway(
            action="proof_state.write",
            caller="hermes_cli.warroom_goal.enforce_tool_policy",
            policies=("parent_owned_proof_write",),
            target=path,
            state={"current_role": state.current_role, "tracking_dir": state.tracking_dir},
            metadata={"role": state.current_role, "proof_or_state_write": True, "tool_name": tool_name},
        )
        return "WARROOM V3 blocked: final proof/state writes are controller-owned; child roles may return evidence only."
    if path:
        for root in state.denied_mutation_roots:
            if _path_inside(path, root):
                return f"WARROOM V3 blocked: denied mutation root {root}."
        if state.allowed_mutation_root and not _path_inside(path, state.allowed_mutation_root):
            return f"WARROOM V3 blocked: mutation path outside allowed worktree root {state.allowed_mutation_root}."
    return None


def _has_final_completion_claim(response: str) -> bool:
    for match in FINAL_CLAIM_RE.finditer(response):
        start = max(0, match.start() - 48)
        end = min(len(response), match.end() + 48)
        window = response[start:end]
        after = response[match.end(): match.end() + 24].strip().lower()
        before = response[max(0, match.start() - 24):match.start()].lower()
        # "complete log/report/list" describes an artifact, not a completion claim.
        # "phase complete" / "milestone complete" is a noncritical boundary,
        # not final done.
        if match.group(0).lower().startswith("complete") and (
            after.startswith(("log", "report", "list", "trace", "error"))
            or "phase" in before
            or "milestone" in before
        ):
            continue
        if NEGATED_CLAIM_RE.search(window):
            continue
        return True
    return False


def goal_completion_output(state: WarroomGoalState, response: str) -> str:
    """Canonical user-facing completion output for an unlocked Warroom /goal.

    This is the output-wire hardwire: after proof packet + Guardian PASS unlock
    final claims, every surface gets an explicit GOAL COMPLETED line instead of
    an ambiguous model/handler response.
    """
    role_evidence = state.role_spawn_evidence_path or "GAP: missing role evidence path"
    guardian = state.role_records.get("guardian", {}) if state.role_records else {}
    guardian_evidence = guardian.get("evidence_path") or "GAP: missing Guardian evidence path"
    return (
        "GOAL COMPLETED\n"
        f"Workflow: {state.workflow}\n"
        f"Status: done\n"
        f"Proof packet: {state.proof_packet_path}\n"
        f"Role spawn evidence: {role_evidence}\n"
        f"Guardian verdict: PASS\n"
        f"Guardian evidence: {guardian_evidence}\n"
        "Normal chat fallback: NO\n"
        "Original final response:\n"
        f"{response}"
    )


def guard_final_response(session_id: str, response: str, *, closure: bool = False) -> str:
    state = load_warroom_goal(session_id)
    if state is None or not response:
        return response
    if not closure:
        return response
    noncritical_state = _record_noncritical_halt_text(session_id, response)
    if noncritical_state is not None:
        state = noncritical_state
        response = (
            response.rstrip()
            + f"\n\nWARROOM V3 auto_continued:{state.noncritical_pause_attempts[-1]['reason']} — non-mission-critical stop denied."
        )
    has_final_claim = _has_final_completion_claim(response)
    if state.required_action == "spawn_roles" and has_final_claim:
        return "WARROOM V3 FINAL BLOCKED: required role spawn action is pending. GAP: normal chat fallback denied until roles spawn or explicit GAP is recorded."
    if has_final_claim:
        proof = state.proof_packet_path
        proof_exists = bool(proof and Path(proof).exists())
        current_state_hash = _final_claim_state_hash(state)
        state_hash_matches = bool(state.final_claim_state_hash and state.final_claim_state_hash == current_state_hash)
        final_decision = agt_action_gateway(
            action="final_completion_claim",
            caller="hermes_cli.warroom_goal.guard_final_response",
            policies=("proof.required_for_done", "no_child_self_report_as_proof"),
            target=session_id,
            state={"status": state.status, "workflow": state.workflow},
            metadata={
                "final_completion_claim": True,
                "proof_packet_exists": proof_exists,
                "guardian_pass": bool(state.final_claim_allowed),
                "current_state_hash": current_state_hash,
                "final_claim_state_hash": state.final_claim_state_hash,
                "current_state_hash_matches": state_hash_matches,
                "child_self_report": False,
            },
        )
        if final_decision.blocked:
            return (
                "WARROOM V3 FINAL BLOCKED: final done/fixed/complete claim requires proof packet "
                "Guardian PASS, and current state hash match.\nGAP: proof packet/final_claim_allowed/state hash missing or stale."
            )
        if HEALTH_ONLY_RE.search(response) and not E2E_EVIDENCE_RE.search(response):
            return "WARROOM V3 FINAL BLOCKED: health checks alone do not prove E2E."
        state.status = "done"
        state.gates["e2e_claim"] = "pass"
        state.gates["proof_packet"] = "pass"
        state.gate_evidence.setdefault("completion_output", []).append("GOAL COMPLETED emitted")
        save_warroom_goal(session_id, state)
        return goal_completion_output(state, response)
    return response


def status_line_for_session(session_id: str) -> Optional[str]:
    state = load_warroom_goal(session_id)
    return state.status_line() if state else None
