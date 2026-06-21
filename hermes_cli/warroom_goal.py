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
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

FAST_TRIGGER = "Use adversary skill for:"
STRICT_TRIGGER = "Use plan adversary skill for:"
GLOBAL_TRIGGER = "Global slash /goal:"
STATE_VERSION = 3
WARROOM_PLAN_WORKFLOWS = {"strict_plan_adversary", "global_plan_adversary"}

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

REQUIRED_SECTIONS = ("Acceptance:", "Constraints:", "Verify with:")
MUTATING_TOOLS = {"write_file", "patch", "skill_manage"}
FINAL_CLAIM_RE = re.compile(r"\b(done|fixed|complete|completed|shipped|hardwired)\b", re.I)
NEGATED_CLAIM_RE = re.compile(r"\b(not|no|isn[’\']t|is not|still|remain(?:s|ing)?|open|failed|blocked|gap)\b", re.I)
E2E_CLAIM_RE = re.compile(r"\be2e\b|end[- ]to[- ]end", re.I)
HEALTH_ONLY_RE = re.compile(r"health check|/health|status endpoint", re.I)
E2E_EVIDENCE_RE = re.compile(r"pytest|playwright|browser|selenium|end[- ]to[- ]end test|e2e test", re.I)
DESTRUCTIVE_TERMINAL_RE = re.compile(
    r"\b(rm\s+-|mv\s+|cp\s+|chmod\s+|chown\s+|git\s+(?:reset|clean|checkout)\b|python\b.*\bwrite\(|tee\s+|>\s*\S)",
    re.I,
)
EXECUTE_CODE_WRITE_RE = re.compile(r"\b(open\(.+['\"]w|write_text\(|write_bytes\(|shutil\.rmtree|os\.remove|Path\(.+\)\.unlink)", re.I)
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

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "WarroomGoalState":
        data = json.loads(raw)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def status_line(self) -> str:
        return f"WARROOM V3 {self.workflow}: {self.status} (role={self.current_role or 'none'})"


_DB_CACHE: Dict[str, Any] = {}


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
        missing = [section.rstrip(":") for section in REQUIRED_SECTIONS if section not in body]
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
    try:
        db.set_meta(_meta_key(session_id), state.to_json())
    except Exception:
        pass


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
) -> Dict[str, Any]:
    now = _utc_stamp()
    record: Dict[str, Any] = {
        "role": role,
        "status": status,
        "role_card_path": role_card_path,
        "role_card_sha256": _sha256_file(role_card_path) if Path(role_card_path).exists() else None,
        "adapter": adapter,
        "runtime_id": runtime_id,
        "started_at": now,
        "last_seen_at": now,
        "evidence_path": evidence_path,
        "exit_code": exit_code,
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

    missing_cards: List[str] = []
    failed_roles: List[str] = []
    for role in roles_to_start:
        role_card_path = state.role_cards.get(role) or _role_cards_for(state.tracking_dir or _default_tracking_dir()).get(role, "")
        if not role_card_path or not Path(role_card_path).exists():
            missing_cards.append(role)
            evidence_path = str(evidence_dir / f"{role}.json")
            state.role_records[role] = {
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
            }
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
            _write_json(Path(evidence_path), {"record": record, "event": "controller_state_created"})
        else:
            try:
                if adapter is not None:
                    result = adapter(role=role, role_card_path=role_card_path, evidence_path=evidence_path, state=state)
                    adapter_name = str(result.get("adapter") or "native_delegate")
                    runtime_id = str(result.get("runtime_id") or result.get("delegation_id") or result.get("session_id") or result.get("pid") or "unknown")
                    exit_code = result.get("exit_code")
                elif use_local_process:
                    result = _spawn_local_role_process(state, role, role_card_path, evidence_path)
                    adapter_name = str(result["adapter"])
                    runtime_id = str(result["runtime_id"])
                    exit_code = result.get("exit_code")
                else:
                    raise RuntimeError("no native_delegate or local_process adapter available")
                record = _role_record(
                    role=role,
                    status="spawned",
                    role_card_path=role_card_path,
                    adapter=adapter_name,
                    runtime_id=runtime_id,
                    evidence_path=evidence_path,
                    exit_code=exit_code,
                )
                if not Path(evidence_path).exists():
                    _write_json(Path(evidence_path), {"record": record, "event": "role_spawned"})
            except Exception as exc:
                failed_roles.append(role)
                record = _role_record(
                    role=role,
                    status="gap",
                    role_card_path=role_card_path,
                    adapter="gap",
                    runtime_id="spawn-failed",
                    evidence_path=evidence_path,
                    error=str(exc),
                )
                _write_json(Path(evidence_path), {"record": record, "event": "role_spawn_failed"})
        state.role_records[role] = record
        state.roles_started[role] = record.get("status") in {"running", "spawned", "done"}
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
        state.gates["role_spawn"] = "pass"
        state.gates["delegate_runtime"] = "pass"
        state.delegate_runtime_available = True
        state.role_spawn_adapter = "mixed" if len({r.get("adapter") for r in state.role_records.values()}) > 1 else next(iter(state.role_records.values())).get("adapter")
        state.required_action = None
        state.role_spawn_gap = None
        if state.status == "gap" and not state.last_gap:
            state.status = "active"
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
) -> Optional[WarroomGoalState]:
    state = load_warroom_goal(session_id)
    if state is None:
        return None
    record = dict(state.role_records.get(role) or {})
    record.update({"role": role, "status": status, "last_seen_at": _utc_stamp(), "evidence_path": evidence_path})
    state.role_records[role] = record
    if role == "guardian":
        state.guardian_verdict_path = evidence_path
        evidence_file = Path(evidence_path)
        evidence_text = evidence_file.read_text(encoding="utf-8", errors="replace") if evidence_file.exists() else ""
        verdict_pass = str(verdict or "").upper() == "PASS" and "PASS" in evidence_text.upper() and "GUARDIAN" in evidence_text.upper()
        state.guardian_pass = verdict_pass
        state.final_claim_allowed = state.guardian_pass and bool(state.proof_packet_path and Path(state.proof_packet_path).exists())
        state.gates["guardian"] = "pass" if state.guardian_pass else "blocked"
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


def create_warroom_goal(
    session_id: str,
    arg: str,
    *,
    tracking_dir: Optional[str] = None,
    allowed_mutation_root: Optional[str] = None,
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
    roles = list(FAST_ROLES if detection.workflow == "fast_adversary" else STRICT_ROLES)
    cards = _role_cards_for(tracking)
    role_cards_ok = all(Path(cards[role]).exists() for role in roles)
    gates = {
        "graphify": "pending",
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
    if detection.missing_sections:
        status = "blocked"
        gates["plan"] = "blocked"
        last_gap = "Missing required strict sections: " + ", ".join(detection.missing_sections)
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
        current_role="controller",
        required_roles=roles,
        roles_started={role: role == "controller" for role in roles},
        role_cards={role: cards[role] for role in roles},
        gates=gates,
        gate_evidence={"controller_active": ["runtime created Warroom state"]},
        tracking_dir=tracking,
        allowed_mutation_root=allowed_root,
        denied_mutation_roots=_default_denied_roots(),
        delegate_runtime_checked=True,
        delegate_runtime_available=False,
        last_gap=last_gap,
        final_claim_allowed=False,
    )
    if state.status == "active":
        state = _start_roles_for_state(state)
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
    return (
        f"WARROOM V3 {state.workflow} enforced state created.\n"
        f"Status: {state.status}. Controller active.\n"
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


def _terminal_mutates(args: Dict[str, Any]) -> bool:
    cmd = str(args.get("command") or "")
    return bool(DESTRUCTIVE_TERMINAL_RE.search(cmd))


def _execute_code_mutates(args: Dict[str, Any]) -> bool:
    code = str(args.get("code") or "")
    return bool(EXECUTE_CODE_WRITE_RE.search(code))


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
        return f"WARROOM V3 blocked: workflow is {state.status} ({state.halt_reason or state.last_gap or 'no reason recorded'})."
    state = _auto_start_build_roles_if_ready(session_id, state)
    if state.required_action == "spawn_roles":
        return "WARROOM V3 blocked: required role spawn action is pending; normal chat/tool fallback denied."

    mutating = tool_name in MUTATING_TOOLS
    # Terminal and execute_code are arbitrary-code surfaces. Treat them as
    # mutation-capable and fail closed for non-Builder roles instead of trying
    # to prove a shell/Python snippet is read-only with regexes.
    if tool_name in {"terminal", "execute_code"}:
        mutating = True
    elif tool_name == "delegate_task":
        if state.current_role not in {"controller", None}:
            return f"WARROOM V3 blocked: role {state.current_role} cannot spawn delegate_task. Controller owns orchestration."
        if state.gates.get("role_spawn") != "pass":
            state.status = "gap"
            state.gates["delegate_runtime"] = "gap"
            state.last_gap = "required roles not spawned before delegate_task"
            save_warroom_goal(session_id, state)
            return "WARROOM V3 GAP: required role spawn evidence missing; agents were not pretended to fire."
        return None

    if not mutating:
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


def guard_final_response(session_id: str, response: str) -> str:
    state = load_warroom_goal(session_id)
    if state is None or not response:
        return response
    noncritical_state = _record_noncritical_halt_text(session_id, response)
    if noncritical_state is not None:
        state = noncritical_state
        response = (
            response.rstrip()
            + f"\n\nWARROOM V3 auto_continued:{state.noncritical_pause_attempts[-1]['reason']} — non-mission-critical stop denied."
        )
    if state.required_action == "spawn_roles":
        return "WARROOM V3 FINAL BLOCKED: required role spawn action is pending. GAP: normal chat fallback denied until roles spawn or explicit GAP is recorded."
    if _has_final_completion_claim(response):
        proof = state.proof_packet_path
        if not proof or not Path(proof).exists() or not state.final_claim_allowed:
            return (
                "WARROOM V3 FINAL BLOCKED: final done/fixed/complete claim requires proof packet "
                "and Guardian PASS.\nGAP: proof packet/final_claim_allowed missing."
            )
        if E2E_CLAIM_RE.search(response) and HEALTH_ONLY_RE.search(response) and not E2E_EVIDENCE_RE.search(response):
            return "WARROOM V3 FINAL BLOCKED: health checks alone do not prove E2E."
    return response


def status_line_for_session(session_id: str) -> Optional[str]:
    state = load_warroom_goal(session_id)
    return state.status_line() if state else None
