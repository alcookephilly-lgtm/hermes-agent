"""AGT hardwire manifest and native-update overwrite guard.

This module protects approved-update paths (``hermes update`` / restore
helpers) from silently replacing the local AGT hardwire files. It is not a
claim that files are impossible to overwrite; it is a gate on Hermes-owned
update/restore paths before they run destructive git/file operations.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APPROVAL_PHRASE = "AL_APPROVES_OVERWRITE_AGT_HARDWIRES"
EXPECTED_MANIFEST_SHA256 = "c334da7659b2064de8fe3187db505a10c732ae5122c23f63edae837f3155e7f0"
MANIFEST_PATH = Path(__file__).with_name("agt_hardwire_manifest.json")
SAFE_NO_HARDWIRE_DIFF = "SAFE_NO_HARDWIRE_DIFF"
BLOCKED_HARDWIRE_OVERWRITE = "BLOCKED_HARDWIRE_OVERWRITE"
APPROVED_HARDWIRE_OVERWRITE = "APPROVED_HARDWIRE_OVERWRITE"
MANIFEST_DRIFT = "MANIFEST_DRIFT"


@dataclass
class HardwireRisk:
    path: str
    reason: str
    before_sha256: str | None = None
    manifest_sha256: str | None = None
    target_blob_sha: str | None = None
    manifest_blob_sha: str | None = None
    target_ref: str | None = None


@dataclass
class HardwireGuardResult:
    allowed: bool
    status: str
    files: list[HardwireRisk] = field(default_factory=list)
    audit_path: Path | None = None
    rollback_ref: str | None = None
    rollback_patch: Path | None = None
    restore_instructions: list[str] = field(default_factory=list)
    message: str = ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_git(root: Path, args: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=check,
    )


def _sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _blob_sha(root: Path, ref: str, relpath: str) -> str | None:
    proc = _run_git(root, ["rev-parse", f"{ref}:{relpath}"])
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _head_sha(root: Path) -> str | None:
    proc = _run_git(root, ["rev-parse", "HEAD"])
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _ref_commit_sha(root: Path, ref: str) -> str | None:
    proc = _run_git(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _default_audit_dir(root: Path) -> Path:
    explicit = os.environ.get("HERMES_AGT_HARDWIRE_AUDIT_DIR")
    if explicit:
        return Path(explicit)
    hermes_home = os.environ.get("HERMES_HOME")
    if hermes_home:
        return Path(hermes_home) / "proof" / "agt-hardwire-update"
    return Path.home() / ".hermes" / "proof" / "agt-hardwire-update"


def _load_manifest() -> tuple[list[dict[str, Any]], list[HardwireRisk]]:
    drift: list[HardwireRisk] = []
    if not MANIFEST_PATH.exists():
        return [], [HardwireRisk(path=str(MANIFEST_PATH), reason="manifest file missing")]

    raw = MANIFEST_PATH.read_text(encoding="utf-8")
    actual_manifest_sha = _sha256_text(raw)
    if (
        EXPECTED_MANIFEST_SHA256
        and not EXPECTED_MANIFEST_SHA256.startswith("__")
        and actual_manifest_sha != EXPECTED_MANIFEST_SHA256
    ):
        drift.append(
            HardwireRisk(
                path=str(MANIFEST_PATH.name),
                reason="manifest content hash mismatch",
                before_sha256=actual_manifest_sha,
                manifest_sha256=EXPECTED_MANIFEST_SHA256,
            )
        )
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [], [HardwireRisk(path=str(MANIFEST_PATH), reason=f"manifest JSON invalid: {exc}")]

    entries = data.get("protected_files") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        drift.append(HardwireRisk(path=str(MANIFEST_PATH.name), reason="manifest missing protected_files list"))
        return [], drift

    required = {"path", "sha256", "git_blob_sha", "commit_source", "reason", "wave_introduced", "wave_last_touched"}
    for entry in entries:
        if not isinstance(entry, dict) or not required.issubset(entry):
            drift.append(HardwireRisk(path=str(MANIFEST_PATH.name), reason="manifest entry missing required fields"))
            break
    return entries, drift


def manifest_entries() -> list[dict[str, Any]]:
    entries, drift = _load_manifest()
    if drift:
        raise RuntimeError("AGT hardwire manifest drift: " + "; ".join(f"{d.path}: {d.reason}" for d in drift))
    return entries


def inspect_manifest_drift(root: str | Path) -> list[HardwireRisk]:
    root_path = Path(root)
    entries, drift = _load_manifest()
    for entry in entries:
        relpath = str(entry["path"])
        current_sha = _sha256_file(root_path / relpath)
        if current_sha is None:
            drift.append(
                HardwireRisk(
                    path=relpath,
                    reason="protected file missing from working tree",
                    manifest_sha256=str(entry["sha256"]),
                )
            )
            continue
        if current_sha != entry["sha256"]:
            drift.append(
                HardwireRisk(
                    path=relpath,
                    reason="working-tree sha256 differs from manifest",
                    before_sha256=current_sha,
                    manifest_sha256=str(entry["sha256"]),
                )
            )
    return drift


def _target_hardwire_diffs(root: Path, target_ref: str) -> list[HardwireRisk]:
    entries, _ = _load_manifest()
    risks: list[HardwireRisk] = []
    for entry in entries:
        relpath = str(entry["path"])
        target_blob = _blob_sha(root, target_ref, relpath)
        manifest_blob = str(entry["git_blob_sha"])
        if target_blob != manifest_blob:
            risks.append(
                HardwireRisk(
                    path=relpath,
                    reason="target update would change protected hardwire file",
                    before_sha256=_sha256_file(root / relpath),
                    manifest_sha256=str(entry["sha256"]),
                    target_blob_sha=target_blob,
                    manifest_blob_sha=manifest_blob,
                    target_ref=target_ref,
                )
            )
    return risks


def _risk_to_dict(risk: HardwireRisk) -> dict[str, Any]:
    return {
        "path": risk.path,
        "reason": risk.reason,
        "before_sha256": risk.before_sha256,
        "manifest_sha256": risk.manifest_sha256,
        "target_blob_sha": risk.target_blob_sha,
        "manifest_blob_sha": risk.manifest_blob_sha,
        "target_ref": risk.target_ref,
    }


def _write_audit(
    root: Path,
    audit_dir: Path,
    *,
    status: str,
    command: str,
    caller: str,
    target_ref: str | None,
    risks: list[HardwireRisk],
    approval_phrase_present: bool,
    approval_reason: str | None,
    rollback_ref: str | None = None,
    rollback_patch: Path | None = None,
    restore_instructions: list[str] | None = None,
    after_sha256: dict[str, str | None] | None = None,
) -> Path:
    audit_dir.mkdir(parents=True, exist_ok=True)
    stamp = _utc_now().replace(":", "").replace("-", "")
    path = audit_dir / f"agt-hardwire-update-{stamp}-{status.lower()}.json"
    packet = {
        "schema": "agt-hardwire-update-proof.v1",
        "timestamp": _utc_now(),
        "status": status,
        "root": str(root),
        "head_sha": _head_sha(root),
        "target_ref": target_ref,
        "command": command,
        "caller": caller,
        "approval_phrase": APPROVAL_PHRASE if approval_phrase_present else None,
        "approval_reason": approval_reason,
        "files": [_risk_to_dict(r) for r in risks],
        "rollback_ref": rollback_ref,
        "rollback_patch": str(rollback_patch) if rollback_patch else None,
        "restore_instructions": restore_instructions or [],
        "after_sha256": after_sha256 or {},
    }
    path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _create_rollback(root: Path, audit_dir: Path, command: str) -> tuple[str | None, Path | None, list[str]]:
    head = _head_sha(root)
    instructions: list[str] = []
    rollback_ref = None
    patch_path = None
    if head:
        suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        base = f"agt-hardwire-pre-overwrite-{suffix}-{head[:10]}"
        rollback_ref = base
        tag_proc = _run_git(root, ["tag", rollback_ref, head])
        if tag_proc.returncode != 0:
            rollback_ref = f"{base}-manual"
        instructions.append(f"cd {root} && git reset --hard {head}")
        if rollback_ref and not rollback_ref.endswith("-manual"):
            instructions.append(f"cd {root} && git reset --hard {rollback_ref}")
    audit_dir.mkdir(parents=True, exist_ok=True)
    patch_path = audit_dir / f"agt-hardwire-pre-overwrite-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.patch"
    diff_proc = _run_git(root, ["diff", "--binary", "HEAD", "--", *protected_paths()])
    patch_path.write_text(diff_proc.stdout if diff_proc.returncode == 0 else "", encoding="utf-8")
    instructions.append(f"Patch bundle: {patch_path}")
    instructions.append(f"Original command/caller: {command}")
    return rollback_ref, patch_path, instructions


def protected_paths() -> list[str]:
    entries, _ = _load_manifest()
    return [str(entry["path"]) for entry in entries]


def _approval_matches(approval_phrase: str | None) -> bool:
    return (approval_phrase or os.environ.get("HERMES_AGT_HARDWIRE_OVERWRITE_APPROVAL") or "").strip() == APPROVAL_PHRASE


def guard_native_update_hardwires(
    root: str | Path,
    target_ref: str,
    *,
    command: str,
    caller: str,
    approval_phrase: str | None = None,
    approval_reason: str | None = None,
    audit_dir: str | Path | None = None,
) -> HardwireGuardResult:
    root_path = Path(root)
    audit_path = Path(audit_dir) if audit_dir is not None else _default_audit_dir(root_path)
    manifest_paths = protected_paths()
    if not any((root_path / rel).exists() for rel in manifest_paths):
        path = _write_audit(
            root_path,
            audit_path,
            status=SAFE_NO_HARDWIRE_DIFF,
            command=command,
            caller=caller,
            target_ref=target_ref,
            risks=[],
            approval_phrase_present=False,
            approval_reason=None,
        )
        return HardwireGuardResult(True, SAFE_NO_HARDWIRE_DIFF, [], path, message="No AGT hardwire files present in update root.")
    risks = inspect_manifest_drift(root_path)
    status = MANIFEST_DRIFT if risks else SAFE_NO_HARDWIRE_DIFF
    if not risks and _ref_commit_sha(root_path, target_ref) is None:
        path = _write_audit(
            root_path,
            audit_path,
            status=SAFE_NO_HARDWIRE_DIFF,
            command=command,
            caller=caller,
            target_ref=target_ref,
            risks=[],
            approval_phrase_present=False,
            approval_reason=None,
        )
        return HardwireGuardResult(True, SAFE_NO_HARDWIRE_DIFF, [], path, message="Target ref not resolved; no protected AGT hardwire diffs detected.")
    if not risks:
        risks = _target_hardwire_diffs(root_path, target_ref)
        status = BLOCKED_HARDWIRE_OVERWRITE if risks else SAFE_NO_HARDWIRE_DIFF

    approved = _approval_matches(approval_phrase)
    reason = approval_reason or os.environ.get("HERMES_AGT_HARDWIRE_OVERWRITE_REASON")

    if not risks:
        path = _write_audit(
            root_path,
            audit_path,
            status=SAFE_NO_HARDWIRE_DIFF,
            command=command,
            caller=caller,
            target_ref=target_ref,
            risks=[],
            approval_phrase_present=False,
            approval_reason=None,
        )
        return HardwireGuardResult(True, SAFE_NO_HARDWIRE_DIFF, [], path, message="No protected AGT hardwire diffs detected.")

    if not approved:
        path = _write_audit(
            root_path,
            audit_path,
            status=status,
            command=command,
            caller=caller,
            target_ref=target_ref,
            risks=risks,
            approval_phrase_present=False,
            approval_reason=reason,
        )
        return HardwireGuardResult(False, status, risks, path, message="Protected AGT hardwire overwrite blocked.")

    rollback_ref, rollback_patch, instructions = _create_rollback(root_path, audit_path, command)
    path = _write_audit(
        root_path,
        audit_path,
        status=APPROVED_HARDWIRE_OVERWRITE,
        command=command,
        caller=caller,
        target_ref=target_ref,
        risks=risks,
        approval_phrase_present=True,
        approval_reason=reason,
        rollback_ref=rollback_ref,
        rollback_patch=rollback_patch,
        restore_instructions=instructions,
    )
    return HardwireGuardResult(
        True,
        APPROVED_HARDWIRE_OVERWRITE,
        risks,
        path,
        rollback_ref=rollback_ref,
        rollback_patch=rollback_patch,
        restore_instructions=instructions,
        message="Protected AGT hardwire overwrite approved and rollback preserved.",
    )


def finalize_native_update_hardwire_audit(root: str | Path, audit_path: str | Path | None) -> None:
    if not audit_path:
        return
    path = Path(audit_path)
    if not path.exists():
        return
    root_path = Path(root)
    try:
        packet = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    packet["completed_at"] = _utc_now()
    packet["after_sha256"] = {rel: _sha256_file(root_path / rel) for rel in protected_paths()}
    path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def restore_target_intersects_hardwires(root: str | Path, restore_target: str | None) -> list[HardwireRisk]:
    root_path = Path(root).resolve()
    target = restore_target or "."
    risks: list[HardwireRisk] = []
    all_paths = protected_paths()
    if target in {".", ""}:
        candidates = all_paths
    else:
        target_path = (root_path / target).resolve()
        candidates = []
        for rel in all_paths:
            protected = (root_path / rel).resolve()
            try:
                if protected == target_path or protected.is_relative_to(target_path) or target_path.is_relative_to(protected):
                    candidates.append(rel)
            except ValueError:
                continue
    for rel in candidates:
        risks.append(
            HardwireRisk(
                path=rel,
                reason="restore target intersects protected hardwire file",
                before_sha256=_sha256_file(root_path / rel),
            )
        )
    return risks


def guard_restore_hardwires(
    root: str | Path,
    restore_target: str | None,
    *,
    command: str,
    caller: str,
    approval_phrase: str | None = None,
    approval_reason: str | None = None,
    audit_dir: str | Path | None = None,
) -> HardwireGuardResult:
    root_path = Path(root)
    audit_path = Path(audit_dir) if audit_dir is not None else _default_audit_dir(root_path)
    manifest_paths = protected_paths()
    if not any((root_path / rel).exists() for rel in manifest_paths):
        path = _write_audit(
            root_path,
            audit_path,
            status=SAFE_NO_HARDWIRE_DIFF,
            command=command,
            caller=caller,
            target_ref=None,
            risks=[],
            approval_phrase_present=False,
            approval_reason=None,
        )
        return HardwireGuardResult(True, SAFE_NO_HARDWIRE_DIFF, [], path)
    risks = inspect_manifest_drift(root_path) or restore_target_intersects_hardwires(root_path, restore_target)
    if not risks:
        path = _write_audit(
            root_path,
            audit_path,
            status=SAFE_NO_HARDWIRE_DIFF,
            command=command,
            caller=caller,
            target_ref=None,
            risks=[],
            approval_phrase_present=False,
            approval_reason=None,
        )
        return HardwireGuardResult(True, SAFE_NO_HARDWIRE_DIFF, [], path)
    approved = _approval_matches(approval_phrase)
    reason = approval_reason or os.environ.get("HERMES_AGT_HARDWIRE_OVERWRITE_REASON")
    if not approved:
        path = _write_audit(
            root_path,
            audit_path,
            status=BLOCKED_HARDWIRE_OVERWRITE,
            command=command,
            caller=caller,
            target_ref=None,
            risks=risks,
            approval_phrase_present=False,
            approval_reason=reason,
        )
        return HardwireGuardResult(False, BLOCKED_HARDWIRE_OVERWRITE, risks, path)
    rollback_ref, rollback_patch, instructions = _create_rollback(root_path, audit_path, command)
    path = _write_audit(
        root_path,
        audit_path,
        status=APPROVED_HARDWIRE_OVERWRITE,
        command=command,
        caller=caller,
        target_ref=None,
        risks=risks,
        approval_phrase_present=True,
        approval_reason=reason,
        rollback_ref=rollback_ref,
        rollback_patch=rollback_patch,
        restore_instructions=instructions,
    )
    return HardwireGuardResult(True, APPROVED_HARDWIRE_OVERWRITE, risks, path, rollback_ref, rollback_patch, instructions)
