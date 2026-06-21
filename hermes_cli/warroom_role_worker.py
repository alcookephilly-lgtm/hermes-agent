"""Minimal Warroom role worker process used by runtime spawn glue.

The worker proves a role process started, read its role card, and wrote evidence.
It does not mutate code. Build mutation remains guarded by warroom_goal policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True)
    parser.add_argument("--role-card", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--tracking-dir", default="")
    parser.add_argument("--worktree-root", default="")
    parser.add_argument("--hold-seconds", type=float, default=0.0)
    args = parser.parse_args()

    card = Path(args.role_card)
    evidence = Path(args.evidence)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "role": args.role,
        "status": "started",
        "pid": os.getpid(),
        "started_at": now,
        "role_card_path": str(card),
        "role_card_sha256": _sha256(card),
        "tracking_dir": args.tracking_dir,
        "worktree_root": args.worktree_root,
        "mutation_allowed": args.role == "builder",
        "note": "role process started and persisted evidence",
    }
    evidence.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.hold_seconds > 0:
        time.sleep(args.hold_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
