"""Tiny source hook for the user-world Warroom /goal runtime.

Hermes core keeps only the literal /goal import/dispatch seam here. The
Warroom state machine, role policy, evidence handling, and adversary routing
live in the user-world runtime at ``~/.hermes/tools/warroom_goal_runtime.py``
(or ``HERMES_WARROOM_GOAL_RUNTIME`` for isolated tests/restore packs).
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def _runtime_path() -> Path:
    override = os.environ.get("HERMES_WARROOM_GOAL_RUNTIME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".hermes" / "tools" / "warroom_goal_runtime.py").resolve()


def _load_user_world_runtime() -> None:
    path = _runtime_path()
    if not path.exists():
        raise RuntimeError(
            "Warroom /goal user-world runtime is missing. Expected "
            f"{path}. Restore/install ~/.hermes/tools/warroom_goal_runtime.py."
        )
    spec = importlib.util.spec_from_file_location(__name__, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load Warroom /goal runtime from {path}")
    module = importlib.util.module_from_spec(spec)
    module.__dict__.setdefault("__hermes_source_hook__", __file__)
    module.__dict__.setdefault("__hermes_user_world_runtime__", str(path))
    sys.modules[__name__] = module
    spec.loader.exec_module(module)


_load_user_world_runtime()
