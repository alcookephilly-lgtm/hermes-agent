# MemoryMunch Hermes Plugin Operations

## What this protects

The runtime plugin lives in `$HERMES_HOME/plugins/memorymunch`. Native Hermes
updates change the Hermes source checkout; they should not edit that runtime
plugin folder. The risk is different: a native update can move the active source
checkout away from the branch that contains our tests and proof harness.

## Senior protocol

- Keep the deployable plugin vendored in git at `contrib/plugins/memorymunch`.
- Keep the runtime plugin deployed under `$HERMES_HOME/plugins/memorymunch`.
- Use `contrib/plugins/memorymunch/watchdog.py` to prove the runtime copy matches
  the git copy.
- Tag every known-good build.
- After native `hermes update`, rerun watchdog + focused tests before E2E.

## Lame terms: source/test branch

The source/test branch is the safety inspection station. It contains tests and
small Hermes-side compaction hooks that prove MemoryMunch does not bleed old
sessions, stale activation memories, or bad compaction summaries into the answer.

The plugin is the engine. The source/test branch proves the engine stays safe.

## Compaction ownership

MemoryMunch owns its compaction protocols when the plugin is enabled. Hermes core
is only the wall outlet/hook: it asks the active memory provider whether it wants
to build a source-of-truth compaction checkpoint. If MemoryMunch is off or says
no, Hermes uses normal compaction.

Switches:

```bash
# MemoryMunch off: Hermes normal compaction
unset HERMES_MEMORYMUNCH_ENABLE

# MemoryMunch on: MemoryMunch source-of-truth compaction protocols are on by default
export HERMES_MEMORYMUNCH_ENABLE=1

# Debug override: MemoryMunch recall/tools on, but Hermes normal compaction
export HERMES_MEMORYMUNCH_COMPACTION_ENABLE=0
```

## Watchdog commands

Read-only check:

```bash
python contrib/plugins/memorymunch/watchdog.py --json
```

Repair runtime plugin from repo copy:

```bash
python contrib/plugins/memorymunch/watchdog.py --repair --json
```

## Focused proof command

```bash
/home/alcoo/.hermes/hermes-agent/venv/bin/python -m pytest \
  tests/run_agent/test_background_compaction.py \
  tests/run_agent/test_memorymunch_compression_context.py \
  tests/run_agent/test_memorymunch_softwall.py \
  tests/plugins/test_memorymunch_watchdog.py \
  tests/plugins/test_memorymunch_compaction_ownership.py \
  -q -o 'addopts='
```
