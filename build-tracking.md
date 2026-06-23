# Build Tracking

## Active Milestone
- **M1 - Planning / adversary-incorporated pre-mutation gate**

## Milestone Status
- **PLAN_REVIEW_READY**

## Gates
- [x] Graphify report read first via smart-read.
- [x] jcodemunch repo resolution captured for the local repo.
- [x] CodeGraph status checked and recorded as not initialized (no mutation performed).
- [x] Controller-provided watch status captured as not stale.
- [x] Local git baseline verified.
- [x] Golden rollback tag verified to exist.
- [x] Planning docs updated to cover full adversary acceptance surface.
- [ ] Plan review approved.
- [ ] Builder implementation executed on approved Warroom files only.
- [ ] Exact targeted regressions/evidence collected.
- [ ] Reviewer diff isolation confirmed.
- [ ] Guardian serial final verification PASS.
- [ ] Local commit created after Guardian PASS.
- [ ] Push withheld for this task.

## Baseline Evidence
### Graph / repo discovery
- Graphify report path: `/mnt/c/Users/paulcooke1976/claude-config/graphify-out/GRAPH_REPORT.md`
  - Read first via smart-read.
  - Header date: `2026-06-23`
  - Summary: `7528 nodes`, `16654 edges`
- jcodemunch local index metadata:
  - Repo: `local/hermes-agent-ab4055f7`
  - Source root: `/home/alcoo/.hermes/hermes-agent`
  - Indexed at: `2026-06-23T08:49:07.132602`
- CodeGraph:
  - `codegraph status /home/alcoo/.hermes/hermes-agent` => `Not initialized`
- Controller context carried forward:
  - Watch status: `any_stale=F any_in_progress=F any_failing=F`

### Git / rollback baseline
- HEAD: `380936902a32ca35c05bd2fc37dddb9adb95cc36`
- Golden tag exists: `golden-20260623-warroom-goal-parser-hotfix`

### Pre-existing unrelated dirt to preserve
- `plugins/image_gen/openai-codex/__init__.py` modified
- `tests/plugins/image_gen/test_openai_codex_provider.py` modified
- `.warroom/` untracked
- Planning docs are tracked in this task scope:
  - `build-tracking.md`
  - `living-build-doc.md`

## Build Acceptance Coverage
- [x] Canonical heading-intent detection called out as the real fix target.
- [x] Punctuation/case/spacing normalization called out explicitly.
- [x] Exact verify-heading variants listed for mandatory coverage:
  - `Verify with these read-only commands:`
  - `Verification:`
  - `Test with:`
  - `Commands to run:`
  - `Proof commands:`
- [x] Acceptance/Constraints variants called out as mandatory intent-normalization coverage.
- [x] Real missing-section blockers required.
- [x] No stale `required_action=spawn_roles` after parser rejection required.
- [x] No fake role spawn / fake role proof after parser rejection required.
- [x] Read-only/controller diagnostics after parser rejection required.
- [x] Existing role-spawn and final-guard hardwires marked as preserve-in-place.
- [x] No unrelated dirt requirement captured.
- [x] Guardian serial final verification requirement captured.
- [x] Local commit after Guardian PASS / no push requirement captured.

## Exact Regression Proof Required In Build Step
1. Strict-plan alias/normalization success path.
2. Exact verify-heading variant coverage.
3. Acceptance/Constraints variant coverage.
4. Real missing-section rejection with canonical missing-intent reporting.
5. Parser rejection leaves no stale `spawn_roles` pending state.
6. Parser rejection leaves no fake role-spawn/proof evidence.
7. Controller/read-only diagnostics still work after parser rejection.
8. Existing role-spawn success path still persists runtime IDs/hash/evidence.
9. Existing final-guard proof requirements still block invalid completion claims.
10. Existing unlocked final path still emits canonical `GOAL COMPLETED` output.
11. Existing real spawn-pending final-block behavior still holds.

## Allowed Files
### Current planning milestone
- `/home/alcoo/.hermes/hermes-agent/living-build-doc.md`
- `/home/alcoo/.hermes/hermes-agent/build-tracking.md`

### Future build milestone
- Warroom parser/runtime files required to implement heading-intent normalization.
- Exact Warroom regression tests needed to prove the change.
- Explicitly disallowed: `.warroom/image_gen/secrets/MCP/gateway` and unrelated files.

## Build-Step Verification Sequence
1. Controller confirms plan/tracking docs are approved.
2. Builder mutates only approved Warroom parser/runtime/test files.
3. Run targeted Warroom parser/runtime regressions.
4. Reviewer checks diff isolation and confirms no unrelated dirt beyond baseline.
5. Guardian performs serial final verification.
6. If Guardian PASSes, create a local commit.
7. Do not push.

## Notes
- This task updated planning docs only.
- No source files were modified.
- No deletes were performed.
- CodeGraph remained uninitialized; no init/uninit action taken.
