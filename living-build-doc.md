# Living Build Doc

## Status
- **PLAN_REVIEW_READY**

## Goal
Plan the Warroom `/goal` parser hardwire so strict-plan prompts are classified by canonical section intent after normalization instead of exact heading string matches, while preserving the existing role-spawn and final-guard hardwires.

## Scope
- Plan only; no source-code mutation in this step.
- Cover the full acceptance surface for strict-plan heading detection, parser rejection behavior, tool-policy notices, and final-verification sequencing.
- Keep source/test edits for the later build step limited to the Warroom parser/runtime path plus exact regression tests required to prove the change.

## No-Touch Constraints
- Do not edit source code in this planning step.
- Do not delete files.
- Do not touch `.warroom/image_gen/secrets/MCP/gateway` paths or any other secrets/MCP/gateway/image_gen material.
- Writable files in this step remain limited to:
  - `/home/alcoo/.hermes/hermes-agent/living-build-doc.md`
  - `/home/alcoo/.hermes/hermes-agent/build-tracking.md`

## Discovery Gates
1. **Graphify report read first via smart-read: PASS**
   - `GRAPH_REPORT.md` was read before repo doc fallback.
   - Report header confirms `/mnt/c/Users/paulcooke1976/CLAUDE CONFIGS` graph report dated `2026-06-23`.
   - Summary confirms `7528 nodes` and `16654 edges`.
2. **jcodemunch repo resolution: PASS**
   - Local jcodemunch index metadata resolves repo `local/hermes-agent-ab4055f7`.
   - `source_root=/home/alcoo/.hermes/hermes-agent`.
   - Indexed timestamp recorded as `2026-06-23T08:49:07.132602`.
3. **CodeGraph status: GAP but non-blocking for planning**
   - `codegraph status /home/alcoo/.hermes/hermes-agent` reports **Not initialized**.
   - No CodeGraph init/uninit mutation was performed.
4. **Controller proof carried into planning docs: PASS**
   - Watch status from controller context remains `any_stale=F any_in_progress=F any_failing=F`.
5. **Local git baseline: PASS**
   - HEAD: `380936902a32ca35c05bd2fc37dddb9adb95cc36`.
   - Golden rollback tag exists: `golden-20260623-warroom-goal-parser-hotfix`.
   - Existing unrelated dirt before this planning update: modified image_gen files, untracked `.warroom/`, and these two planning docs.

## Full Acceptance Requirements For The Build Step
### Canonical heading intent detection
- Strict-plan parsing must recognize section **intent**, not exact raw heading text.
- Recognized headings must normalize back to canonical intents for:
  - `Goal`
  - `Acceptance`
  - `Constraints`
  - `Verify with`
- Canonical downstream behavior must remain stable after normalization; later code/tests may accept aliases, but the runtime contract must still reason about canonical section intents.

### Normalization requirements
- Case-insensitive matching.
- Punctuation-insensitive heading detection where punctuation/casing changes should not create false missing-section blockers.
- Spacing/format tolerance for heading lines so benign formatting differences do not fall back to exact-string rejection.

### Verify-intent variants that must be accepted exactly
The implementation/test plan must explicitly prove all of these resolve to the canonical verify intent:
- `Verify with these read-only commands:`
- `Verification:`
- `Test with:`
- `Commands to run:`
- `Proof commands:`

### Acceptance / Constraints variants
- `Acceptance` and `Constraints` cannot remain exact-label-only.
- The implementation must use the same normalization + canonical-intent mapping strategy for these sections that it uses for verify headings.
- Missing-section blockers must be raised only when the required **intent** is absent after normalization, not when a valid variant is present.

## Required Parser-Rejection Behavior
- Real missing-section blockers only: reject strict-plan kickoff only when one or more required intents are truly absent.
- Parser rejection must not leave `required_action=spawn_roles` pending.
- Parser rejection must not fabricate spawned roles, fake role-spawn proof, or stale role-spawn pending notices.
- Tool policy, controller notice/status text, and read-only diagnostics must report the real blocked reason (missing strict sections / plan blocked), not a stale spawn-pending state.
- Controller read-only diagnostics and tracking-doc updates must remain usable after parser rejection; they cannot be stale-locked behind fake role-spawn pending state.

## Must-Preserve Runtime Guarantees
- Preserve existing role-spawn hardwire when parsing succeeds.
- Preserve existing final-guard hardwire, including:
  - no final completion claim without proof packet + Guardian PASS,
  - no health-check-only E2E claim,
  - `GOAL COMPLETED` output wire after valid unlock,
  - no normal-chat fallback when a real spawn action is still pending.
- Preserve controller-only orchestration and builder-only mutation policy.

## Exact Regression Proof Required
The build step must add or update focused tests proving all of the following:
1. Strict-plan prompts with normalized heading variants enter `strict_plan_adversary` without false missing-section blockers.
2. Verify-intent variants listed above all map to the canonical verify section.
3. Acceptance/Constraints heading variants map to their canonical intents after normalization.
4. Real missing sections still block strict-plan kickoff and report the exact missing canonical intents.
5. A parser-rejected strict-plan kickoff does **not** leave `required_action=spawn_roles` pending.
6. A parser-rejected strict-plan kickoff does **not** claim roles spawned, proof written, or stale role-spawn evidence.
7. Read-only/controller diagnostics remain available after parser rejection.
8. Existing role-spawn success behavior still persists IDs/hashes/evidence for valid workflows.
9. Existing final-guard behavior still blocks completion without proof and still emits canonical `GOAL COMPLETED` output after Guardian PASS.
10. Existing spawn-pending final-guard behavior remains intact for real pending spawn states.

## Implementation Plan
1. Replace exact-string strict-section detection with a normalized heading-intent classifier in the Warroom parser path.
2. Canonicalize recognized aliases back to `Goal`, `Acceptance`, `Constraints`, and `Verify with` intents.
3. Use intent presence, not literal heading text, to decide `missing_sections`.
4. Ensure strict-plan parser rejection leaves the goal in a real blocked state without stale `spawn_roles` follow-on behavior.
5. Audit runtime notice/status/tool-policy branches that currently treat parser rejection like spawn-pending state and tighten them to report the actual blocker.
6. Keep successful strict-plan role-spawn sequencing unchanged once plan/tracking gates pass.
7. Add/update exact regression tests for parser success, parser rejection, read-only/controller behavior, role-spawn preservation, and final-guard preservation.
8. Run only targeted tests for the touched Warroom parser/runtime path plus adjacent regressions required by the changed behavior.
9. Confirm final diff contains only approved Warroom files plus targeted tests, with no unrelated dirt introduced.

## Read-Only Verification Checklist For The Build Step
- Verify strict-plan alias coverage against canonical intents.
- Verify missing-intent rejection reports real missing canonical sections.
- Verify no stale `spawn_roles` state after parser rejection.
- Verify controller/tool-policy messaging stays accurate after parser rejection.
- Verify role-spawn success path still works for valid strict/fast workflows.
- Verify final-guard regressions still pass.
- Verify unrelated dirt remains limited to the pre-existing image_gen changes, `.warroom/`, and approved Warroom edits.

## Final Execution / Review Sequence
1. Controller records plan + tracking docs as PASS for plan review.
2. Builder performs minimal Warroom parser/runtime/test edits only after plan approval.
3. Reviewer checks exact regressions and unrelated-dirt isolation.
4. Guardian performs serial final verification and must PASS before any completion claim.
5. After Guardian PASS, create a local commit for the approved change set.
6. Do **not** push in this task.

## Final Gate
No source-code mutation should begin until plan review is complete. The build step is only acceptable if it proves:
- canonical intent-detected headings after normalization,
- exact verify-heading variant coverage,
- Acceptance/Constraints variant coverage,
- real missing-section blockers,
- no stale/fake role-spawn behavior after parser rejection,
- preserved role-spawn + final-guard hardwires,
- targeted regressions passing,
- no unrelated dirt beyond the pre-existing baseline and approved Warroom files,
- Guardian serial verification PASS before local commit,
- local commit created after Guardian PASS with **no push**.
