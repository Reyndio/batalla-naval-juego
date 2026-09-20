# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**.

Latest validated playable implementation on active branch: `fef4b4e5bff54a8370a2365b28e5a3518eaa115b`.
Latest active-branch state/documentation head: `a4172d2a6a87bd350186bc27b33ff81183914bf0`.

**Fresh-chat rule:** switch conceptually to `feature/restore-prototype-ux-parity` before inspecting or changing implementation. Read that branch's `PROJECT_STATE.md`, the compliance matrix and relevant ADRs. Do not use this canonical snapshot as a substitute for the active branch when the latter has advanced.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The 2v2 remains a development/regression scenario for historical ship data, multi-ship control and shared mechanics. It is not the final fleet architecture.

## Immutable / stable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains the discovery/stable branch and is not used for normal development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.

## Source / baseline policy

ADR-0004 remains the technical source policy. Sail fatigue remains an explicit project divergence under ADR-0006. Translational inertia is a documented PROJECT-RECONSTRUCTION under ADR-0007 because the baseline manual omits the detailed computer movement algorithm.

The playable interface uses neutral simulator terminology and does not display the baseline product name. Internal research/ADR/compliance documents retain source attribution for provenance.

Authoritative checklist remains on the active branch:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

## Current verified / project-rule progress

- **Hull 0 / Hull 1 / sinking — VERIFIED.**
- **Current four-ship class dependency — VERIFIED.**
- **Rudder/history/class manoeuvre rules — VERIFIED.**
- **Tacking stop/departure — VERIFIED.**
- **Crew quality — shooting/manoeuvre portions verified; boarding pending.**
- **Sail-change fatigue — PROJECT-DIVERGENCE.** `NV→PV→MV→TV`; every adjacent point crossed costs +10%, symmetric, so direct changes cost 10/20/30.
- **Gunnery/ammunition — advanced PARTIAL.** Four ammunition families, per-band loading, double-shot reload, <=112 m forced hull, target-sail modifiers, windward/leeward allocation and actual carronade ranges are implemented/tested; source-omitted base damage/range and dependent crew/fire/morale pieces remain open.
- **Sailing speed — PARTIAL.** Class factors, fallen-mast penalties, dismasted stop and Hull 0/1 cap exist; literal rig thresholds and dragging-mast behavior remain pending.
- **Translational inertia — PROJECT-RECONSTRUCTION implemented.** Ships retain a persistent 2D motion vector; sail reductions no longer stop translation instantly, acceleration is progressive, turning carries previous way, and the movement preview shows the inertial destination. Current third-class response coefficient is 0.40/turn; collision retains 25% prior motion into the next turn. Quantitative calibration remains provisional.
- **Raking geometry — corrected.** Bow/stern rake classification now requires both the defender-axis cone (+/-15°) and approximately perpendicular headings (+/-15° around 90°), producing a T-like geometry; oblique L-like/diagonal positions no longer receive rake multipliers.
- **Swept collision detection — corrected.** Collision checking follows the actual inertial movement trajectory rather than only endpoints.
- **Tactical readability — corrected.** Objective/threat rings and selected battery-side marks are live.

## Validation / deployment

Validated implementation commit: `fef4b4e5bff54a8370a2365b28e5a3518eaa115b`.

Render deploy: `dep-dao3lefavr4c73atgk1g` — **live**.

The service builds with `npm install && npm test`; therefore the full repository suite passed before deployment.

Validated suite: **60 tests, 0 failed**.

Development service:

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- auto-deploy: enabled

Stable reference service remains untouched.

## Next concrete task

First validate inertia, collision and rake geometry through live play. Unless user testing exposes another regression, continue with morale / surrender / boarding, then critical mast/dragging-mast, four helm-damage states and fire. Leeway, heel and deeper sailing calibration remain part of the Historical 1v1 milestone.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable original-prototype reference.
