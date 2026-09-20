# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**.

Latest playable implementation on active branch: `e19e2425d4f2c4189fb4cc4a8c68cfe0b3f4c304`.
Latest active-branch state/documentation head: `5e71d819139b0ad2db09d327ba5cafb74b1b0714`.
Sail-fatigue implementation commit: `a29741a112488dab0a33c1c804f05e52c6fde0f3`.
ADR-0006 commit: `5cb8b9081a889e40deebf3e39232f463243bc48e`.

**Fresh-chat rule:** switch conceptually to `feature/restore-prototype-ux-parity` before inspecting or changing implementation. Read that branch's `PROJECT_STATE.md`, the compliance matrix and relevant ADRs. Do not use this canonical snapshot as a substitute for the active branch when the latter has advanced.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The 2v2 remains the active development/regression scenario for historical ship data, multi-ship control and shared mechanics. It is not the final fleet architecture.

## Immutable / stable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains the discovery/stable branch and is not used for normal development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.

## Source / baseline policy

ADR-0004 remains the technical source policy. The current sail-fatigue rule is an explicit project divergence under ADR-0006.

The playable interface now uses neutral simulator terminology and does **not** display the baseline product name. Internal research/ADR/compliance documents retain source attribution for provenance.

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

## Collision regression fixed

The previous collision path only checked geometry after movement, allowing two ships to cross visually during simultaneous movement and finish apart without consequences.

The active branch now includes swept trajectory collision detection (`src/collision-guard.js`) that checks bow/centre/stern volumes throughout movement, stops ships at first contact, and applies hull/rigging/crew damage, sail-dependent fatigue and stern rudder-damage risk. Endpoint collisions already caught by the original path are not double-counted.

## Tactical readability fixed

Player-facing targeting/battery state is now explicit:

- current target gets a red `OBJETIVO` ring;
- selected own ship gets a pulsing/dashed red `APUNTADO` ring when one or more enemies target it;
- force-status cards get matching emphasis;
- Babor/Estribor buttons remain visibly selected;
- selected firing side is marked on the ship with a red side indicator;
- overlays follow pan, zoom, fit, recenter, reset/start and the `C` shortcut.

## Validation / deployment

Latest validated implementation: `e19e2425d4f2c4189fb4cc4a8c68cfe0b3f4c304`.

Render deploy: `dep-dao223ff3r2c73ef49v0` — **live**.

The service build command is `npm install && npm test`; the full suite therefore passed before deployment.

Validated suite: **55 tests, 0 failed**.

Development service:

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- auto-deploy: enabled

Stable reference service remains untouched.

## Next concrete task

Unless user testing exposes another regression, continue with the morale / surrender / boarding dependency chain, then critical mast/dragging-mast, four helm-damage states and fire.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable original-prototype reference.
