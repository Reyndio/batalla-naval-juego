# PROJECT STATE

Last updated: 2026-09-20

## Branches

Canonical integration branch: `develop/historical-simulator`.

Active implementation/validation branch: `feature/restore-prototype-ux-parity`.

PR #2 — `Restore prototype interaction parity in historical 2v2 pilot` — remains **draft**. Do not merge it merely for convenience; mechanical and user-facing validation are still active gates.

Latest playable implementation head: `e19e2425d4f2c4189fb4cc4a8c68cfe0b3f4c304`.
Latest sail-fatigue implementation commit: `a29741a112488dab0a33c1c804f05e52c6fde0f3`.
ADR-0006 commit: `5cb8b9081a889e40deebf3e39232f463243bc48e`.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The historical 2v2 remains the active development/regression scenario for real ship data, independent ship orders and shared mechanics. It is not the final fleet architecture.

## Stable / immutable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains untouched by normal historical-simulator development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`;
- the stable game remains the minimum functional behavior floor during migration.

## Source / baseline policy

ADR-0004 remains the general technical policy: reproduce applicable explicit rules from the historical baseline and deterministic tests before changing them, and do not invent omitted algorithms and present them as source-derived.

The **playable interface no longer displays the baseline product name**. Player-facing headings, labels, log text and injected controls are scrubbed to neutral simulator terminology. Internal research documents, ADRs, compliance files and source-attribution material keep the original source name where needed for provenance and auditability.

Authoritative mechanical checklist remains:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

## Historical 2v2 ship set

October 1805 configurations:

- Royal Navy: HMS Bellerophon and HMS Conqueror;
- Real Armada: Montañés and Bahama.

All four are documented 74-gun / 74-gun-class two-deckers and resolve to third class in the baseline dependency model.

## Current playable behavior

### Sail-change fatigue — PROJECT RULE / DELIBERATE DIVERGENCE

ADR-0006 supersedes ADR-0005 for current playable behavior.

Sail states are ordered `NV → PV → MV → TV`, and every adjacent sail point crossed costs +10% fatigue:

- same state: 0%;
- one point: +10%;
- two points: +20%;
- three points (`NV↔TV`): +30%.

The rule is symmetric. Direct jumps pay the whole cost in one turn; progressive changes pay +10% per point on each turn.

### Hull / sinking

Verified current behavior includes Hull 0 remaining operational, exact 10% per-turn sinking trigger, Hull 0/1 70% speed cap, lower-battery restriction at Hull 0, and pump/repair 0→1 at fatigue <=100 for +20 fatigue.

### Manoeuvre / tacking / crew quality

Verified current behavior includes 0/1/2 rudder points, 15° per point, previous-rudder history, class chances, one-mast/dismasted restrictions, exact head-to-wind stop/departure rule, and the currently implemented shooting/manoeuvre portions of Beginner/Normal/Veteran/Elite crew quality.

### Gunnery

The current branch includes the implemented/tested ammunition slice for round shot, bar/chain, grapeshot and separately reloaded double shot; per-band loading; <=112 m forced hull aim; target sail-state modifiers; windward/leeward allocation; actual-carronade range contribution; Hull-0 lower-battery restriction; and gun dismounting from hull fire.

Source-omitted base-damage/range details, full crew-service restrictions, full-sail fire risk, morale dependencies and true two-broadside execution remain incomplete.

## Collision review — corrected 2026-09-20

A live test exposed a real gap: the old collision code only tested ship geometry **after** movement. Two ships could therefore visually cross during simultaneous movement and finish separated, producing no collision consequence.

New `src/collision-guard.js` adds swept collision detection across the whole movement trajectory:

- ship poses are sampled through the turn, including interpolated heading;
- bow/centre/stern collision volumes are checked throughout the path;
- a mid-turn hit stops both ships at the first detected contact pose instead of allowing them to pass through;
- collision damage is applied to hull, rigging and crew;
- collision fatigue is applied by current sail state;
- stern contacts retain rudder-damage risk;
- collision fatigue cannot be accidentally reduced by idle-recovery processing from the base turn resolver;
- endpoint collisions already handled by the original collision path are not double-charged.

Deterministic regressions cover a crossing-path collision whose endpoints are separated, a distant no-collision path, and visible hull/crew/fatigue consequences.

## Tactical readability — corrected 2026-09-20

The playable map now exposes targeting state directly:

- the ship targeted by the selected player vessel gets a red tactical ring labelled `OBJETIVO`;
- if one or more enemy ships target the selected player vessel, that vessel gets a pulsing/dashed red ring labelled `APUNTADO` (or `APUNTADO ×N`);
- the corresponding force-status cards receive the same red emphasis;
- selecting `Babor` or `Estribor` now leaves the button visibly active;
- the selected firing side is also marked by a red side indicator on the selected ship;
- these overlays follow pan, zoom, fit-fleet, recenter buttons, reset/start and the `C` camera shortcut.

## Validation / deployment

Latest validated implementation commit: `e19e2425d4f2c4189fb4cc4a8c68cfe0b3f4c304`.

Render deploy: `dep-dao223ff3r2c73ef49v0` — **live**.

The service build command is `npm install && npm test`; therefore the complete repository suite passed before the deployment went live.

Validated suite: **55 tests, 0 failed** (previous 51 plus 4 collision/UI regressions).

Development service:

- Render id: `srv-dampdunf3r2c73arnjr0`;
- branch: `feature/restore-prototype-ux-parity`;
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`;
- auto-deploy: enabled.

Stable reference service remains untouched.

## Documentation decisions

- ADR-0004: general complete-applicable-baseline policy.
- ADR-0005: previous direct-extremes 30/30 reconstruction; superseded for playable sail-fatigue behavior.
- ADR-0006: current rule, +10 fatigue per sail point crossed; explicit PROJECT RULE / DELIBERATE DIVERGENCE.
- Player-facing UI uses neutral simulator terminology; technical source documentation retains source attribution.

## Major work still incomplete

Important remaining groups include morale/combat capability; remaining gunnery range/crew-service/fire dependencies; boarding/surrender/white flag/prizes; critical mast and dragging-mast rules; source-ambiguous magazine/captain criticals; four helm-damage states; five-level fire loop; scoring/end/fear; signals; exact wind-change/visibility; court-martial; and explicit time/turn conventions.

## Next concrete task

Unless user testing exposes another regression, the next coherent baseline slice is the morale / surrender / boarding dependency chain:

1. implement exact morale loss/recovery triggers with unambiguous thresholds;
2. implement surrender checks and one-turn white-flag state;
3. implement boarding eligibility, ratio modifiers, casualties and crew-quality/fatigue effects;
4. implement capture, prize-crew requirements and recapture behavior;
5. add deterministic tests before marking those rows verified;
6. continue afterward with critical mast/dragging-mast, four helm-damage states and the fire loop.

## Branch discipline

- `main`: do not develop here;
- `develop/historical-simulator`: canonical integration/recovery branch;
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft;
- `archive/prototype-v1`: immutable original prototype reference.
