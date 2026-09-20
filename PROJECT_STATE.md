# PROJECT STATE

Last updated: 2026-09-20

## Branches

Canonical integration branch: `develop/historical-simulator`.

Active implementation/validation branch: `feature/restore-prototype-ux-parity`.

PR #2 — `Restore prototype interaction parity in historical 2v2 pilot` — remains **draft**. Do not merge it merely for convenience; mechanical and user-facing validation are still active gates.

Latest validated playable implementation head: `fef4b4e5bff54a8370a2365b28e5a3518eaa115b`.
Latest sail-fatigue implementation commit: `a29741a112488dab0a33c1c804f05e52c6fde0f3`.
ADR-0006 commit: `5cb8b9081a889e40deebf3e39232f463243bc48e`.
ADR-0007 is the current inertia / raking-geometry decision.

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

The playable interface does not display the baseline product name. Internal research documents, ADRs, compliance files and source-attribution material keep source names where needed for provenance and auditability.

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

## Translational inertia — added 2026-09-20

Live testing correctly identified that movement still changed translational speed instantaneously. This was incompatible with the Historical 1v1 milestone requirement for inertia and with period seamanship's repeated concept of a vessel retaining or requiring `way`.

`src/inertia-model.js` now adds a persistent two-dimensional motion vector:

- the ordinary sail/wind/class/hull/rig/rudder model still computes the commanded displacement;
- actual motion approaches that commanded vector progressively rather than snapping to it;
- going to `NV` does **not** stop a moving ship instantly;
- residual way decays over successive turns;
- a ship starting without way accelerates progressively;
- heading changes no longer redirect the whole translation instantaneously, because previous motion is carried into the new turn;
- class response is slower for larger vessels and faster for smaller vessels;
- current third-class response coefficient is `0.40` per turn;
- after a collision only 25% of the previous motion vector is carried into the next turn;
- the movement shadow uses the same inertia model, so the player sees the inertial destination before confirming.

This is **PROJECT-RECONSTRUCTION**, not a literal recovered baseline algorithm. The baseline manual explicitly omits the detailed computer movement calculation. The rationale and historical evidence are recorded in `docs/decisions/ADR-0007-INERTIA_AND_RAKING_GEOMETRY.md`.

Leeway, heel, sea-state response and quantitative hydrodynamic calibration remain future work.

## Raking geometry — corrected 2026-09-20

The former rake detector only required the attacker to lie inside the target's +/-15° bow/stern cone. That allowed an oblique partial-battery geometry to receive a bow/stern rake multiplier.

`src/raking-geometry.js` now requires a T-like geometry:

1. attacker within +/-15° of the defender's bow or stern longitudinal axis; and
2. ship headings approximately perpendicular, within +/-15° of 90°.

Therefore a broadside fired approximately down the target's long axis from ahead/astern receives the rake classification; an oblique L-like/diagonal position does not.

Deterministic tests verify both a true stern-rake T position and an oblique position in the same stern cone that must remain an ordinary shot.

## Collision review — corrected 2026-09-20

The old collision code only tested geometry after movement, allowing ships to cross visually during simultaneous movement and finish apart without consequences.

`src/collision-guard.js` provides swept trajectory collision detection across the actual movement path. With inertia installed before the collision layer, the sweep now follows the inertial trajectory rather than the instantaneous commanded endpoint.

- bow/centre/stern collision volumes are checked throughout the path;
- a mid-turn hit stops both ships at first detected contact;
- hull/rigging/crew damage and sail-dependent fatigue are applied;
- stern contacts retain rudder-damage risk;
- endpoint-only inherited collision geometry is reduced inside the inertia layer so the swept detector owns the meaningful physical contact path;
- collision fatigue remains outside idle-recovery processing.

## Tactical readability — corrected 2026-09-20

- selected target gets a red `OBJETIVO` ring;
- selected own ship gets a pulsing/dashed red `APUNTADO` ring when one or more enemies target it;
- force-status cards receive matching emphasis;
- Babor/Estribor buttons remain visibly selected;
- selected firing side is marked on the ship;
- overlays follow pan, zoom, fit-fleet, recenter, reset/start and the `C` shortcut.

## Validation / deployment

Latest validated implementation commit: `fef4b4e5bff54a8370a2365b28e5a3518eaa115b`.

Render deploy: `dep-dao3lefavr4c73atgk1g` — **live**.

The service build command is `npm install && npm test`; therefore the complete repository suite passed before deployment.

Validated suite: **60 tests, 0 failed** (previous 55 plus 5 inertia/raking regressions).

Development service:

- Render id: `srv-dampdunf3r2c73arnjr0`;
- branch: `feature/restore-prototype-ux-parity`;
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`;
- auto-deploy: enabled.

Stable reference service remains untouched.

## Documentation decisions

- ADR-0004: general complete-applicable-baseline policy.
- ADR-0005: previous direct-extremes 30/30 reconstruction; superseded for playable sail-fatigue behavior.
- ADR-0006: current +10 fatigue per sail point crossed; explicit PROJECT RULE / DELIBERATE DIVERGENCE.
- ADR-0007: persistent translational inertia as project reconstruction and strict T-like raking geometry.
- Player-facing UI uses neutral simulator terminology; technical source documentation retains source attribution.

## Major work still incomplete

Important remaining groups include morale/combat capability; remaining gunnery range/crew-service/fire dependencies; boarding/surrender/white flag/prizes; critical mast and dragging-mast rules; source-ambiguous magazine/captain criticals; four helm-damage states; five-level fire loop; scoring/end/fear; signals; exact wind-change/visibility; court-martial; explicit time/turn conventions; leeway; heel; and deeper sailing calibration.

## Next concrete task

User-facing validation of inertia/collision/raking now takes priority. Unless that exposes another regression, the next coherent baseline slice remains the morale / surrender / boarding dependency chain, followed by critical mast/dragging-mast, four helm-damage states and fire.

## Branch discipline

- `main`: do not develop here;
- `develop/historical-simulator`: canonical integration/recovery branch;
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft;
- `archive/prototype-v1`: immutable original prototype reference.
