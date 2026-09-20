# PROJECT STATE

Last updated: 2026-09-20

## Canonical branch

`develop/historical-simulator`

Active validation branch: `feature/restore-prototype-ux-parity`

Current active-branch head after the Velmad Hull 0 / fatigue slice: `828fe30730445fb20e895a46fdfa292036b7d571`.

PR #2 — `Restore prototype interaction parity in historical 2v2 pilot` — remains **draft**. Do not merge it merely for convenience; the Velmad-completeness gate and user-facing validation remain open.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

The historical 2v2 remains a development/regression scenario for real ship data, multi-ship state, interaction parity and shared mechanics. It is not the final fleet architecture.

## Stable / immutable references

- Frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`.
- Stable/default `main` remains untouched by historical-simulator development.
- Canonical integration branch: `develop/historical-simulator`.
- Stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, branch `main`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.
- Stable game remains the minimum functional behavior floor during migration.

## Mandatory Velmad v1.2 parity gate

ADR-0004 remains governing policy: reproduce every applicable explicit Velmad v1.2 mechanic, exact stated values/thresholds/transitions/interactions, and deterministic tests before replacing, simplifying, rebalancing or extending it.

Authoritative matrix:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

Detailed movement and combat-damage algorithms explicitly omitted by the Velmad manual must not be invented and labelled Velmad. Stable/original behavior may be used only as a documented reconstruction reference until stronger evidence exists.

## Historical 2v2 ship set

Selected October 1805 configurations:

### Royal Navy
- HMS Bellerophon: 28×32-pdr, 28×18-pdr, 18×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; working action complement 522.
- HMS Conqueror: 28×32-pdr, 30×18-pdr, 16×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; working action complement 573.

### Real Armada
- Montañés: 28×36-lb, 30×18-lb, 8×8-lb, 10×30-lb obuses; 76 principal pieces; working complement 749.
- Bahama: 28×24-lb, 30×18-lb, 10×8-lb, 6×30-lb obuses, 4×24-lb obuses; 78 principal pieces; working complement 689; 702 remains a documented secondary-source discrepancy.

National-side rule remains fixed: one coherent navy per side.

## Prototype interaction parity already restored on PR #2

The active branch retains:

- recognizable top-down hull/deck/masts/sails;
- NV/PV/MV/TV and progressive sail changes;
- movement shadow/projected path;
- restored prototype helm/control behavior pending later exact Velmad manoeuvre replacement;
- explicit Babor/Estribor fire;
- target, aim, section and ammunition controls;
- pan, zoom, recenter and fleet view;
- explicit **Iniciar partida**;
- configurable visible turn clock, timeout resolution and pause/resume;
- independent orders for both human ships;
- historical guns per broadside and operational guns by side;
- hull-hit gun dismounting on the struck side;
- independent mast/rig state and mast-fall casualties;
- rudder damage;
- bow/stern rakes;
- collision damage;
- loaded ammunition distinct from next ammunition;
- round shot, grape and double shot;
- confirmation reset after turn resolution.

## Velmad slice completed 2026-09-20

Temporary child branch `feature/velmad-hull-fatigue-parity` was merged to the active validation branch through PR #4. The active head is now `828fe30730445fb20e895a46fdfa292036b7d571`.

### Hull 0 / Hull 1 / sinking — VERIFIED

The former shortcut `hull == 0 -> sunk/out` is removed.

Implemented and deterministically tested:

- Hull 0 remains operational subject to restrictions;
- uncaptured Hull-0 ship has exactly 10% chance per turn to begin sinking;
- only actual `sinking` transition makes the vessel out of combat;
- Hull 0 and Hull 1 speed cap: 70%;
- Hull 0 cannot use the lower/main battery;
- Hull 1 restores that battery;
- lower-deck contribution is derived from each historical ship's actual lower-deck long-gun fit instead of a generic percentage;
- pumping/repair Hull 0→1 allowed at fatigue <=100%;
- repair cost exactly +20% fatigue;
- minimal player damage-control control exposes the 0→1 order without unrelated UI redesign;
- old automatic extra hull-destruction casualties were removed because they are not part of this Velmad rule.

Compliance matrix section 15 is now **VERIFIED**.

### Fatigue — advanced, still PARTIAL

Exact unambiguous Velmad values now encoded/tested:

- one broadside +10%;
- both broadsides rule +30% represented/tested;
- making full sail +30%;
- collect all sail / pass to no sail +40%;
- no sail to few/medium +20%;
- collision: full +60%, medium/few +40%, no sail +0%;
- normal idle recovery -10%;
- recovery when fatigue >80: -20%;
- +10 cost hooks for double-shot reload, fire-fighting party and cutting party;
- fatigue affects firing effectiveness and firing eligibility through the Velmad crew-quality table.

Not falsely marked complete:

- translated manual line `Remove all sailing: 30%` remains SOURCE-AMBIGUOUS and is not guessed;
- true simultaneous both-broadside execution is not yet a player action;
- fire-fighting, cutting-party and exact double-shot loading loops are separate incomplete Velmad systems;
- boarding fatigue effect awaits boarding.

Compliance matrix section 2 remains **PARTIAL**.

### Crew quality — shooting portion implemented, row still PARTIAL

All four Velmad levels now exist:

- Beginner / `NOVATA`: 6% firing penalty per 10% fatigue; may fire through 100%; two-point chance multiplier represented as 0.5.
- Normal: 5%; may fire through 100%.
- Veteran / `VETERANA`: 4%; may fire with 120%; veteran manoeuvre property recorded.
- Elite: 3%; may fire with 120%; elite all-rudder property recorded.

The exact firing penalties and 100/120 firing limits are implemented and tested. Crew-quality manoeuvre effects are intentionally not wired into the still-provisional restored-prototype helm model; they become active when the exact Velmad class/rudder-history manoeuvre rule is implemented. Boarding quality effects likewise await boarding.

Compliance matrix section 7 remains **PARTIAL**, with the shooting/fatigue subpart verified.

## Validation

Render deployment for active commit `828fe30730445fb20e895a46fdfa292036b7d571` reached **live** status on service `batalla-naval-2v2-parity` (`dep-danmi3eq1p3s73cj88jg`).

The service build command is `npm install && npm test`; therefore the full repository test suite completed successfully before the deployment went live.

Current suite: **28 tests, 0 failed**:

- 19 pre-existing historical/parity/HTTP tests retained;
- 9 new deterministic Velmad Hull 0 / fatigue / crew tests.

Additional local deterministic regression run during implementation also passed the core long-run and AI-vs-AI simulations before merge.

These tests prove the newly verified Hull 0 slice and preserved prototype behavior; they do **not** imply complete Velmad parity.

## Development deployment

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- current deployed commit: `828fe30730445fb20e895a46fdfa292036b7d571`
- build: `npm install && npm test`
- start: `npm start`
- auto-deploy: enabled

Stable reference service `batalla-naval-juego-1` remains untouched.

## UI direction

The fixed left/right layout remains provisional. Target remains:

- sea/canvas uses essentially full viewport;
- primary orders persist in compact top bar;
- secondary panels floating/collapsible;
- clicking a ship opens contextual identity/state/damage card;
- own-ship context hosts damage control/special actions;
- enemy exact internal information eventually respects observability.

The Hull-0 repair action was added minimally without starting the unrelated presentation overhaul.

## Major Velmad work still incomplete

Use the compliance matrix as authoritative backlog. Major groups still include:

- morale/combat capability;
- completion of fatigue-dependent action loops;
- vessel classes, exact class-relative sailing and rigging thresholds;
- exact Velmad rudder-history/two-point manoeuvre probabilities and crew-quality integration;
- tacking;
- bar/chain shot and exact double-shot loading sequence;
- distance/sail-state shooting modifiers and crew-served-gun limits;
- windward/leeward shooting distributions;
- carronade range contribution;
- boarding, surrender, white flag, prizes and recapture;
- critical mast knockdown and dragging/cutting fallen masts;
- critical magazine/captain rules;
- four helm-damage states;
- five-level fire/firefighting/transmission;
- remaining battle-end/scoring/fear rules;
- signals;
- exact wind-change/visibility rules;
- court-martial;
- explicit 5-minute turn / 75 m length conventions.

## Stable/current files to read before further work

On `feature/restore-prototype-ux-parity`:

- `docs/decisions/ADR-0001-velmad-baseline-and-historical-evidence.md`
- `docs/decisions/ADR-0003-preserve-prototype-interaction-parity.md`
- `docs/decisions/ADR-0004-complete-velmad-parity-before-divergence.md`
- `docs/reports/STABLE_PROTOTYPE_MECHANICS_PARITY.md`
- `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`
- `src/pilot2v2-core.js`
- `src/pilot2v2-ui.js`
- `pilot-2v2.html`
- `tests/pilot2v2-ux-parity.test.js`
- `tests/pilot2v2.test.js`
- `tests/velmad-hull-fatigue.test.js`

## Next concrete task

Continue the mandatory baseline systematically. The next coherent dependency slice is:

1. implement Velmad vessel-class dependency data for the four pilot ships;
2. replace the provisional helm rule with exact Velmad one/two-point rudder-history probabilities;
3. wire Beginner/Normal/Veteran/Elite manoeuvre effects into that exact model;
4. implement the Velmad tacking stop/exit rule;
5. add deterministic tests before marking manoeuvring/crew-quality subparts VERIFIED;
6. then continue the fatigue-dependent actions through their owning systems rather than inventing stand-alone shortcuts.

Do not introduce new realism refinements before the applicable Velmad baseline is complete.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable old prototype reference.
