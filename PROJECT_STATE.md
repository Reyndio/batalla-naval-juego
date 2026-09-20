# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**.

Current active-branch documentation head recorded at handoff: `cece7aa1445c75baa00880cdce92fa385a08d169`.
Current verified mechanical merge commit: `828fe30730445fb20e895a46fdfa292036b7d571`.

**Fresh-chat rule:** switch conceptually to `feature/restore-prototype-ux-parity` before inspecting or changing implementation. Read that branch's `PROJECT_STATE.md` and `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`. Do not treat this canonical snapshot as the current implementation.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

The 2v2 remains a development/regression scenario for historical ship data, multi-ship control and shared mechanics. It is not the final fleet architecture.

## Immutable / stable references

- Frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`.
- Stable/default `main` remains the discovery/stable branch.
- Stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.
- The stable working game remains the minimum functional behavior floor during migration.

## Historical 2v2 ship set

Selected October 1805 configurations:

### Royal Navy
- HMS Bellerophon: 28×32-pdr, 28×18-pdr, 18×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; action complement 522.
- HMS Conqueror: 28×32-pdr, 30×18-pdr, 16×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; action complement 573.

### Real Armada
- Montañés: 28×36-lb, 30×18-lb, 8×8-lb, 10×30-lb obuses; 76 principal pieces; complement 749.
- Bahama: 28×24-lb, 30×18-lb, 10×8-lb, 6×30-lb obuses, 4×24-lb obuses; 78 principal pieces; complement 689; 702 retained as a documented secondary-source discrepancy.

National-side rule remains fixed: one coherent navy per side.

## Mandatory Velmad v1.2 parity gate

ADR-0004 governs implementation order:

1. inventory every applicable explicit Velmad mechanic;
2. reproduce its stated percentages, thresholds, dependencies and state transitions;
3. add deterministic tests;
4. only then mark that row VERIFIED;
5. complete applicable Velmad baseline before replacing/improving it;
6. later changes/additions require strong historical/technical/physical evidence and explicit documentation.

The authoritative release checklist on the active branch is:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

Algorithms the manual explicitly omits because the original computer automated them must not be invented and labelled Velmad.

## Prototype interaction parity retained

The active branch still includes the restored usable floor from the stable prototype: recognizable ships, NV/PV/MV/TV, progressive sail changes, movement shadow/path, helm controls, explicit broadside fire, target/aim/section/ammunition controls, pan/zoom/recenter/fleet view, explicit start, turn clock, timeout, pause/resume, independent orders, historical guns, gun dismounting, mast/rig damage, rudder damage, rakes, collisions, ammunition state and confirmation/reset workflow.

PR #2 remains **draft**. Do not merge it merely for convenience.

## Velmad progress completed 2026-09-20

A child implementation branch `feature/velmad-hull-fatigue-parity` was merged into the active validation branch through PR #4.

### Hull 0 / Hull 1 / sinking — VERIFIED

The former `hull == 0 -> sunk/out` shortcut has been replaced and tested:

- Hull 0 remains operational with Velmad restrictions;
- uncaptured Hull-0 ship has exact 10% per-turn chance to begin sinking;
- actual sinking is the out-of-combat transition;
- Hull 0/1 speed max 70%;
- Hull 0 cannot use lower/main battery; Hull 1 can;
- lower-deck loss is derived from the actual historical gun fit;
- pump/repair 0→1 allowed at fatigue <=100, cost +20 fatigue;
- minimal player damage-control action added;
- unsupported old automatic extra hull-destruction casualties removed.

Compliance matrix section 15 is **VERIFIED**.

### Fatigue — advanced, still PARTIAL

Implemented/tested unambiguous values include:

- one broadside +10%; both broadside rule +30%;
- making full sail +30%;
- collect all sail / no sail +40%;
- no sail to few/medium +20%;
- collisions 60/40/0 by full/medium-or-few/no sail;
- idle recovery 10%, or 20% when fatigue >80;
- shooting effectiveness/eligibility now uses crew quality;
- +10 cost hooks for double-shot reload, firefighting and cutting party.

The translated `Remove all sailing: 30%` wording remains source-ambiguous and is not guessed. Dependent fire/cut/double-shot/boarding systems remain incomplete, so section 2 remains PARTIAL.

### Crew quality — shooting portion implemented, row still PARTIAL

All four Velmad levels exist and exact firing effects are tested:

- Beginner: 6% penalty per 10 fatigue, may fire through 100%;
- Normal: 5%, through 100%;
- Veteran: 4%, may fire with 120%;
- Elite: 3%, may fire with 120%.

Manoeuvre properties are represented but deliberately not applied to the provisional helm model until exact Velmad class/rudder-history mechanics are implemented. Boarding quality effects await boarding. Section 7 remains PARTIAL.

## Validation / deployment

Active mechanical merge `828fe30730445fb20e895a46fdfa292036b7d571` deployed successfully to Render service `batalla-naval-2v2-parity` via deploy `dep-danmi3eq1p3s73cj88jg` and reached `live`.

The service build command is `npm install && npm test`, so the full suite completed successfully before deployment.

Current suite after this slice: **28 tests, 0 failed** — the previous 19 plus 9 deterministic Velmad Hull 0 / fatigue / crew tests.

Development service:

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- auto-deploy: enabled

Stable reference service remains untouched.

## UI direction

Target remains a full tactical canvas with compact permanent primary orders and collapsible/contextual secondary information. Own-ship context should host damage control/special actions; enemy exact internal state should eventually respect observability. The Hull-0 repair action was added minimally without starting the unrelated layout redesign.

## Major Velmad systems still incomplete

Use the compliance matrix as authoritative. Important remaining groups include morale, vessel classes/speed thresholds, exact Velmad manoeuvring and tacking, full ammunition/loading/distance rules, windward/leeward shooting, carronades, boarding/surrender/white flag/prizes, critical mast and dragging-mast rules, fire, four helm-damage states, scoring/end conditions/signals/wind/visibility/court-martial/time conventions.

## Next concrete task

The next coherent dependency slice is:

1. implement Velmad vessel-class dependency data for the pilot ships;
2. replace provisional helm behavior with the exact one/two-point rudder-history and class probabilities;
3. wire Beginner/Normal/Veteran/Elite manoeuvre effects into that model;
4. implement the Velmad tacking stop/exit rule;
5. add deterministic tests before marking corresponding manoeuvring/crew-quality subparts VERIFIED;
6. continue fatigue-dependent actions through their owning systems rather than inventing shortcuts.

Do not introduce new realism refinements until the applicable Velmad baseline is complete.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable original-prototype reference.

A new chat should never ask the user to restate project history when GitHub is available.
