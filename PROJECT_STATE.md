# PROJECT STATE

Last updated: 2026-09-20

## Canonical branch

`develop/historical-simulator`

Active validation branch: `feature/restore-prototype-ux-parity`

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

The Historical 1v1 Simulator remains the first polished milestone. The historical 2v2 remains a development/regression scenario used to validate real ship data, multi-ship state and shared mechanics.

## Current status

- Frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`.
- Stable/default `main` remains untouched by historical-simulator development.
- Canonical integration branch remains `develop/historical-simulator`.
- Stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, branch `main`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.
- PR #1, the first four-ship vertical slice, was merged into `develop/historical-simulator`.
- PR #2, `Restore prototype interaction parity in historical 2v2 pilot`, remains **draft** pending user-facing parity acceptance.

## Mandatory Velmad v1.2 parity gate

Velmad v1.2 is now an **implementation-completeness gate**, not merely a general inspiration.

Before the simulator may replace, rebalance, simplify or extend a Velmad rule, it must first reproduce **every applicable mechanic explicitly stated in the Velmad v1.2 manual**, with its stated values, thresholds, state transitions and interactions, and have tests demonstrating that behavior.

Only after complete applicable parity is reached may an individual Velmad rule be changed. Any change requires strong historical, technical or physical evidence and an explicit documented decision. New mechanics beyond Velmad require the same evidence discipline and must be identified as additions.

This is formalized in:

- `docs/decisions/ADR-0004-complete-velmad-parity-before-divergence.md`
- `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

The compliance matrix is the authoritative checklist for this gate.

Important source limitation: the Velmad v1.2 manual explicitly says detailed movement and combat damage-calculation algorithms were omitted because they were automated by the computer. Those algorithms must not be invented and labelled as Velmad; the stable implementation, archived behavior and later research must be separately documented as evidence.

## Stable prototype parity rule

The working `batalla-naval-juego-1` build remains the **minimum functional behavior floor** during migration.

No mechanic already present in that stable build may disappear silently. It may be retained, adapted to historical ship data, or deliberately superseded by an evidence-backed model, but omission is a regression.

Detailed inventory: `docs/reports/STABLE_PROTOTYPE_MECHANICS_PARITY.md`.

Historical adaptation does not preserve generic values such as 52 guns per broadside or 875 crew. The mechanic is preserved while those generic values are replaced by the selected dated historical ship records.

## Historical 2v2 ship set

Selected October 1805 configurations:

- **Royal Navy**
  - HMS Bellerophon: 28×32-pdr, 28×18-pdr, 18×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; working action complement 522.
  - HMS Conqueror: 28×32-pdr, 30×18-pdr, 16×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; working action complement 573.
- **Real Armada**
  - Montañés: 28×36-lb, 30×18-lb, 8×8-lb, 10×30-lb obuses; 76 principal pieces; working complement 749.
  - Bahama: 28×24-lb, 30×18-lb, 10×8-lb, 6×30-lb obuses, 4×24-lb obuses; 78 principal pieces; working complement 689, with 702 retained as a documented secondary-source discrepancy.

National-side rule remains fixed: one coherent navy per side.

## Parity restoration currently implemented on PR #2

### Match lifecycle

- explicit pre-battle configuration;
- **Iniciar partida** button;
- configurable turn duration;
- visible turn countdown;
- timeout automatically resolves the turn;
- pause/resume;
- confirmation of both human ships before manual turn resolution;
- confirmations reopen after each resolved turn;
- turn report/log;
- return-to-configuration/reset path;
- short movement animation between turns.

### Navigation / control

- NV/PV/MV/TV;
- progressive sail-state changes;
- rudder -4..+4;
- stable-prototype sail-dependent rudder change and amplitude restrictions;
- damaged-rudder restriction;
- projected movement shadow;
- wind direction and strength;
- map pan, zoom, recenter and fleet view;
- keyboard controls W/S/A/D/Q/E/P/C/Tab.

### Crew / fatigue

Independent per ship:

- historical crew complement;
- casualties;
- fatigue accumulation and recovery;
- current prototype experience handling;
- fatigue penalty to combat effectiveness.

**This is not yet Velmad-complete**: the exact Beginner/Normal/Veteran/Elite table and all Velmad fatigue costs/recovery rules remain to be reproduced.

### Artillery / damage

Independent per ship and per side:

- historical guns-per-broadside instead of generic `52/52`;
- operational Babor/Estribor gun counts;
- hull impacts can dismount guns on the struck side;
- lost guns reduce later broadside strength;
- full / forward-half / aft-half fire sections;
- hull / rigging aim;
- loaded ammunition separate from ammunition selected for the next load;
- round shot, grape and double shot;
- three independent mast states: fore, main and mizzen;
- mast damage/fall and mast-fall casualties;
- hull/rig damage affecting speed efficiency;
- rudder damage;
- bow and stern rakes;
- collision damage including hull, rigging, casualties and possible rudder effects;
- current pilot sunk/out-of-combat state.

Velmad-supported double-shot effects are used where the stable prototype was incomplete: increased hull effect and 50% more artillery dismounting.

**Critical correction still required:** the current pilot shortcut `hull == 0 -> sunk/out` is not Velmad-compliant. Under Velmad, hull 0 remains operational with penalties, has a 10% per-turn risk to begin sinking, cannot use the first battery, and can be pumped/repaired to hull 1 for +20% fatigue subject to the manual's fatigue condition.

## User-interface direction

The battle area should move toward a full-screen tactical canvas rather than permanent large side panels.

Target UI architecture:

- principal orders remain permanently visible in a compact top bar, following the stable game / Velmad interaction concept;
- turn clock, wind and critical messages remain visible as compact HUD elements;
- secondary panels are floating/collapsible and do not permanently consume sea area;
- clicking a ship opens contextual ship status;
- own-ship contextual status becomes the location for damage-control and special actions such as fire-fighting, cutting a dragging mast, hull-0 pumping/repair, boarding/capture actions, etc.;
- enemy ship information must eventually respect observability rather than expose internal exact values without justification.

## Velmad systems still missing or incomplete

The full matrix is authoritative; major missing/incomplete groups include:

- morale/combat capability and morale recovery;
- exact Velmad fatigue costs and four crew-quality levels;
- Velmad class-relative sailing and rigging thresholds;
- exact Velmad rudder-history/two-point manoeuvre probabilities;
- tacking rule;
- full four-ammunition model including bar/chain shot and exact double-shot loading restrictions;
- distance rules, sail-state shooting modifiers and crew-served-gun limits;
- windward/leeward shooting distributions;
- carronade distance contribution;
- boarding calculation;
- surrender and white-flag states;
- prize crews, captured-ship restrictions and recapture;
- exact hull 0/1 state machine;
- critical mast knockdown;
- tangled/dragging fallen mast and cutting party;
- magazine/fire/captain critical-impact rules;
- four helm-damage states;
- five-level fire system and fire transmission;
- end-of-battle disengagement/no-fire conditions;
- score/victory/fear mechanics;
- signals;
- exact wind-change probability and visibility;
- court-martial rule;
- explicit 5-minute turn / 75 m length conventions.

## Validation

Latest observed Render build before this documentation-only gate update:

- **19 tests passed, 0 failed**;
- historical side/data integrity;
- four independent ship states;
- side-safe targeting;
- long-run numerical integrity;
- AI-vs-AI battle completion;
- HTTP smoke checks;
- explicit start/clock/pause controls present;
- stable rudder constraints;
- progressive sail change;
- independent fatigue;
- hull-fire gun dismounting by struck side;
- mast/rig damage;
- loaded-vs-next ammunition state;
- confirmation reset after turn resolution;
- camera/shadow/rendering parity checks.

These tests demonstrate restored prototype behavior, **not complete Velmad v1.2 parity**.

## Development deployment

Current parity service:

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- build: `npm install && npm test`
- start: `npm start`
- auto-deploy: enabled

Stable reference service `batalla-naval-juego-1` remains untouched.

## Historical research / decision files

- `docs/research/HISTORICAL_SHIPS_2V2_CANDIDATE_SELECTION.md`
- `docs/research/HISTORICAL_SHIPS_2V2_CONFIGURATION_ENVELOPE.md`
- `docs/research/HISTORICAL_SHIPS_2V2_DATA_SPEC.md`
- `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`
- `docs/research/ships/BELLEROPHON_1805.md`
- `docs/research/ships/CONQUEROR_1805.md`
- `docs/research/ships/MONTANES_1805.md`
- `docs/research/ships/BAHAMA_1805.md`
- `docs/decisions/ADR-0001-velmad-baseline-and-historical-evidence.md`
- `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`
- `docs/decisions/ADR-0003-preserve-prototype-interaction-parity.md`
- `docs/decisions/ADR-0004-complete-velmad-parity-before-divergence.md`
- `docs/reports/HISTORICAL_2V2_PILOT_PLAYTEST.md`
- `docs/reports/STABLE_PROTOTYPE_MECHANICS_PARITY.md`

## Branch roles

- `archive/prototype-v1`: immutable historical snapshot.
- `main`: stable/default branch; also feeds `batalla-naval-juego-1`.
- `develop/historical-simulator`: canonical integration branch.
- `feature/restore-prototype-ux-parity`: current PR #2 validation branch and parity deployment.

## Next task

1. Use `VELMAD_V1_2_MECHANICS_COMPLIANCE.md` as the implementation backlog and release gate.
2. Fix the most material contradictions first, beginning with hull 0/1 and the current automatic-sinking shortcut.
3. Implement Velmad systems in coherent tested slices rather than adding new speculative realism.
4. Continue checking the stable `batalla-naval-juego-1` interaction floor so no existing useful behavior regresses.
5. Keep PR #2 draft while this baseline restoration is still incomplete.
6. After full applicable Velmad parity, evaluate proposed historical improvements one by one under ADR-0001, with evidence and explicit decisions.
7. Perform controlled dependency remediation before any production promotion.
