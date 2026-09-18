# PROJECT STATE

Last updated: 2026-09-18

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
- Stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, branch `main`, current reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.
- Velmad v1.2 remains the foundational historical-mechanics reference.
- PR #1, the first four-ship vertical slice, was merged into `develop/historical-simulator`.
- PR #2, `Restore prototype interaction parity in historical 2v2 pilot`, remains **draft** pending visual/user acceptance.

## Stable mechanics parity rule

The working `batalla-naval-juego-1` build is now the **minimum functional behavior floor** during migration to the historical simulator.

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
- damaged-rudder ±1 restriction;
- projected movement shadow;
- wind direction and strength;
- late-battle wind-change mechanic;
- map pan, zoom, recenter and fleet view;
- keyboard controls W/S/A/D/Q/E/P/C/Tab.

### Crew / fatigue

Independent per ship:

- historical crew complement;
- casualties;
- fatigue accumulation and recovery;
- NOVATA/NORMAL/VETERANA experience;
- experience-dependent fatigue thresholds;
- fatigue penalty to combat effectiveness.

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
- sunk/out-of-combat state.

Velmad-supported double-shot effects are used where the stable prototype was incomplete: increased hull effect and 50% more artillery dismounting are treated as evidence-backed restoration, not arbitrary balance bonuses.

## User-interface parity restored

- recognizable top-down hull/deck/masts/sails;
- ships rotate without deforming;
- current vs ordered state styling;
- movement shadow and projected path;
- visible firing arcs;
- tactical hover/range information;
- right-drag map panning and wheel zoom;
- explicit Babor/Estribor firing;
- target, aim, section and ammunition controls;
- per-ship status for hull, three masts, guns by side, crew, fatigue, experience, rudder, speed efficiency, ammunition, sail and heading.

## Validation

Latest observed Render build after parity tests:

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

## Historical research files

- `docs/research/HISTORICAL_SHIPS_2V2_CANDIDATE_SELECTION.md`
- `docs/research/HISTORICAL_SHIPS_2V2_CONFIGURATION_ENVELOPE.md`
- `docs/research/HISTORICAL_SHIPS_2V2_DATA_SPEC.md`
- `docs/research/ships/BELLEROPHON_1805.md`
- `docs/research/ships/CONQUEROR_1805.md`
- `docs/research/ships/MONTANES_1805.md`
- `docs/research/ships/BAHAMA_1805.md`
- `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`
- `docs/reports/HISTORICAL_2V2_PILOT_PLAYTEST.md`
- `docs/reports/STABLE_PROTOTYPE_MECHANICS_PARITY.md`

## Known limitations / next historical work

Parity restoration does **not** mean the inherited stable mechanics are the final historical model. Current shared constants remain provisional where not supported by stronger evidence.

Still to be developed or substantially deepened for Milestone 1:

- evidence-backed sailing physics: inertia, leeway, heel, tacking/wearing and ship-specific qualities;
- final historical artillery/penetration/dispersion model;
- component-level batteries and damage beyond the restored stable behavior;
- smoke and visibility;
- morale;
- fire and flooding;
- surrender, capture and boarding;
- deeper crew-task allocation and fatigue model;
- final Human vs Human / Human vs AI / AI vs AI scenario architecture.

## Branch roles

- `archive/prototype-v1`: immutable historical snapshot.
- `main`: stable/default branch; also feeds `batalla-naval-juego-1`.
- `develop/historical-simulator`: canonical integration branch.
- `feature/restore-prototype-ux-parity`: current PR #2 validation branch and parity deployment.

## Next task

1. visually playtest the current parity deployment;
2. fix any remaining mechanic or interaction that exists in `batalla-naval-juego-1` but is absent or degraded;
3. keep PR #2 draft until that user-facing parity gate passes;
4. after parity acceptance, merge to `develop/historical-simulator` and continue shared historical-engine separation without dropping the restored mechanics;
5. perform controlled dependency remediation before any production promotion.
