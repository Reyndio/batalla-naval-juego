# PROJECT STATE

Last updated: 2026-09-20

## Branches

Canonical integration branch: `develop/historical-simulator`.

Active implementation/validation branch: `feature/restore-prototype-ux-parity`.

PR #2 — `Restore prototype interaction parity in historical 2v2 pilot` — remains **draft**. Do not merge it merely for convenience; mechanical and user-facing validation are still active gates.

Latest validated playable implementation/test head: `60c934d3595ab1d0f54584bfa5db16149bc61be1`.
Sail-fatigue implementation: `a29741a112488dab0a33c1c804f05e52c6fde0f3`.
ADR-0006: sail fatigue per point.
ADR-0007: inertia / strict T-like raking geometry.
ADR-0008: restored prototype rudder, section-specific collision response, collision mast entanglement, full-sail ignition risk and hidden enemy fatigue.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The historical 2v2 remains the active development/regression scenario for real ship data, independent ship orders and shared mechanics. It is not the final fleet architecture.

## Stable / immutable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains untouched by normal historical-simulator development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`;
- the stable game remains the minimum functional behavior floor during migration.

## Source / baseline policy

ADR-0004 remains the general technical source policy: preserve and test applicable explicit baseline rules, and do not invent omitted algorithms and present them as source-derived.

The playable interface does not display the baseline product name. Internal research/ADR/compliance documents retain source attribution for provenance.

Several current playable rules are deliberate owner-approved divergences/reconstructions and therefore must not be presented as literal baseline parity: sail-change fatigue (ADR-0006), translational inertia and strict T geometry (ADR-0007), and the restored stable-prototype helm plus collision/fire additions (ADR-0008).

Authoritative mechanical checklist remains:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

## Historical 2v2 ship set

October 1805 configurations:

- Royal Navy: HMS Bellerophon and HMS Conqueror;
- Real Armada: Montañés and Bahama.

All four are documented 74-gun / 74-gun-class two-deckers and resolve to third class in the baseline class dependency model.

## Current playable behavior

### Sail-change fatigue — PROJECT RULE / DELIBERATE DIVERGENCE

States are ordered `NV → PV → MV → TV`; every adjacent point crossed costs +10% fatigue. Direct changes therefore cost 10/20/30 according to distance, symmetrically in either direction. Progressive changes pay +10 per one-point change on each turn.

### Hull / sinking

Verified current behavior includes Hull 0 remaining operational, exact 10% per-turn sinking trigger, Hull 0/1 70% speed cap, lower-battery restriction at Hull 0, and pump/repair 0→1 at fatigue <=100 for +20 fatigue.

### Playable helm — restored stable-prototype behavior

ADR-0008 restores the helm that exists in `archive/prototype-v1` as the current player-facing/runtime steering model:

- positions `-4,-3,-2,-1,0,+1,+2,+3,+4`;
- at NV/PV: 1=10°, 2=20°, 3=30°, T/4=45°;
- MV steering angle = 70% of those values;
- TV steering angle = 40%;
- maximum helm-position change per turn: NV/PV 4, MV 3, TV 2;
- maximum absolute helm: NV/PV 4, MV 4, TV 3;
- therefore `±4` is never available at TV; `±3` can be reached progressively from `±2` but not jumped to from centred helm;
- damaged rudder remains restricted to `±1`.

The source-manual 0/1/2 rudder abstraction remains preserved/tested as source behavior, but it is **not** the current player-facing helm semantics. Any older state line describing the playable runtime as 0/1/2 is superseded by ADR-0008.

The current head-to-wind tacking stop/departure layer remains active on top of the restored control surface pending further user validation.

### Translational inertia — PROJECT-RECONSTRUCTION

`src/inertia-model.js` retains a persistent two-dimensional motion vector. Sail/wind/class/hull/rig/helm produce a commanded vector; actual translation approaches it progressively. A ship going to NV keeps residual way, acceleration is progressive, and heading changes do not instantly redirect the whole previous motion vector.

Current third-class response coefficient is `0.40` per turn. This is a project calibration because the source manual omits the detailed movement algorithm.

### Raking geometry

A rake requires both:

1. attacker within ±15° of the defender's bow/stern longitudinal axis; and
2. headings approximately perpendicular, within ±15° of 90°.

This prevents oblique L/diagonal geometries from receiving a rake multiplier while retaining true T-like bow/stern rakes.

### Collision response — revised 2026-09-20

Swept collision detection remains active across the full inertial trajectory. On first contact, the struck vessel's retained momentum now depends on the impacted section:

- **BOW**: 0% retained — complete stop at collision;
- **CENTER**: 25% retained — 75% speed reduction;
- **STERN**: 50% retained — 50% speed reduction;
- **exactly astern** (current 5° tolerance): 100% retained — the impact itself neither raises nor lowers forward speed.

Stern/rudder damage risk is now alignment-based rather than sail-difference-only: it rises continuously from 25% toward **75% at exact astern alignment**.

Collision damage still affects hull, rigging and crew and applies sail-dependent collision fatigue.

### Collision mast fall / entanglement / carpenters

The impacted mast zone follows the stable prototype mapping: bow→foremast, centre→mainmast, stern→mizzenmast.

Current collision-specific project reconstruction:

- a mast at/below 30% health after collision damage is critically weak;
- it gets a 50% collision-fall check;
- if it falls in this collision, it falls toward the colliding vessel;
- current entanglement chance is 75%;
- entangled ships have zero translational movement until cleared;
- a carpenter/cutting party must be ordered;
- cutting costs +10% fatigue for that turn and has exact 50% success.

The +10/50% cutting rule follows the source fallen-mast rule; the 30% weak-health threshold and 75% collision-entanglement probability are project reconstruction values under ADR-0008. The complete general dragging-mast/wind-side subsystem remains incomplete.

### Gunnery / full sail

The implemented ammunition/loading/wind/carronade slice remains active. At full sail:

- upperworks long guns and carronades remain excluded from available firepower;
- firing accuracy receives the source-defined penalty equivalent to +10% fatigue;
- after an actual full-sail broadside there is now a 20% ignition check;
- owner-approved project rule: when wind enters through the same side being fired, current ignition probability rises to **30%**.

The 30% wind-side value is an explicit PROJECT-RECONSTRUCTION calibration, not a source claim.

A successful ignition now creates `fireLevel=1` / `onFire=true` state and is visible to the player. The complete five-level fire propagation/damage/fire-fighting loop is **not yet complete**.

### Enemy-information privacy

The player no longer sees exact enemy fatigue in force-status cards. Enemy exact fatigue values in blocked-fire report lines are also scrubbed to a qualitative fatigue message. Enemy fatigue remains fully simulated internally.

### Tactical readability

- selected target gets a red `OBJETIVO` ring;
- selected own ship gets a pulsing/dashed red `APUNTADO` ring when targeted by enemy ships;
- force-status cards receive matching emphasis;
- Babor/Estribor buttons remain visibly selected;
- selected firing side is marked on the ship;
- overlays follow pan, zoom, fit-fleet, recenter and reset/start camera operations.

## Validation / deployment

Latest validated implementation/test head: `60c934d3595ab1d0f54584bfa5db16149bc61be1`.

Render deploy: `dep-dao4msnavr4c73auepdg` — **live**.

The service build command is `npm install && npm test`; therefore the complete repository suite passed before deployment.

Validated suite: **76 tests, 0 failed**.

New deterministic coverage includes:

- restored nine-position prototype helm and exact PV/NV/MV/TV turn/change/amplitude rules;
- TV `±4` prohibition and progressive access to `±3`;
- damaged-rudder `±1` restriction;
- collision momentum retention for bow/centre/stern/exact-astern;
- exact-astern 75% rudder risk and decreasing risk off-axis;
- critically weak collision mast fall toward the collider, 75% entanglement and 50% carpenter release;
- inertia consuming each collision-retention state and cancelling motion while entangled;
- 20% ordinary vs 30% wind-side full-sail ignition calculation;
- actual logged full-sail broadside ignition to level 1;
- no fire roll when no broadside actually fired;
- browser script wiring, hidden enemy fatigue and damage-control UI parsing.

Development service:

- Render id: `srv-dampdunf3r2c73arnjr0`;
- branch: `feature/restore-prototype-ux-parity`;
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`;
- auto-deploy: enabled.

Stable reference service remains untouched.

## Documentation decisions

- ADR-0004: general source-baseline policy.
- ADR-0005: prior direct-extremes 30/30 sail reconstruction; superseded by ADR-0006 for playable sail fatigue.
- ADR-0006: +10 fatigue per sail point crossed.
- ADR-0007: persistent translational inertia and strict T-like raking geometry.
- ADR-0008: restored prototype helm; section-specific collision momentum; alignment-based stern/rudder damage; weak collision mast fall/entanglement; full-sail fire risk; enemy fatigue privacy.
- Player-facing UI uses neutral simulator terminology; technical source documentation retains source attribution.

## Major work still incomplete

Important remaining groups include morale/combat capability; source-omitted gunnery range/crew-service details; boarding/surrender/white flag/prizes; complete critical-mast and ordinary dragging-mast rules; source-ambiguous magazine/captain criticals; four helm-damage states; complete five-level fire loop; scoring/end/fear; signals; exact wind-change/visibility; court-martial; explicit time/turn conventions; leeway; heel; and deeper sailing/inertia calibration.

## Next concrete task

Immediate priority is user validation of:

1. prototype helm feel at PV/MV/TV, especially progressive TV access to ±3 and no ±4;
2. collision stop/retention by impact section and exact-astern behavior;
3. weak-mast fall/entanglement/carpenter release;
4. full-sail firing accuracy/ignition behavior and enemy-information hiding.

After that validation, continue the morale / surrender / boarding dependency chain, followed by the remaining mast, helm-damage and fire systems.

## Branch discipline

- `main`: do not develop here;
- `develop/historical-simulator`: canonical integration/recovery branch;
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft;
- `archive/prototype-v1`: immutable original prototype reference.
