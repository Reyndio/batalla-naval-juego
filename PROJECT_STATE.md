# PROJECT STATE

Last updated: 2026-09-20

## Branches

Canonical integration branch: `develop/historical-simulator`.

Active implementation/validation branch: `feature/restore-prototype-ux-parity`.

PR #2 — `Restore prototype interaction parity in historical 2v2 pilot` — remains **draft**. Do not merge it merely for convenience; mechanical and user-facing validation are still active gates.

Latest validated playable implementation/test head: `461af63c341d90393a49af556d2573e91e98078e`.
Latest active documentation before this state commit: `3a48d6a1042470e67c2de0d408a27ab158620593`.
ADR-0006: sail fatigue per point.
ADR-0007: inertia / strict T-like raking geometry.
ADR-0008: restored prototype rudder, collision response/entanglement, angle-sensitive full-sail ignition/fire loop and hidden enemy fatigue.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The historical 2v2 remains the active development/regression scenario for real ship data, independent ship orders and shared mechanics. It is not the final fleet architecture.

## Stable / immutable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains untouched by normal historical-simulator development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`;
- the stable game remains the minimum functional behavior floor during migration.

## Source / baseline policy

ADR-0004 remains the general technical source policy. Current playable deviations/reconstructions are explicit and must not be presented as literal source parity:

- ADR-0006 — +10 fatigue per sail point crossed;
- ADR-0007 — persistent translational inertia and strict T-like rake geometry;
- ADR-0008 — stable-prototype nine-position helm, collision physics/entanglement, angle-sensitive full-sail ignition and enemy-information privacy.

The playable interface does not display the baseline product name. Internal research/ADR/compliance documents retain source attribution for provenance.

Authoritative mechanical checklist:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

## Historical 2v2 ship set

October 1805 configurations:

- Royal Navy: HMS Bellerophon and HMS Conqueror;
- Real Armada: Montañés and Bahama.

All four are documented 74-gun / 74-gun-class two-deckers and resolve to third class in the source classification layer.

## Current playable behavior

### Sail-change fatigue

States `NV → PV → MV → TV`; every adjacent point crossed costs +10% fatigue. Direct changes cost 10/20/30 according to distance, symmetrically; progressive changes pay +10 per point/turn.

### Hull / sinking

Hull0 remains operational with its verified restrictions; uncaptured Hull0 has exact10% per-turn sinking trigger; Hull0/1 speed cap70%; lower battery unavailable at Hull0; pump0→1 at fatigue<=100 costs+20.

### Playable helm — stable-prototype parity

Current runtime/player helm follows `archive/prototype-v1` under ADR-0008:

- positions `-4,-3,-2,-1,0,+1,+2,+3,+4`;
- NV/PV: 1=10°, 2=20°, 3=30°, T/4=45°;
- MV effectiveness x0.7; TV x0.4;
- maximum position change per turn: NV/PV4, MV3, TV2;
- maximum absolute position: NV/PV4, MV4, TV3;
- TV never permits ±4; from centred helm it cannot jump directly to ±3, but from ±2 it can progress to ±3;
- damaged rudder remains limited to ±1.

The source 0/1/2-point abstraction remains preserved/tested as provenance, but is not the current player-facing control semantics. Head-to-wind tacking stop/departure remains layered over the restored control surface pending continued live validation.

### Translational inertia

Persistent2D motion vector; moving ships retain way when reducing sail, accelerate/decelerate progressively and do not instantly redirect all translation when heading changes. Current third-class response coefficient is0.40/turn. This is PROJECT-RECONSTRUCTION because the source movement algorithm is omitted.

### Raking geometry

Rake requires attacker within ±15° of defender bow/stern axis **and** headings within ±15° of perpendicular. Oblique L/diagonal geometry does not receive the rake multiplier.

### Collision response

Swept collision follows the inertial trajectory. Retained momentum of the struck vessel:

- bow0% — stop;
- centre25% — speed -75%;
- stern50% — speed -50%;
- exact astern within current5° tolerance100% — collision itself does not change forward speed.

Stern/rudder damage risk increases continuously with alignment from25% toward75% exactly astern.

### Weak mast / entanglement / carpenters

Collision zone mapping follows prototype: bow→foremast, centre→mainmast, stern→mizzenmast.

Current collision reconstruction:

- mast <=30% health after impact gets50% collision-fall check;
- collision-fallen mast falls toward colliding ship;
- 75% chance to leave both ships entangled;
- entangled ships have zero translational movement;
- carpenter/cutting action costs +10 fatigue and has exact50% success.

Ordinary non-collision dragging-mast/wind-side behavior remains incomplete.

### Full-sail firing and fires

At TV the existing source effects remain active: upperworks/carronade contribution excluded and accuracy penalty equivalent to +10 fatigue.

The source manual's flat20% full-sail ignition line is retained as provenance but deliberately replaced in the playable runtime by an angle-sensitive project rule:

- **10%** when wind is not entering through the firing side, defined as more than45° from the firing-side normal;
- **15%** when wind enters obliquely, more than15° and up to45° from that normal;
- **20%** when wind is nearly directly opposed to the broadside, within±15° of the firing-side normal.

The rule is symmetric for babor/estribor. The±15° and±45° boundaries are current project calibration tolerances and are deterministically tested.

The playable fire state/progression/control loop remains implemented:

- new fire starts L1; additional declaration +1;
- unattended fire +1 level/turn;
- fire-fighting action +10 fatigue/turn;
- control chance L1=50%, -10 percentage points per higher level;
- control success reduces1 if firing/changing sail, otherwise2;
- control failure:50% worsens one level /50% remains;
- L3:50 damage to hull or standing mast +33% explosion chance;
- L4:100 hull +100 mast damage, or mast portion redirected to hull when dismasted, +66% explosion chance;
- L5: crew abandonment / out of combat;
- explosion destroys vessel;
- fire transmits between entangled ships at10% × source fire level per turn.

### Enemy-information privacy

Exact enemy fatigue is hidden in force cards and blocked-fire report lines. Enemy fatigue remains fully simulated internally.

### Tactical readability

Target/threat red rings, persistent Babor/Estribor selection and red battery-side indicator remain active and follow camera movement.

## Validation / deployment

Implementation/test/documentation head `461af63c341d90393a49af556d2573e91e98078e` reached **live** through Render deploy `dep-dao87rff3r2c73ekj6og` after the complete repository test suite passed.

Current suite contains **87 tests** after adding three deterministic angle-sensitive ignition tests.

New coverage for the ignition recalibration includes:

- 10/15/20% risk tiers;
- exact ±15° direct-wind and ±45° side-entry boundaries;
- symmetric port/starboard behavior;
- actual full-sail ignition using the direct-wind20% tier.

Development service:

- Render id: `srv-dampdunf3r2c73arnjr0`;
- branch: `feature/restore-prototype-ux-parity`;
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`;
- auto-deploy: enabled.

Stable reference service remains untouched.

## Documentation decisions

- ADR-0004: general source-baseline policy.
- ADR-0005: prior direct-extremes sail reconstruction; superseded by ADR-0006.
- ADR-0006: +10 fatigue per sail point crossed.
- ADR-0007: persistent inertia and strict T-like rake geometry.
- ADR-0008: prototype helm; collision section momentum/rudder risk; collision mast entanglement; angle-sensitive full-sail ignition/fire control; hidden enemy fatigue.

## Major work still incomplete

Morale/combat capability; source-omitted gunnery base range/damage and crew-service details; boarding/surrender/white flag/prizes; general critical-mast/ordinary dragging-mast rules; ambiguous magazine/captain criticals; four source helm-damage states; unresolved external fire triggers tied to critical/dragging-mast mechanics; scoring/end/fear; signals; exact wind-change/visibility; court-martial; explicit time/turn conventions; leeway; heel; deeper sailing/inertia calibration.

## Next concrete task

Immediate priority is live user validation of the restored prototype helm, collision response/exact-astern behavior, mast entanglement/carpenter release, angle-sensitive full-sail ignition/fire control and enemy-information hiding. Then continue morale/surrender/boarding and the remaining mast/helm-damage dependencies.

## Branch discipline

- `main`: do not develop here;
- `develop/historical-simulator`: canonical integration/recovery branch;
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft;
- `archive/prototype-v1`: immutable original prototype reference.
