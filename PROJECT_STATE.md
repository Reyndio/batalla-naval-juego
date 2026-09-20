# PROJECT STATE

Last updated: 2026-09-20

## Branches

Canonical integration branch: `develop/historical-simulator`.

Active implementation/validation branch: `feature/restore-prototype-ux-parity`.

PR #2 — `Restore prototype interaction parity in historical 2v2 pilot` — remains **draft**. Do not merge it merely for convenience; complete applicable Velmad parity and user-facing validation remain open gates.

Current active-branch implementation head before this documentation commit: `71f4bb9979d6f5d72f352e83d08cfe5a1bdd197c`.
Velmad manoeuvre merge commit: `edd0c0c7a9a77dd2afa407781032b921affd7e99`.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The historical 2v2 remains the active development/regression scenario for real ship data, multiple independent ships and shared mechanics. It is not the final fleet architecture.

## Stable / immutable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains untouched by normal historical-simulator development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`;
- the stable game remains the minimum functional behavior floor during migration.

## Mandatory Velmad v1.2 parity gate

ADR-0004 remains governing policy: reproduce every applicable explicit Velmad v1.2 mechanic and deterministic tests before replacing, simplifying, rebalancing or extending it.

Authoritative matrix:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

Algorithms explicitly omitted by the manual because the original computer automated them must not be invented and labelled Velmad. Stable/original behavior may be retained as a documented reconstruction reference.

## Historical 2v2 ship set

October 1805 configurations:

- Royal Navy: HMS Bellerophon and HMS Conqueror;
- Real Armada: Montañés and Bahama.

All four are documented 74-gun / 74-gun-class two-deckers and therefore resolve to **Velmad third class**. Actual fitted principal-piece totals are not used to misclassify them.

## Prototype interaction floor retained

The active branch still retains recognizable ships, NV/PV/MV/TV orders, projected movement shadow, explicit port/starboard firing, target/aim/section/ammunition controls, pan/zoom/recenter/fleet view, explicit start, clock/timeout/pause, independent ship orders, historical guns, gun dismounting, mast/rig damage, rudder damage, rakes, collisions, ammunition state and confirmation/reset workflow.

The former provisional helm behavior has now been deliberately superseded by explicit Velmad manoeuvre rules after deterministic validation.

## Velmad progress — 2026-09-20

### Hull 0 / Hull 1 / sinking — VERIFIED

- Hull 0 remains operational with restrictions;
- uncaptured Hull-0 ship has exact 10% per-turn chance to begin sinking;
- actual sinking is the out-of-combat transition;
- Hull 0/1 speed max 70%;
- Hull 0 cannot use lower/main battery; Hull 1 can;
- lower-deck loss derives from the historical gun fit;
- pump/repair 0→1 allowed at fatigue <=100 for +20 fatigue;
- minimal damage-control order is playable.

Compliance section 15: **VERIFIED**.

### Extreme sail fatigue — playable 30/30 PROJECT-RECONSTRUCTION

The translated v1.2 rules contain both `Remove all sailing: +30%` and `Collect all the sail (pass to no sail): +40%`, without defining a unique operational distinction.

ADR-0005 records the current playable reconstruction:

- direct `NV → TV`: +30% fatigue;
- direct `TV → NV`: +30% fatigue;
- both are one ordered extreme sail action, not forced through intermediate PV/MV turns;
- `NV → PV/MV`: +20% remains as explicitly stated;
- the conflicting +40 line remains documented and unresolved rather than silently deleted.

This 30/30 behavior is intentionally labelled **PROJECT-RECONSTRUCTION**, supported by direct recollection of original Velmad play and internal consistency, not falsely claimed as unambiguous literal v1.2 text.

Fatigue section 2 remains **PARTIAL** because two-broadside execution, boarding interaction and dependent fire/cutting/double-shot action loops are still incomplete.

### Vessel classes — current four-ship path VERIFIED

- class dependency tables exist in the core;
- current four pilot ships resolve from documented 74-gun-class rating to Velmad class 3;
- class-3 speed factor = 100%;
- class-3 independent two-point helm chance = 75%;
- deterministic tests cover all four records.

Compliance section 3: **VERIFIED for the current pilot ingestion path**.

### Manoeuvring — VERIFIED explicit rudder/class/history rules

- Velmad helm is now 0/1/2 points, not the provisional ±4 prototype scale;
- each point = exactly 15°;
- previous actual helm on the same side permits two points next turn;
- from centered/opposite helm, two points require the independent class roll;
- class chances: 25/50/75/100/100/100% for classes 1–6;
- one fallen mast: max one point;
- dismasted: no turn;
- obsolete ±3/±4 controls are hidden at runtime; UI labels the one/two-point model.

Compliance section 5: **VERIFIED for the explicit v1.2 rudder-point/history/class mechanics**.

### Tacking — VERIFIED

- rotation proceeds point-by-point;
- when bow reaches/crosses exact wind direction while tacking, heading clamps exactly head-to-wind and no remaining point rotates farther that turn;
- leaving head-to-wind next turn is limited to one point regardless of a two-point order;
- deterministic tests cover arrival and departure.

Compliance section 6: **VERIFIED**.

### Crew quality — shooting + manoeuvre portions verified, row still PARTIAL

- Beginner: firing penalty 6% per 10 fatigue, fires through 100%, class two-point chance halved;
- Normal: 5%, through 100%, normal class chance;
- Veteran: 4%, through 120%, always allowed two-point helm;
- Elite: 3%, through 120%, full two-point helm in the current Velmad 0/1/2 model;
- boarding-quality effects remain pending boarding.

Compliance section 7 remains **PARTIAL** only because boarding interaction is not implemented.

### Sailing speed — PARTIAL

Implemented: class-relative factors, -30% per fallen mast, dismasted stop, Hull 0/1 70% cap.

Still unresolved: literal Velmad rigging thresholds 2800/1800 etc cannot be applied directly while the inherited prototype uses `BASE_RIG=1200`; compatible baseline rig-point scale must be recovered/defined without pretending the manual supplied an omitted algorithm. Dragging-mast 90% cap also awaits that subsystem.

## Validation / deployment

Implementation commit `71f4bb9979d6f5d72f352e83d08cfe5a1bdd197c` deployed successfully to Render service `batalla-naval-2v2-parity` through deploy `dep-danuo4uq1p3s73cpe8qg` and reached **live**.

The service build command is `npm install && npm test`, so the complete repository test suite passed before the deployment went live.

Current suite: **37 tests, 0 failed** — prior 28 plus 9 new deterministic manoeuvre/tacking/extreme-sail tests. Two older parity expectations were deliberately updated because exact Velmad helm and direct 30/30 extreme sail behavior now supersede those provisional prototype rules.

Development service:

- Render id: `srv-dampdunf3r2c73arnjr0`;
- branch: `feature/restore-prototype-ux-parity`;
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`;
- auto-deploy: enabled.

Stable reference service remains untouched.

## Documentation decisions

- ADR-0004: complete applicable Velmad baseline before divergence.
- ADR-0005: playable direct `NV↔TV` 30/30 reconstruction while preserving the conflicting +40 v1.2 line as unresolved source evidence.

## Major Velmad work still incomplete

Use the compliance matrix as authoritative. Important remaining groups include morale/combat capability; full ammunition/loading/distance/sail-state shooting rules; windward/leeward allocation; carronades; boarding/surrender/white flag/prizes; critical mast and dragging-mast rules; source-ambiguous magazine/captain criticals; four helm-damage states; five-level fire loop; scoring/end/fear; signals; exact wind-change/visibility; court-martial; and explicit time/75 m conventions.

## Next concrete task

Next coherent baseline slice:

1. implement the explicit four-ammunition behavior and loading restrictions without inventing the manual-omitted base damage algorithm;
2. add exact target-sail modifiers and <=112 m forced-hull rule;
3. implement explicit windward/leeward damage allocation;
4. add carronade range contribution for actual carronades while keeping Spanish obuses distinct unless evidence justifies equivalence;
5. add deterministic tests and deploy before marking any gunnery subpart VERIFIED;
6. continue with morale/surrender/boarding/critical/fire systems afterward.

## Branch discipline

- `main`: do not develop here;
- `develop/historical-simulator`: canonical integration/recovery branch;
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft;
- `archive/prototype-v1`: immutable original prototype reference.
