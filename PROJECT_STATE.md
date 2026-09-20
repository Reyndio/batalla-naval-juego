# PROJECT STATE

Last updated: 2026-09-20

## Branches

Canonical integration branch: `develop/historical-simulator`.

Active implementation/validation branch: `feature/restore-prototype-ux-parity`.

PR #2 — `Restore prototype interaction parity in historical 2v2 pilot` — remains **draft**. Do not merge it merely for convenience; complete applicable Velmad parity and user-facing validation remain open gates.

Current active-branch head immediately before this state update: `a46055cde4d4439e42791f28c1ee4c150c3ee7f7`.
Latest sail-fatigue core correction: `4986ed5fb7339e0c36de2b69c3c63b2d17e171f2`.
Regression-test commit: `b9099e2a9e46a5988a8ea56d5fb74bd61b99852b`.

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

The active branch retains recognizable ships, NV/PV/MV/TV orders, projected movement shadow, explicit port/starboard firing, target/aim/section/ammunition controls, pan/zoom/recenter/fleet view, explicit start, clock/timeout/pause, independent ship orders, historical guns, gun dismounting, mast/rig damage, rudder damage, rakes, collisions, ammunition state and confirmation/reset workflow.

Exact Velmad rules now deliberately supersede provisional prototype behavior where they have deterministic coverage.

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

### Extreme sail fatigue — playable 30/30 PROJECT-RECONSTRUCTION, corrected scope

The translated v1.2 rules contain both `Remove all sailing: +30%` and `Collect all the sail (pass to no sail): +40%`, without defining a unique operational distinction.

ADR-0005 records the playable reconstruction:

- direct `NV → TV`: +30% fatigue;
- direct `TV → NV`: +30% fatigue;
- the reconstructed reverse +30 applies specifically to the direct extreme `TV→NV` action and is **not** a generic `any sail state → NV` cost;
- `PV → NV` and `MV → NV` do not receive the reconstructed +30 charge;
- `NV → PV/MV`: +20% remains as explicitly stated;
- the explicit `Making full sail: +30%` rule remains active for orders ending at TV;
- the conflicting +40 line remains documented and unresolved rather than silently deleted.

A live-user regression exposed that the first implementation accidentally charged +30 for `PV→NV`. Core commit `4986ed5...` corrected the condition; `tests/velmad-hull-fatigue.test.js` now explicitly covers `PV→NV` and verifies ordinary no-action fatigue recovery instead of a +30 charge. The dedicated extreme-action UI now labels `TV→NV directo (+30%)` / `NV→TV directo (+30%)` and only enables those buttons from the opposite extreme.

This 30/30 behavior remains **PROJECT-RECONSTRUCTION**, supported by direct recollection of original Velmad play and internal consistency, not falsely claimed as unambiguous literal v1.2 text.

Fatigue section 2 remains **PARTIAL** because two-broadside execution, boarding interaction, fire-fighting and mast-cutting owning systems are incomplete.

### Vessel classes — current four-ship path VERIFIED

- class dependency tables exist in the core;
- current four pilot ships resolve from documented 74-gun-class rating to Velmad class 3;
- class-3 speed factor = 100%;
- class-3 independent two-point helm chance = 75%;
- deterministic tests cover all four records.

Compliance section 3: **VERIFIED for the current pilot ingestion path**.

### Manoeuvring — VERIFIED explicit rudder/class/history rules

- Velmad helm is 0/1/2 points, not the provisional ±4 prototype scale;
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

### Gunnery / ammunition — substantial exact slice implemented, section 8 still PARTIAL

A separate `src/velmad-gunnery.js` layer now owns the applicable explicit ammunition/loading rules while retaining the inherited stable base-damage curve where v1.2 explicitly omits its computer algorithm.

Implemented/tested:

- round shot, bar/chain, grapeshot, and separately reloaded double shot;
- exact explicit ammunition multipliers currently recoverable from the manual;
- per-broadside-band loaded ammunition state;
- after a band fires, selected standard ammunition is loaded for that band next turn while the opposite band retains its load;
- double-shot reload requires round shot already loaded, blocks that band during the reload turn, costs +10 fatigue, and becomes available next turn;
- <=112 m forces hull aim;
- target sail-state rigging modifiers: MV normal, TV +50%, PV -10%, NV -50%;
- firing at NV gives the equivalent of 10 less fatigue; TV gives 10 more and removes upperworks/carronade firepower;
- historical lower-battery loss at Hull 0 remains integrated.

Still open in section 8:

- exact computer base-damage algorithm is SOURCE-OMITTED and must not be invented as Velmad;
- inherited stable range envelope is not yet the manual's full stated range/10%-per-length behavior;
- round-rigging 7-length cap cannot yet be exercised under that shorter inherited envelope;
- insufficient-crew gun-service restriction;
- full-sail 20% fire risk;
- morale consequences;
- true both-broadsides-in-one-turn execution.

### Windward / leeward shooting — VERIFIED

- exact 30° total wind fork is represented as ±15° around the windward/leeward axes;
- target-windward hull aim: 60% hull / 30% rig / 10% lost;
- target-windward rig aim: 0% hull / 90% rig / 10% lost;
- target-leeward hull aim: 100% hull;
- target-leeward rig aim: 40% hull / 60% rig;
- deterministic tests cover classification and allocations.

Compliance section 9: **VERIFIED**.

### Carronades — VERIFIED for actual carronades in current data path

- >300 m: no contribution;
- <=300 m: one third;
- <=225 m: one half;
- <=150 m: full contribution;
- contribution derives from actual historical carronade fit;
- Spanish obuses remain distinct and are not silently treated as carronades without evidence.

Compliance section 10: **VERIFIED for actual carronades**.

### Sailing speed — PARTIAL

Implemented: class-relative factors, -30% per fallen mast, dismasted stop, Hull 0/1 70% cap.

Still unresolved: literal Velmad rigging thresholds 2800/1800 etc cannot be applied directly while the inherited prototype uses `BASE_RIG=1200`; compatible baseline rig-point scale must be recovered/defined without pretending the manual supplied an omitted algorithm. Dragging-mast 90% cap also awaits that subsystem.

## Validation / deployment

The regression-corrected branch through ADR commit `13cfcdb624f77fe1152e32e0d3a6af4e38d761f7` deployed successfully to Render service `batalla-naval-2v2-parity` through deploy `dep-danvdfvlk1mc73fmoh60` and reached **live**.

The service build command is `npm install && npm test`, so the complete repository test suite passed before that deployment went live.

Current suite after the regression test: **51 tests, 0 failed**:

- 19 pre-Hull/fatigue tests;
- 10 Hull/fatigue tests including the new `PV→NV` regression;
- 9 manoeuvre/tacking/extreme-sail tests;
- 13 gunnery/ammunition/wind/carronade tests.

The later compliance/state documentation commits are documentation-only but still trigger the same Render test gate through auto-deploy.

Development service:

- Render id: `srv-dampdunf3r2c73arnjr0`;
- branch: `feature/restore-prototype-ux-parity`;
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`;
- auto-deploy: enabled.

Stable reference service remains untouched.

## Documentation decisions

- ADR-0004: complete applicable Velmad baseline before divergence.
- ADR-0005: playable direct `NV↔TV` 30/30 reconstruction while preserving the conflicting +40 v1.2 line as unresolved source evidence; the reconstructed reverse +30 is scoped only to direct `TV→NV`, not intermediate reductions.

## Major Velmad work still incomplete

Use the compliance matrix as authoritative. Important remaining groups include morale/combat capability; remaining section-8 base-range/crew-service/fire dependencies; boarding/surrender/white flag/prizes; critical mast and dragging-mast rules; source-ambiguous magazine/captain criticals; four helm-damage states; five-level fire loop; scoring/end/fear; signals; exact wind-change/visibility; court-martial; and explicit time/turn conventions.

## Next concrete task

The next coherent baseline slice is the morale / surrender / boarding dependency chain:

1. implement exact morale loss/recovery triggers that have unambiguous thresholds;
2. implement surrender checks and one-turn white-flag state;
3. implement boarding eligibility, combat ratio modifiers, casualties and crew-quality/fatigue effects;
4. implement capture, prize-crew requirements and recapture behavior;
5. add deterministic tests before marking those rows VERIFIED;
6. then continue into critical mast/dragging-mast, helm-damage and fire loops, resolving source-ambiguous critical formulas separately rather than guessing.

## Branch discipline

- `main`: do not develop here;
- `develop/historical-simulator`: canonical integration/recovery branch;
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft;
- `archive/prototype-v1`: immutable original prototype reference.
