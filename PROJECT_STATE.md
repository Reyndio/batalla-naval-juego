# PROJECT STATE

Last updated: 2026-09-20

## Branches

Canonical integration branch: `develop/historical-simulator`.

Active implementation/validation branch: `feature/restore-prototype-ux-parity`.

PR #2 — `Restore prototype interaction parity in historical 2v2 pilot` — remains **draft**. Do not merge it merely for convenience; complete applicable Velmad parity and user-facing validation remain open gates.

Latest playable implementation + test head: `4c66c286e6639258bb9cb5efb61d885b3ede7012`.
Latest sail-fatigue implementation commit: `a29741a112488dab0a33c1c804f05e52c6fde0f3`.
ADR-0006 commit: `5cb8b9081a889e40deebf3e39232f463243bc48e`.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The historical 2v2 remains the active development/regression scenario for real ship data, multiple independent ships and shared mechanics. It is not the final fleet architecture.

## Stable / immutable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains untouched by normal historical-simulator development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`;
- the stable game remains the minimum functional behavior floor during migration.

## Mandatory Velmad v1.2 parity gate

ADR-0004 remains the general implementation policy: reproduce applicable explicit Velmad mechanics and deterministic tests before replacing them. Algorithms explicitly omitted by the manual must not be invented and labelled Velmad.

The current sail-fatigue rule is an explicit owner-approved exception and is documented as a **PROJECT RULE / DELIBERATE DIVERGENCE**, not as literal Velmad parity. Therefore fatigue remains PARTIAL/DIVERGENT.

Authoritative mechanical checklist remains:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

## Historical 2v2 ship set

October 1805 configurations:

- Royal Navy: HMS Bellerophon and HMS Conqueror;
- Real Armada: Montañés and Bahama.

All four are documented 74-gun / 74-gun-class two-deckers and resolve to **Velmad third class**. Actual fitted principal-piece totals are not used to misclassify them.

## Prototype interaction floor retained

The active branch retains recognizable ships, NV/PV/MV/TV orders, projected movement shadow, explicit port/starboard firing, target/aim/section/ammunition controls, pan/zoom/recenter/fleet view, explicit start, clock/timeout/pause, independent ship orders, historical guns, gun dismounting, mast/rig damage, rudder damage, rakes, collisions, ammunition state and confirmation/reset workflow.

Exact Velmad rules supersede provisional prototype behavior where they have deterministic coverage, except where an explicit project divergence is documented.

## Velmad / project-rule progress — 2026-09-20

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

### Sail-change fatigue — PROJECT RULE / DELIBERATE DIVERGENCE

ADR-0006 supersedes ADR-0005 for current playable behavior.

Sail states are ordered `NV → PV → MV → TV`, and **every adjacent sail point crossed costs +10% fatigue**:

- same state: 0%;
- one point: +10%;
- two points: +20%;
- three points (`NV↔TV`): +30%.

The rule is symmetric in both directions. Direct jumps pay the whole cost in one turn; progressive changes pay +10% per one-point change on each turn.

Examples now tested:

- `PV→NV`: +10, so a ship at 50 fatigue becomes 60 rather than receiving idle recovery;
- `MV→TV`: +10;
- `PV→TV`: +20;
- `NV→TV` and `TV→NV`: +30.

This is not literal Velmad v1.2. It intentionally differs from explicit translated lines such as `NV→PV/MV +20` and the general `Making full sail +30`, while the conflicting +30/+40 all-sail-removal source lines remain preserved in documentation.

Fatigue section 2 therefore remains **PARTIAL/DIVERGENT**. Other pending fatigue dependencies include true two-broadside execution, boarding interaction, fire-fighting and mast-cutting owning systems.

### Vessel classes — current four-ship path VERIFIED

- class dependency tables exist in the core;
- current four pilot ships resolve from documented 74-gun-class rating to Velmad class 3;
- class-3 speed factor = 100%;
- class-3 independent two-point helm chance = 75%;
- deterministic tests cover all four records.

### Manoeuvring — VERIFIED explicit rudder/class/history rules

- Velmad helm is 0/1/2 points;
- each point = exactly 15°;
- previous actual helm on the same side permits two points next turn;
- from centered/opposite helm, two points require the independent class roll;
- class chances: 25/50/75/100/100/100% for classes 1–6;
- one fallen mast: max one point;
- dismasted: no turn.

### Tacking — VERIFIED

- rotation proceeds point-by-point;
- bow clamps exactly head-to-wind when reached/crossed while tacking;
- no remaining point rotates farther that turn;
- leaving head-to-wind next turn is limited to one point.

### Crew quality — shooting + manoeuvre portions verified, row still PARTIAL

- Beginner: firing penalty 6% per 10 fatigue, fires through 100%, class two-point chance halved;
- Normal: 5%, through 100%, normal class chance;
- Veteran: 4%, through 120%, always allowed two-point helm;
- Elite: 3%, through 120%, full two-point helm in the current model;
- boarding-quality effects remain pending boarding.

### Gunnery / ammunition — substantial exact slice implemented, section 8 still PARTIAL

Implemented/tested:

- round shot, bar/chain, grapeshot, separately reloaded double shot;
- per-broadside-band loaded ammunition state;
- selected standard ammunition loads for the band that fired for the next turn;
- double-shot reload requires round shot already loaded, blocks that band during reload, costs +10 fatigue, and becomes available next turn;
- <=112 m forces hull aim;
- target sail-state rigging modifiers: MV normal, TV +50%, PV -10%, NV -50%;
- firing at NV gives the equivalent of 10 less fatigue; TV gives 10 more and excludes upperworks/carronade firepower;
- historical lower-battery loss at Hull 0 remains integrated.

Still open: source-omitted base-damage algorithm, full range behavior, insufficient-crew gun service, full-sail fire risk, morale consequences, and true both-broadsides execution.

### Windward / leeward shooting — VERIFIED

- exact 30° total wind fork;
- target-windward hull aim: 60% hull / 30% rig / 10% lost;
- target-windward rig aim: 0% hull / 90% rig / 10% lost;
- target-leeward hull aim: 100% hull;
- target-leeward rig aim: 40% hull / 60% rig.

### Carronades — VERIFIED for actual carronades in current data path

- >300 m: no contribution;
- <=300 m: one third;
- <=225 m: one half;
- <=150 m: full contribution;
- Spanish obuses remain distinct pending evidence.

### Sailing speed — PARTIAL

Implemented: class-relative factors, -30% per fallen mast, dismasted stop, Hull 0/1 70% cap.

Still unresolved: literal Velmad rigging thresholds on a compatible rig-point scale and dragging-mast behavior.

## Validation / deployment

Implementation/test commit `4c66c286e6639258bb9cb5efb61d885b3ede7012` deployed successfully to Render service `batalla-naval-2v2-parity` through deploy `dep-dao1na7lk1mc73fp24k0` and reached **live**.

The service build command is `npm install && npm test`, so the complete repository suite passed before that deployment went live.

Current validated suite: **51 tests, 0 failed**.

Development service:

- Render id: `srv-dampdunf3r2c73arnjr0`;
- branch: `feature/restore-prototype-ux-parity`;
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`;
- auto-deploy: enabled.

Stable reference service remains untouched.

## Documentation decisions

- ADR-0004: general complete-applicable-Velmad-baseline policy.
- ADR-0005: previous direct-extremes 30/30 reconstruction; superseded for playable sail-fatigue behavior.
- ADR-0006: current rule, +10 fatigue per sail point crossed; explicit PROJECT RULE / DELIBERATE DIVERGENCE.

## Major Velmad work still incomplete

Important remaining groups include morale/combat capability; remaining section-8 range/crew-service/fire dependencies; boarding/surrender/white flag/prizes; critical mast and dragging-mast rules; source-ambiguous magazine/captain criticals; four helm-damage states; five-level fire loop; scoring/end/fear; signals; exact wind-change/visibility; court-martial; and explicit time/turn conventions.

## Next concrete task

Next coherent baseline slice remains the morale / surrender / boarding dependency chain:

1. implement exact morale loss/recovery triggers with unambiguous thresholds;
2. implement surrender checks and one-turn white-flag state;
3. implement boarding eligibility, ratio modifiers, casualties and crew-quality/fatigue effects;
4. implement capture, prize-crew requirements and recapture behavior;
5. add deterministic tests before marking those rows VERIFIED;
6. continue afterward with critical mast/dragging-mast, four helm-damage states and the fire loop.

## Branch discipline

- `main`: do not develop here;
- `develop/historical-simulator`: canonical integration/recovery branch;
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft;
- `archive/prototype-v1`: immutable original prototype reference.
