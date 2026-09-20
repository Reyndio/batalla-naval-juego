# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**.

Current active-branch documentation head recorded at handoff: `ef977ff4a55f72416e04031ff7487b312d400ce9`.
Latest validated implementation commit: `71f4bb9979d6f5d72f352e83d08cfe5a1bdd197c`.
Velmad manoeuvre merge commit: `edd0c0c7a9a77dd2afa407781032b921affd7e99`.

**Fresh-chat rule:** switch conceptually to `feature/restore-prototype-ux-parity` before inspecting or changing implementation. Read that branch's `PROJECT_STATE.md`, `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`, and relevant ADRs. Do not treat this canonical snapshot as the current implementation if the active branch has advanced.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The 2v2 remains a development/regression scenario for historical ship data, multi-ship control and shared mechanics. It is not the final fleet architecture.

## Immutable / stable references

- Frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`.
- Stable/default `main` remains the discovery/stable branch and is not used for normal development.
- Stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.
- Stable working game remains the minimum functional behavior floor during migration.

## Mandatory Velmad v1.2 parity gate

ADR-0004 still governs implementation order: reproduce every applicable explicit rule and test it before changing/rebalancing it. Algorithms explicitly omitted by the manual must not be invented and labelled Velmad.

Authoritative current checklist lives on the active branch:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

## Current verified / reconstructed progress

- **Hull 0 / Hull 1 / sinking — VERIFIED.** Hull 0 remains operational, 10% per-turn sinking check, Hull 0/1 70% speed cap, lower battery unavailable at Hull 0, pump 0→1 at fatigue <=100 for +20.
- **Vessel-class dependency for current four ships — VERIFIED.** Bellerophon, Conqueror, Montañés and Bahama are documented 74-gun/74-gun-class two-deckers and resolve to Velmad third class.
- **Velmad manoeuvring — VERIFIED explicit rudder/history/class mechanics.** 0/1/2 points, 15° per point, previous-helm history, class chances 25/50/75/100/100/100, one mast max one point, dismasted no turn.
- **Tacking — VERIFIED.** Stop exactly head-to-wind and limit departure to one point.
- **Crew quality — shooting and manoeuvre portions verified; row PARTIAL until boarding exists.** Beginner half manoeuvre chance, Normal class chance, Veteran/Elite full two-point helm; exact firing fatigue tables/limits retained.
- **Extreme sail transition — PROJECT-RECONSTRUCTION.** Direct NV→TV and TV→NV are playable at +30 fatigue each in one action. ADR-0005 records this as a deliberate reconstruction because the translated v1.2 PDF also contains a conflicting +40 `Collect all the sail` line. The conflict is not erased or relabelled as literal Velmad.
- **Sailing speed — PARTIAL.** Class-relative factors, -30% per fallen mast, dismasted stop and Hull 0/1 cap exist; literal rigging thresholds and dragging-mast rule remain pending.

## Validation / deployment

Implementation commit `71f4bb9979d6f5d72f352e83d08cfe5a1bdd197c` reached `live` on Render service `batalla-naval-2v2-parity` through deploy `dep-danuo4uq1p3s73cpe8qg`.

The service builds with `npm install && npm test`; therefore the full repository suite passed before that deployment went live.

Validated suite: **37 tests, 0 failed**.

Development service:

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- auto-deploy: enabled

Stable reference service remains untouched.

## Next concrete task

Continue the baseline on the active branch with the gunnery dependency slice:

1. implement explicit four-ammunition behavior and loading restrictions without inventing Velmad's omitted base damage algorithm;
2. add exact target-sail modifiers and <=112 m forced-hull rule;
3. implement explicit windward/leeward allocation;
4. add carronade range contribution for actual carronades while keeping Spanish obuses distinct unless evidence supports equivalence;
5. deterministic tests + deployment before marking gunnery subparts verified;
6. continue afterward with morale/surrender/boarding/critical/fire systems, preserving SOURCE-AMBIGUOUS and SOURCE-OMITTED labels where required.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable original-prototype reference.

A new chat should never ask the user to restate project history when GitHub is available.
