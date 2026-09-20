# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**.

Current active-branch documentation head recorded at handoff: `5bda0907d3b70868c0480a0abf4b6a1128e496c0`.
Latest sail-fatigue core correction: `4986ed5fb7339e0c36de2b69c3c63b2d17e171f2`.
Latest dedicated regression-test commit: `b9099e2a9e46a5988a8ea56d5fb74bd61b99852b`.

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
- **Vessel-class dependency for current four ships — VERIFIED.** Bellerophon, Conqueror, Montañés and Bahama resolve from documented 74-gun/74-gun-class rating to Velmad third class.
- **Velmad manoeuvring — VERIFIED explicit rudder/history/class mechanics.** 0/1/2 points, 15° per point, previous-helm history, class chances 25/50/75/100/100/100, one mast max one point, dismasted no turn.
- **Tacking — VERIFIED.** Stop exactly head-to-wind and limit departure to one point.
- **Crew quality — shooting and manoeuvre portions verified; row PARTIAL until boarding exists.**
- **Extreme sail transition — PROJECT-RECONSTRUCTION.** Direct NV→TV and TV→NV are playable at +30 fatigue each in one action. The reverse +30 is scoped only to direct TV→NV; PV/MV→NV do not inherit it. A live-user regression exposed the earlier over-broad condition and `tests/velmad-hull-fatigue.test.js` now covers PV→NV explicitly. ADR-0005 preserves the conflicting +40 source line.
- **Gunnery/ammunition — advanced PARTIAL.** Round, bar/chain, grape, separately reloaded double shot, per-band loading, <=112 m forced hull, target-sail modifiers and shooter NV/TV service modifiers are implemented/tested. Source-omitted base damage/range, crew-service, fire and morale dependencies remain open.
- **Windward/leeward shooting — VERIFIED.** Exact 30° classification and explicit damage allocations implemented/tested.
- **Carronades — VERIFIED for actual carronades in the current historical data path.** Exact 300/225/150 m contribution table. Spanish obuses remain distinct pending evidence.
- **Sailing speed — PARTIAL.** Class-relative factors, -30% per fallen mast, dismasted stop and Hull 0/1 cap exist; literal rigging thresholds and dragging-mast rule remain pending.

## Validation / deployment

The regression-corrected branch through commit `13cfcdb624f77fe1152e32e0d3a6af4e38d761f7` reached **live** on Render service `batalla-naval-2v2-parity` through deploy `dep-danvdfvlk1mc73fmoh60`.

The service builds with `npm install && npm test`; therefore the full repository suite passed before that deployment went live.

Validated suite after the sail regression test: **51 tests, 0 failed**.

Development service:

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- auto-deploy: enabled

Stable reference service remains untouched.

## Next concrete task

Continue the baseline on the active branch with the morale / surrender / boarding dependency chain:

1. implement exact morale loss/recovery triggers with unambiguous thresholds;
2. implement surrender checks and one-turn white-flag state;
3. implement boarding eligibility, ratio modifiers, casualties and crew-quality/fatigue effects;
4. implement capture, prize-crew requirements and recapture behavior;
5. add deterministic tests before marking those rows VERIFIED;
6. continue afterward with critical mast/dragging-mast, four helm-damage states and the fire loop, keeping ambiguous critical formulas unresolved rather than guessing.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable original-prototype reference.

A new chat should never ask the user to restate project history when GitHub is available.
