# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**.

Latest playable implementation + tests on active branch: `4c66c286e6639258bb9cb5efb61d885b3ede7012`.
Latest active-branch documentation head at this handoff: `e541e715a837c4ee8e2a11ffafeb8b68c8e39af0`.
Sail-fatigue implementation commit: `a29741a112488dab0a33c1c804f05e52c6fde0f3`.
ADR-0006 commit: `5cb8b9081a889e40deebf3e39232f463243bc48e`.

**Fresh-chat rule:** switch conceptually to `feature/restore-prototype-ux-parity` before inspecting or changing implementation. Read that branch's `PROJECT_STATE.md`, `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`, and relevant ADRs.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The 2v2 remains a development/regression scenario for historical ship data, multi-ship control and shared mechanics. It is not the final fleet architecture.

## Immutable / stable references

- Frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`.
- Stable/default `main` remains the discovery/stable branch and is not used for normal development.
- Stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.
- Stable working game remains the minimum functional behavior floor during migration.

## Mandatory Velmad v1.2 parity gate

ADR-0004 remains the general policy: reproduce applicable explicit Velmad v1.2 mechanics and tests before replacing them. Algorithms omitted by the manual must not be invented and labelled Velmad.

The current sail-change fatigue rule is a narrow, owner-approved **PROJECT-DIVERGENCE** documented in ADR-0006, so fatigue must not be described as literal Velmad parity.

Authoritative checklist on the active branch:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

## Current verified / project-rule progress

- **Hull 0 / Hull 1 / sinking — VERIFIED.** Hull 0 remains operational, has a 10% per-turn sinking check, Hull 0/1 speed cap 70%, lower battery unavailable at Hull 0, and pump 0→1 at fatigue <=100 for +20.
- **Vessel-class dependency — VERIFIED for current four ships.** Bellerophon, Conqueror, Montañés and Bahama resolve from documented 74-gun-class rating to Velmad third class.
- **Manoeuvring — VERIFIED explicit Velmad rudder/history/class rules.** 0/1/2 points, 15° per point, class chances 25/50/75/100/100/100, one mast max one point, dismasted no turn.
- **Tacking — VERIFIED.** Stop exactly head-to-wind and limit departure to one point.
- **Crew quality — shooting and manoeuvre portions verified; row PARTIAL until boarding exists.**
- **Sail-change fatigue — PROJECT-DIVERGENCE.** ADR-0006 supersedes ADR-0005 for playable behavior: states are `NV→PV→MV→TV`; every adjacent point crossed costs +10%, so direct changes cost 10/20/30 depending on distance and the rule is symmetric. `PV→NV` now costs +10. This intentionally differs from several literal v1.2 sail-fatigue lines.
- **Gunnery/ammunition — advanced PARTIAL.** Round, bar/chain, grape, separately reloaded double shot, per-band loading, <=112 m forced hull, target-sail modifiers and shooter NV/TV service modifiers are implemented/tested. Source-omitted base damage/range, crew-service, fire and morale dependencies remain open.
- **Windward/leeward shooting — VERIFIED.** Exact 30° classification and explicit damage allocations implemented/tested.
- **Carronades — VERIFIED for actual carronades in current historical data path.** Exact 300/225/150 m contribution table. Spanish obuses remain distinct pending evidence.
- **Sailing speed — PARTIAL.** Class-relative factors, -30% per fallen mast, dismasted stop and Hull 0/1 cap exist; literal rigging thresholds and dragging-mast rule remain pending.

## Validation / deployment

Implementation/test commit `4c66c286e6639258bb9cb5efb61d885b3ede7012` reached **live** on Render service `batalla-naval-2v2-parity` through deploy `dep-dao1na7lk1mc73fp24k0`.

The service builds with `npm install && npm test`; therefore the full repository suite passed before that deployment went live.

Validated suite: **51 tests, 0 failed**.

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
6. continue afterward with critical mast/dragging-mast, four helm-damage states and the fire loop.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable original-prototype reference.
