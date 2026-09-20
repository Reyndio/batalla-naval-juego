# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**

Current PR head recorded at handoff: `3bb370f3e7aac7db9eafae18b9ebb9429c23c907`.

**Fresh-chat rule:** after reading this file on the canonical branch, switch conceptually to `feature/restore-prototype-ux-parity` before inspecting or changing the current implementation. Do not continue coding from the older canonical snapshot as if it were current.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

The 2v2 is a development/regression scenario used to validate historical ship data, multi-ship control and shared mechanics. It is not the final fleet architecture.

## Immutable / stable references

- Frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`.
- Stable/default `main` remains the discovery/stable branch.
- Stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.
- The stable working game is the **minimum functional behavior floor** during migration: no useful mechanic already present there may silently disappear.

## Historical 2v2 ship set

Selected October 1805 configurations:

### Royal Navy
- HMS Bellerophon: 28×32-pdr, 28×18-pdr, 18×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; working action complement 522.
- HMS Conqueror: 28×32-pdr, 30×18-pdr, 16×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; working action complement 573.

### Real Armada
- Montañés: 28×36-lb, 30×18-lb, 8×8-lb, 10×30-lb obuses; 76 principal pieces; working complement 749.
- Bahama: 28×24-lb, 30×18-lb, 10×8-lb, 6×30-lb obuses, 4×24-lb obuses; 78 principal pieces; working complement 689; 702 remains a documented secondary-source discrepancy.

National-side rule remains fixed: one coherent navy per side; no mixed-national teams in this pilot.

## Current playable parity branch

Development deployment:

- service: `batalla-naval-2v2-parity`
- branch: `feature/restore-prototype-ux-parity`
- playable URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- stable reference service remains untouched.

The parity branch restored major mechanics/interactions lost by the first 2v2 slice, including:

- recognizable top-down hull/deck/masts/sails;
- NV/PV/MV/TV and progressive sail changes;
- movement shadow and projected path;
- helm -4..+4 with stable-prototype restrictions;
- explicit Babor/Estribor fire;
- target, aim, section and ammunition controls;
- pan, zoom, recenter and fleet view;
- explicit **Iniciar partida**;
- configurable visible turn clock;
- automatic resolution at timeout;
- pause/resume;
- independent orders for both human ships;
- fatigue and crew experience;
- historical guns per broadside and operational guns by side;
- hull hits dismounting guns on the struck side;
- mast/rig state and mast-fall casualties;
- rudder damage;
- bow/stern rakes;
- collision damage;
- loaded ammunition distinct from next ammunition;
- round shot, grape and double shot;
- confirmation reset after turn resolution.

Latest fully observed automated parity build before documentation-only commits: **19 tests passed, 0 failed**.

PR #2 intentionally remains **draft**. Do not merge it merely for convenience; user-facing parity and the new Velmad-compliance gate are still open.

## Governing mechanics decisions

### ADR-0001 — Velmad baseline and historical evidence

Velmad v1.2 is the foundational mechanics reference. Changes require strong evidence; intuition is not enough.

### ADR-0003 — Preserve prototype interaction parity

The deployed stable game is the minimum interaction/mechanics floor during migration. Useful existing behavior must not be lost silently.

### ADR-0004 — Complete Velmad parity before divergence

Accepted 2026-09-20.

**Mandatory implementation order:**

1. inventory every applicable mechanic explicitly stated in Velmad v1.2;
2. implement it faithfully with the stated percentages, thresholds, dependencies and state transitions;
3. add tests demonstrating that exact rule;
4. only then mark it verified in the compliance matrix;
5. reach complete applicable Velmad baseline parity before replacing or improving any Velmad rule;
6. any later improvement requires strong historical/technical/physical evidence and an explicit documented comparison;
7. any mechanic added beyond Velmad also requires good documentation and must be identified as an addition.

Important source limitation: Velmad explicitly omits some detailed movement and damage-calculation algorithms because the computer automated them. Those omitted formulas must not be invented and labelled as Velmad; stable/original behavior may be used as a documented reconstruction reference until stronger evidence exists.

The exhaustive compliance matrix currently lives on the active branch at:

`docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`

It is an implementation/release gate, not a wish list.

## Immediate known contradictions with Velmad

The current pilot still contains provisional behavior that must be replaced to match the manual. The clearest first contradiction is:

- **Hull 0 must not mean automatic sinking.** Under Velmad, a hull-0 ship remains operational with restrictions, has a 10% per-turn chance to begin sinking, cannot use the first/bottom/main battery, is limited in speed, and may be pumped/repaired to hull 1 at the stated fatigue cost when eligible. Once actual sinking begins, the vessel is out of combat.

Other mandatory baseline systems still incomplete include exact Velmad morale, full fatigue cost/recovery table, four crew-quality levels, exact Velmad helm/class rules, tacking, bar/chain shot, windward/leeward shooting effects, carronade range contribution, boarding, surrender, white-flag state, prizes/recapture, critical mast knockdown, dragging fallen masts and cutting parties, fire progression/firefighting, helm-damage states, signals, wind changes, visibility and remaining manual-defined end/scoring rules.

## UI direction agreed with user

The current fixed left/right panels are not the target architecture.

Target interaction model:

- battle sea/canvas should use essentially the full viewport;
- primary ship orders remain permanently visible in a compact top bar, following the useful pattern of the stable game and original Velmad;
- secondary panels should be collapsible/floating rather than permanently consuming battlefield width;
- clicking a ship opens a contextual popup/card with identity, flag, ship state and operational damage;
- own-ship popup is also the center for damage-control/special actions such as firefighting, cutting a dragging mast, pumping/repairing hull 0→1, etc.;
- enemy information should be limited to what is reasonably observable rather than exposing hidden exact internal state without a rule justification;
- current hard world-edge clamping is provisional and must not be mistaken for a historical mechanic.

This UI redesign has **not yet been implemented**. Do not lose the restored mechanics while changing the layout.

## Stable/current mechanical references to read before further work

On `feature/restore-prototype-ux-parity`:

- `docs/decisions/ADR-0001-velmad-baseline-and-historical-evidence.md`
- `docs/decisions/ADR-0003-preserve-prototype-interaction-parity.md`
- `docs/decisions/ADR-0004-complete-velmad-parity-before-divergence.md`
- `docs/reports/STABLE_PROTOTYPE_MECHANICS_PARITY.md`
- `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`
- `src/pilot2v2-core.js`
- `src/pilot2v2-ui.js`
- `pilot-2v2.html`
- `tests/pilot2v2-ux-parity.test.js`
- `tests/pilot2v2.test.js`

Historical ship research remains under `docs/research/ships/` and related 2v2 research documents.

## Next concrete task

**Do not start by inventing new historical refinements. Complete the Velmad baseline first.**

Recommended next implementation unit:

1. work on `feature/restore-prototype-ux-parity` or a child feature branch based on its current head;
2. implement the exact Velmad **Hull 0 / Hull 1 / sinking state machine** instead of `HP 0 = sunk`;
3. expose the necessary state/action in the contextual ship UI architecture without yet doing an unrelated presentation overhaul;
4. add deterministic tests for hull-0 survival, 10% sinking check, hull-0 battery restriction, hull-0/1 speed cap, eligibility/cost for pumping to hull 1, and transition to actual sinking;
5. update `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md` only when tests prove parity;
6. continue through the matrix systematically until all applicable Velmad rules are VERIFIED;
7. only after complete baseline parity, open evidence-backed improvement/addition decisions.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration branch and fresh-chat recovery point.
- `feature/restore-prototype-ux-parity`: current active implementation/validation branch; PR #2 is draft.
- `archive/prototype-v1`: immutable old prototype reference.

A new chat should never ask the user to restate this history if GitHub is available.