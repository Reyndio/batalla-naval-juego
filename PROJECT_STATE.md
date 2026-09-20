# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**.

Latest validated playable implementation/test commit on active branch: `7069eb1365108c68dce57ca3e4202233fe593551`.
Latest active-branch state/documentation head at this handoff: `4dbb27019ab431b6cf46eda37305dfa61b45e600`.

**Fresh-chat rule:** switch conceptually to `feature/restore-prototype-ux-parity` before inspecting or changing implementation. Read that branch's `PROJECT_STATE.md`, `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`, ADR-0006, ADR-0007 and ADR-0008. Do not use this canonical snapshot as a substitute for the active branch.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The 2v2 remains a development/regression scenario for historical ship data, multi-ship control and shared mechanics. It is not the final fleet architecture.

## Immutable / stable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains the discovery/stable branch and is not used for normal development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.

## Source / playable policy

ADR-0004 remains the general technical source policy. Current playable divergences/reconstructions are explicit:

- ADR-0006 — +10 fatigue per sail point crossed;
- ADR-0007 — persistent translational inertia and strict T-like rake geometry;
- ADR-0008 — restored stable-prototype nine-position helm, section-specific collision response, alignment-based stern/rudder risk, collision mast entanglement/carpenter release, full-sail ignition/fire control and hidden enemy fatigue.

Player-facing UI uses neutral simulator terminology; internal source documentation retains provenance.

## Current active-branch state

- Hull0/Hull1/sinking path remains verified.
- Sail fatigue remains +10% per crossed sail point.
- Translational inertia is active and previewed.
- Raking requires true T-like geometry.
- Swept collision follows the inertial trajectory.
- Playable helm matches the stable prototype: positions -4..+4; NV/PV 10/20/30/45°, MV x0.7, TV x0.4; change limits 4/3/2; TV max absolute helm3 and never ±4; damaged rudder max ±1.
- Collision retention: bow0%, centre25%, stern50%, exact astern100%; stern rudder risk rises to75% exactly astern.
- Critically weak collision-zone masts can fall toward the colliding ship and entangle both; carpenter action costs+10 fatigue and succeeds50%.
- Full-sail fire keeps its accuracy/upperworks penalties; ignition20%, raised to project-calibrated30% when wind enters the firing side.
- Fire levels1–5, unattended escalation, +10 fire-fighting action, level-dependent control, L3/L4 damage/explosion, L5 abandonment and entangled-fire transmission are now playable/tested.
- Exact enemy fatigue is hidden from player UI/log.
- Objective/threat rings and selected battery-side marks remain live.
- Ordinary non-collision dragging-mast rules and external critical-fire triggers remain incomplete.

## Validation / deployment

Active code/test commit `7069eb1365108c68dce57ca3e4202233fe593551` passed the complete suite and reached **live** through Render deploy `dep-dao4q67lk1mc73fs4qjg`.

Validated suite: **84 tests, 0 failed**.

Development service:

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- auto-deploy: enabled

Stable reference service remains untouched.

## Next concrete task

Immediate priority is live user validation of the restored prototype helm, collision section response/exact-astern rudder risk, mast entanglement/carpenter release, full-sail ignition/fire control and enemy-information hiding. Then continue morale/surrender/boarding and the remaining ordinary mast/helm-damage dependencies.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable original-prototype reference.
