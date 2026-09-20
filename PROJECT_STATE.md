# PROJECT STATE

Last updated: 2026-09-20

## Canonical integration branch

`develop/historical-simulator`

## Active work / validation branch

`feature/restore-prototype-ux-parity`

Open draft PR: **#2 — Restore prototype interaction parity in historical 2v2 pilot**.

Latest validated playable implementation/test commit on active branch: `60c934d3595ab1d0f54584bfa5db16149bc61be1`.
Latest active-branch state/documentation head at this handoff: `b9058e9777f53d71ab5097c4424e67054107c8e3`.

**Fresh-chat rule:** switch conceptually to `feature/restore-prototype-ux-parity` before inspecting or changing implementation. Read that branch's `PROJECT_STATE.md`, `docs/research/VELMAD_V1_2_MECHANICS_COMPLIANCE.md`, ADR-0006, ADR-0007 and ADR-0008. Do not use this canonical snapshot as a substitute for the active branch.

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**.

The 2v2 remains a development/regression scenario for historical ship data, multi-ship control and shared mechanics. It is not the final fleet architecture.

## Immutable / stable references

- frozen original prototype: `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`;
- stable/default `main` remains the discovery/stable branch and is not used for normal development;
- stable working Render reference: `batalla-naval-juego-1`, service `srv-d11jigk9c44c73fdfnn0`, reference commit `573e809c19645c7a8a611433502715aa5c2cf504`.

## Source / playable policy

ADR-0004 remains the general technical source policy. Current playable divergences/reconstructions are explicitly documented rather than presented as literal source parity:

- ADR-0006 — +10 fatigue per sail point crossed;
- ADR-0007 — persistent translational inertia and strict T-like rake geometry;
- ADR-0008 — restored stable-prototype nine-position helm, section-specific collision momentum, alignment-based stern/rudder risk, collision mast entanglement/carpenter release, full-sail ignition and hidden enemy fatigue.

The playable interface uses neutral simulator terminology and does not display the baseline product name. Internal research/ADR/compliance documents retain source attribution for provenance.

## Current active-branch state

- Hull0/Hull1/sinking path remains verified.
- Current four historical ships remain class-3 in the baseline classification layer.
- Sail fatigue remains the owner-approved 10% per crossed sail point rule.
- Translational inertia is active and the movement preview uses the inertial destination.
- Raking requires true T-like geometry, not merely an oblique bow/stern cone.
- Swept collision follows the inertial trajectory.
- **Playable helm now matches the stable prototype**: -4..+4; NV/PV 10/20/30/45°, MV x0.7, TV x0.4; max change 4/3/2 for NV-PV/MV/TV; TV max absolute helm3 and never ±4; damaged rudder max ±1.
- Collision momentum by impacted section: bow stops, centre retains25%, stern retains50%, exact astern retains100%; stern rudder-damage risk rises to75% at exact astern alignment.
- Critically weak collision-zone masts can fall toward the colliding ship and may entangle both vessels; carpenter cutting action costs +10 fatigue and has 50% success.
- Full-sail shooting retains its accuracy penalty and upperworks restriction; actual full-sail broadside now has source20% ignition risk, raised to project-calibrated30% when wind enters the firing side.
- Exact enemy fatigue is hidden from the player UI/log.
- Objective/threat rings and selected battery-side marks remain live.
- Complete general dragging-mast and five-level fire loops remain incomplete.

## Validation / deployment

Latest active code/test commit `60c934d3595ab1d0f54584bfa5db16149bc61be1` passed the full suite. Subsequent state/compliance-only commits also passed unchanged tests; latest active documentation deploy `dep-dao4num8bjmc73b2ffig` reached **live** at active head `b9058e9777f53d71ab5097c4424e67054107c8e3`.

Validated suite: **76 tests, 0 failed**.

Development service:

- service: `batalla-naval-2v2-parity`
- Render id: `srv-dampdunf3r2c73arnjr0`
- branch: `feature/restore-prototype-ux-parity`
- URL: `https://batalla-naval-2v2-parity.onrender.com/pilot`
- auto-deploy: enabled

Stable reference service remains untouched.

## Next concrete task

Immediate priority is live user validation of the restored prototype helm, collision section response/exact-astern rudder risk, collision mast entanglement/carpenter release, full-sail ignition and hidden enemy fatigue. After that, continue the morale/surrender/boarding chain and then complete ordinary mast/dragging behavior, four helm-damage states and the full fire loop.

## Branch discipline

- `main`: do not develop here.
- `develop/historical-simulator`: canonical integration/recovery branch.
- `feature/restore-prototype-ux-parity`: active implementation/validation branch; PR #2 remains draft.
- `archive/prototype-v1`: immutable original-prototype reference.
