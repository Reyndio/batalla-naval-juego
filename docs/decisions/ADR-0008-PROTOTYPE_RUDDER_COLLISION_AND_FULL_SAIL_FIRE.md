# ADR-0008 — Prototype rudder, collision response, mast entanglement and full-sail fire

Date: 2026-09-20
Status: Accepted for current playable simulator

## Context

Live testing identified four related problems in the playable 2v2 validation build:

1. the current 0/1/2-point helm surface no longer matched the stable prototype control model the project is required to preserve until a replacement is validated;
2. collision inertia did not distinguish impact on bow, centre and stern;
3. collision consequences did not yet model weak-mast fall toward the colliding vessel and the resulting possibility of the ships becoming entangled;
4. full-sail firing already carried the source-derived accuracy and upper-battery restrictions, but the explicit fire risk was not yet represented, and enemy fatigue was exposed to the player.

The project owner explicitly required restoration of the prototype helm behavior and specified the collision response described below.

## Decision 1 — playable helm follows the stable prototype

The player-facing/runtime steering model is restored from `archive/prototype-v1` rather than using the 0/1/2-point baseline abstraction as the live control surface.

Playable positions are `-4,-3,-2,-1,0,+1,+2,+3,+4`.

At NV/PV, base turn angles are:

- 1 point: 10°;
- 2 points: 20°;
- 3 points: 30°;
- 4 points / T: 45°.

Sail-state steering effectiveness:

- NV/PV: 100%;
- MV: 70%;
- TV: 40%.

Maximum helm-position change per turn:

- NV/PV: 4 points;
- MV: 3 points;
- TV: 2 points.

Maximum absolute helm position:

- NV/PV: 4;
- MV: 4;
- TV: 3.

Therefore `±4` is never available at TV. A TV ship starting from centred helm cannot jump directly to `±3` because the per-turn change limit is 2, but it can reach `±3` progressively from `±2`.

A damaged rudder remains limited to `±1`.

The existing head-to-wind tacking stop/departure logic remains layered over this control model.

### Classification

**PROTOTYPE-PARITY / OWNER-APPROVED PLAYABLE DIVERGENCE.**

The source manual's 0/1/2-point manoeuvre abstraction remains documented and tested as source behavior, but it is no longer the current player-facing helm semantics. This explicitly supersedes any earlier state document that called the 0/1/2 runtime control surface the current playable implementation.

## Decision 2 — collision response depends on impacted section

For the vessel being struck:

- impact on **BOW**: retained translational momentum = 0%; the vessel is stopped;
- impact on **CENTER**: retained translational momentum = 25%; speed is reduced 75%;
- impact on **STERN**: retained translational momentum = 50%; speed is reduced 50%;
- impact essentially exactly from astern, within a current 5° tolerance of the stern/rudder axis: retained momentum = 100%; the impact itself neither increases nor decreases forward speed.

For a stern impact, rudder-damage probability varies continuously with alignment to the stern/rudder axis:

- poorly aligned stern impact approaches 25%;
- exact astern alignment reaches 75%.

This replaces the previous sail-difference-only rudder-risk formula in the swept collision layer.

### Classification

**OWNER-APPROVED PROJECT RULE.**

The exact percentages and 5° exact-astern tolerance are gameplay/physical reconstruction parameters and must not be labelled as source-text facts.

## Decision 3 — weak masts may fall into the colliding ship and entangle both vessels

The stable prototype already associated collision section with mast area:

- bow -> foremast;
- centre -> mainmast;
- stern -> mizzenmast.

For the first playable collision-entanglement implementation:

- a mast at or below 30% health after collision damage is treated as critically weak;
- such a mast has a 50% collision-triggered fall check;
- a mast knocked down by this collision is recorded as falling toward the colliding vessel;
- if it falls onto the other vessel, current entanglement probability is 75%;
- while entangled, both vessels have zero translational movement;
- a carpenter/cutting party must be ordered to clear the mast;
- the cutting party costs +10% fatigue per turn and succeeds on a roll below 50%.

The +10 fatigue and 50% cutting success follow the source manual's fallen-mast cutting rule. The 30% critical-health threshold and 75% collision-entanglement probability are explicit project reconstructions for the owner-requested collision case. The general source rules for ordinary mast fall, wind-driven fall side and dragging-mast behavior remain separately applicable and are not replaced by this collision-specific rule.

## Decision 4 — full-sail firing accuracy and fire risk

The source manual explicitly states that when firing at full sail:

- the upper-deck battery is excluded;
- firing accuracy suffers a penalty equivalent to +10% fatigue;
- despite the upper-battery exclusion, there remains a 20% risk of causing a fire.

The first two effects were already implemented. The runtime now also applies the 20% ignition check after an actual full-sail broadside.

The owner additionally requires increased fire risk when wind enters through the side being fired. Until stronger evidence provides a calibrated value, the playable project rule is:

- ordinary full-sail broadside: 20%;
- wind entering through the firing side: 30%.

The 30% figure is a **PROJECT-RECONSTRUCTION calibration**, not source-derived. It may be revised after historical/physical research without changing the underlying rule that the risk increases.

This implementation creates fire state/level when ignition occurs. It does **not** claim the complete five-level fire subsystem is finished; propagation, damage and fire-fighting resolution remain their own implementation gate.

## Decision 5 — enemy fatigue is hidden

Exact fatigue of enemy vessels is not player-visible. The enemy may visibly fail an action because of crew exhaustion, but the UI and report must not reveal its exact fatigue percentage.

This is an information-design rule and does not alter the simulation's internal enemy fatigue state.

## Validation requirements

Deterministic tests must cover:

- all nine helm positions and prototype angle/factor/change/amplitude tables;
- TV `±4` prohibition and progressive access to `±3`;
- damaged-rudder `±1` restriction;
- bow/centre/stern/exact-astern collision momentum retention;
- alignment-dependent stern rudder risk reaching 75% exactly astern;
- critically weak mast fall/entanglement and 50% carpenter release check;
- full-sail 20%/30% fire-risk calculation;
- playable wiring for hidden enemy fatigue and carpenter action.

## Consequences

The project now deliberately separates three evidence layers:

1. source-manual mechanics retained for provenance and historical baseline;
2. stable-prototype behavior restored where the user explicitly requires the established playable control model;
3. project reconstructions for collision physics and wind-amplified ignition where exact historical/source algorithms are unavailable.

Future documentation must not describe the playable helm as source-manual 0/1/2 parity while ADR-0008 is active.