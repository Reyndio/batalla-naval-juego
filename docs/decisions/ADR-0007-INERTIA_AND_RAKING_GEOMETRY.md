# ADR-0007 — Translational inertia and strict raking geometry

Date: 2026-09-20
Status: Accepted for active playable branch

## Context

The current pilot changes a ship's translational movement immediately to the speed implied by the ordered sail state. A ship going from medium/full sail to no sail can therefore stop unrealistically within one movement resolution, and a ship starting from no way can jump immediately to the full commanded displacement.

The baseline v1.2 manual gives class/sail/wind speed dependencies and manoeuvre rules, but explicitly omits the detailed computer movement algorithm. It does not provide a recoverable numerical inertia formula. Therefore an inertia formula must not be labelled as a literal baseline rule.

Historical seamanship does establish the represented phenomenon. Nares, *Seamanship* (1877), repeatedly refers to a vessel/boat carrying her way and notes that a heavily laden boat carries her way more than an empty one; period seamanship also treats having sufficient 'way on' as essential for manoeuvre. This supports persistent motion as a physical/historical requirement even though it does not provide the simulator coefficients used here.

Source: https://whalesite.org/anthology/1877_Nares_Seamanship.htm

## Decision — inertia

Add a project-reconstruction translational inertia layer.

- Every ship stores a two-dimensional motion vector (`motionVx`, `motionVy`).
- The ordinary movement model still computes the commanded displacement from sail, wind, hull/rig condition, class and rudder/heading.
- The actual next motion vector approaches that commanded vector gradually rather than replacing it instantly.
- Large classes respond more slowly; small craft respond more quickly.
- Distance travelled during the movement phase uses the mean of previous and next motion vectors, approximating continuous acceleration/deceleration during the turn.
- Going to `NV` does not erase existing way immediately; residual motion decays over subsequent turns.
- A ship starting with no way accelerates progressively.
- Turning changes the commanded vector, while the retained motion vector creates visible carry-through instead of translating instantly along the new heading.
- A collision retains only 25% of the pre-collision motion vector on the following turn.

Current response coefficients are tuning hypotheses, not historical measurements:

| Class | Response per turn |
|---|---:|
| 1 | 0.30 |
| 2 | 0.35 |
| 3 | 0.40 |
| 4 | 0.48 |
| 5 | 0.56 |
| 6 | 0.64 |

These values must remain explicitly identified as PROJECT-RECONSTRUCTION until stronger quantitative evidence supports calibration.

## Decision — raking geometry

Raking fire is fire directed down the target ship's longitudinal axis from ahead or astern. Historical descriptions repeatedly describe ships manoeuvring across an opponent's bow or stern to obtain raking fire; U.S. Navy historical summaries describe vessels crossing the stern/bow and firing the length of the decks.

Sources:

- https://www.history.navy.mil/our-collections/art/exhibits/conflicts-and-operations/the-war-of-1812/uss-argus-vs-hms-pelican.html
- https://www.history.navy.mil/about-us/leadership/director/directors-corner/h-grams/h-gram-089/h-089-1.html

The existing implementation only checked whether the firing ship lay inside a +/-15 degree cone from the target's bow or stern. That could award a rake to an oblique/partial-battery geometry.

A rake now requires both:

1. the attacker lies within +/-15 degrees of the defender's longitudinal bow/stern axis; and
2. the ships' headings are approximately perpendicular, within +/-15 degrees of 90 degrees.

This produces the intended T-like geometry: the firing broadside crosses the target's bow or stern and the shot travels approximately along the target's long axis. Oblique L-like/diagonal positions remain ordinary broadside/section fire and do not receive bow/stern rake multipliers.

## Validation

Deterministic tests must cover:

- residual movement after ordering no sail;
- progressive acceleration from zero way;
- decaying residual motion over successive no-sail turns;
- a true stern-rake T position being classified as a rake;
- an oblique position in the same stern cone being rejected as a rake;
- playable HTML loading inertia before collision/gunnery so collision checking follows the inertial path.

## Consequences

This is an intentional extension beyond recoverable baseline movement text. It advances the Historical 1v1 milestone requirement for inertia but does not complete leeway, heel, sea-state response or a fully researched hydrodynamic manoeuvre model.
