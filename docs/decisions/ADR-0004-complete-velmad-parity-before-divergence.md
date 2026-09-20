# ADR-0004 — Complete Velmad v1.2 parity before divergence

Date: 2026-09-20
Status: Accepted

## Context

Velmad v1.2 is not merely an inspiration for this project. Its rules are the result of deliberate design work intended to represent age-of-sail combat as a coherent system. During the historical 2v2 work, several mechanics already present in Velmad or in the stable playable prototype were accidentally omitted or simplified, including fatigue, gun dismounting and the special state of a ship at hull 0.

ADR-0001 established Velmad as the foundational baseline and allowed evidence-backed refinement. This ADR makes the implementation order stricter so that the baseline cannot be lost during modernization.

## Decision

Before replacing, simplifying, rebalancing or extending a Velmad mechanic, the historical simulator must first reach **complete mechanical parity with every rule explicitly described in the Velmad v1.2 manual** that is applicable to the simulation scope.

The required sequence is:

1. Inventory every mechanic stated in the Velmad v1.2 manual.
2. Implement it faithfully, preserving its stated thresholds, percentages, dependencies, state transitions and consequences.
3. Add tests that demonstrate the rule is represented.
4. Mark the mechanic as implemented in the Velmad compliance matrix only after those tests exist.
5. Only after the complete applicable baseline is present may a Velmad mechanic be modified or replaced.
6. Any replacement or improvement requires strong historical, technical or physical evidence, a documented comparison against the Velmad rule, and an explicit project decision.
7. Any mechanic added beyond Velmad must also be supported by documented evidence and must be clearly identified as an addition rather than silently presented as a Velmad rule.

A rule is not considered preserved merely because a superficially similar mechanic exists. The numerical values and interactions stated by Velmad must be represented unless a later accepted evidence-backed decision explicitly supersedes them.

## Important limitation of the source

The Velmad v1.2 manual itself states that the detailed movement and combat damage-calculation systems were omitted from the published rules because those aspects were automated by the computer. Therefore:

- rules explicitly stated in the manual are normative baseline requirements;
- algorithms that the manual explicitly does not provide must not be invented and called 'Velmad';
- for those omitted algorithms, the stable playable implementation and any recoverable original behavior may be used as implementation references, but provenance and uncertainty must be documented;
- later historical refinement still requires evidence under ADR-0001.

## Consequences

- `hull == 0` must not mean automatic sinking. Velmad hull-0 behavior, sinking risk, first-battery restriction and recovery to hull 1 must be represented before a replacement damage model is considered.
- Fire, dragging/fouled fallen masts, cutting parties, helm damage states, morale, surrender, prizes, boarding, fatigue, crew quality, ammunition loading, wind-position shooting effects and all other applicable manual systems are mandatory baseline work rather than optional future embellishments.
- UI work must expose the information and actions needed to operate those mechanics without forcing permanent panels to occupy the battle area.
- A mechanical-compliance matrix is a release gate for the historical simulator.

## Relationship to earlier decisions

This ADR **does not repeal ADR-0001**. ADR-0001 still governs how evidence-backed improvements are evaluated. ADR-0004 changes the order of work: first reproduce the complete Velmad v1.2 baseline; then evaluate improvements or additions one by one.