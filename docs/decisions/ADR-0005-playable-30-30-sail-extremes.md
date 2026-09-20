# ADR-0005 — Playable 30/30 extreme sail reconstruction

Date: 2026-09-20
Status: accepted project reconstruction, pending stronger source evidence

## Context

Velmad v1.2 contains mutually difficult-to-reconcile fatigue lines in the translated rules:

- `Making full sail`: +30% fatigue;
- `Remove all sailing`: +30% fatigue;
- `Collect all the sail (pass to no sail)`: +40% fatigue;
- no sail to few/medium sail: +20% fatigue.

The text does not define a unique operational difference between `Remove all sailing` and `Collect all the sail (pass to no sail)`. Treating both as the same TV→NV action would assign two costs to one transition.

Direct user recollection from having played Velmad is that no 40% sail action was used and that the extreme transition behaved symmetrically at 30% in each direction. That recollection is useful reconstruction evidence but is not equivalent to documentary proof.

## Decision

For the playable historical-simulator branch:

- direct `NV → TV` costs +30% fatigue;
- direct `TV → NV` costs +30% fatigue;
- the 30/30 reconstruction applies specifically to the one-action transition between those two extremes;
- it must **not** be generalized as `any sail state → NV = +30%`;
- `PV → NV` and `MV → NV` therefore do not inherit the reconstructed +30% extreme cost;
- the explicit `Making full sail: +30%` line remains active for an order that ends at `TV`, including from PV/MV;
- `NV → PV` and `NV → MV` retain the explicit +20% rule;
- the literal +40% line remains recorded in the compliance matrix as a source conflict.

The 30/30 rule is therefore labelled **PROJECT RECONSTRUCTION**, not `VERIFIED literal Velmad v1.2 text`.

## Rationale

This choice keeps the game playable, matches direct recollection of the original game, preserves the unambiguous 30% `Making full sail` line, and avoids inventing an undocumented distinction merely to make the translated 30/40 wording internally consistent.

Historical seamanship research reviewed during the decision did not establish a general fixed rule that gathering all sail was intrinsically one third more fatiguing than making all sail. Weather and sail load can make shortening sail substantially harder in particular conditions, but that is not evidence for a universal 40/30 fatigue ratio.

The implementation also keeps the direct extreme action distinct in the UI: the explicit `TV→NV directo (+30%)` action is only enabled while actually at TV, and `NV→TV directo (+30%)` only while actually at NV. Ordinary intermediate sail orders continue through the main sail controls.

## Reversibility

If original Spanish rules, executable Velmad behavior, v1.3 notes, source code, or other primary evidence resolves the conflict, this ADR may be superseded and the mechanic/test expectations changed accordingly.
