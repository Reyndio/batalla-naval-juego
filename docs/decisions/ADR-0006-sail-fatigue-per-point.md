# ADR-0006 — Sail-change fatigue by sail point

Date: 2026-09-20
Status: accepted project rule
Supersedes for playable behavior: ADR-0005

## Context

The Velmad v1.2 fatigue text is not internally clean around sail handling. It states, among other lines, `Making full sail: +30%`, `Remove all sailing: +30%`, `Collect all the sail (pass to no sail): +40%`, and `no sail to few or medium sail: +20%`.

Earlier playable reconstruction ADR-0005 used a special direct `NV↔TV = +30%` rule while retaining other literal/manual-derived cases. Live testing showed that this produced a rule set that was harder to predict and easier to implement incorrectly.

The project owner selected a simpler abstraction based on the four ordered sail states already used by the simulator: `NV → PV → MV → TV`.

## Decision

For the playable historical-simulator branch, every adjacent sail-state point crossed costs **+10% fatigue**.

Therefore:

- no change: 0%;
- one point, e.g. `NV↔PV`, `PV↔MV`, `MV↔TV`: +10%;
- two points, e.g. `NV↔MV`, `PV↔TV`: +20%;
- three points, `NV↔TV`: +30%.

A direct jump pays the whole cost in that turn. A progressive change pays +10% for each one-point change on each turn.

The rule is symmetric in both directions.

## Source status

This is a **PROJECT RULE / DELIBERATE DIVERGENCE**, not a claim about literal Velmad v1.2.

It differs from explicit lines in the v1.2 text, notably the stated +20% from no sail to few/medium sail and the general `Making full sail: +30%` wording. The conflicting +30/+40 sail-removal wording remains preserved in the compliance documentation as source evidence.

This narrow playable divergence is explicitly owner-approved. Consequently, the fatigue row must remain PARTIAL/DIVERGENT rather than being labelled VERIFIED Velmad parity.

## Rationale

The rule has one invariant: **one sail point = 10% fatigue**. It is easy to predict, symmetric, supports both direct and progressive handling, and removes special-case behavior that caused the `PV→NV` regression.

## Reversibility

If stronger primary evidence or recovered original Velmad behavior establishes a better model, this ADR can be superseded. Any later historical refinement must state whether it replaces this game abstraction or only modifies it under particular weather, damage or crew conditions.
