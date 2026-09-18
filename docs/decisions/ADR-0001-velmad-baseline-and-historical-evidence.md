# ADR-0001 — Velmad baseline and historical evidence

Date: 2026-09-18
Status: Accepted

## Context

The project descends conceptually from Velmad, a historical age-of-sail naval wargame whose rules incorporated substantial discussion and specialist community knowledge. The recovered Velmad v1.2 rules provide a coherent baseline for navigation, artillery, damage, morale, fatigue, capture, fire, and other mechanics.

The new simulator aims to be more historically faithful where modern research and implementation capacity permit.

## Decision

Velmad v1.2 is the foundational baseline for mechanics and battle dynamics, but it is not an immutable canon.

For each mechanic:

1. Identify what real phenomenon the Velmad rule is attempting to represent.
2. Record the Velmad rule accurately.
3. Compare it with the current prototype implementation.
4. Research historical, technical, or physical evidence.
5. Keep the Velmad approach when it remains a sound representation or when evidence is insufficient to justify a change.
6. Replace or refine it when a better model is supported by solid evidence.
7. Document the evidence, uncertainty, and reason for the decision.

No mechanic should be changed merely because another treatment feels more realistic.

## Evidence classes

Historical data and rules should distinguish:

- **Documented** — directly supported by reliable primary or strong secondary evidence.
- **Reconstructed** — inferred from multiple documented facts with a defensible method.
- **Estimated** — necessary approximation where exact evidence is unavailable.
- **Hypothesis** — exploratory model not yet sufficiently supported; should not silently become canon.

## Consequences

- The simulator may diverge substantially from Velmad while preserving the phenomena Velmad attempted to model.
- Research provenance becomes part of game-system design.
- Tests should validate both computational correctness and expected historical behavior where feasible.
- Ambiguous or poorly documented points remain explicitly unresolved rather than being silently invented.
