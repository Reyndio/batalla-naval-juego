# ADR-0003 — Preserve proven prototype interaction affordances

Date: 2026-09-18
Status: Proposed for merge after visual user validation

## Context

The first historical 2v2 vertical slice successfully validated four-ship state, targeting and deployment, but its browser interface replaced the mature prototype interaction model with a simplified control surface and minimal triangular ship markers.

Direct playtest feedback identified this as a material regression rather than an acceptable temporary presentation simplification. The lost or degraded affordances included:

- recognizable top-down ship silhouettes;
- visible differences between NV, PV, MV and TV sail states;
- projected movement shadow;
- full helm command range and familiar helm controls;
- direct port/starboard firing controls;
- firing section and ammunition controls;
- tactical hover information;
- map panning / recentering;
- familiar keyboard control flow;
- immediate visual distinction between current state and ordered state.

The project goal is to improve the historical simulator without discarding useful depth already present in the prototype.

## Decision

New historical-simulator interfaces must preserve useful, already-proven interaction affordances from the frozen prototype unless a replacement is demonstrably clearer or more capable.

For the current 2v2 regression scenario, restore the prototype interaction language while keeping the new multi-ship state and historical data boundary:

1. render ships as recognizable top-down hulls with masts and visible sail state, not abstract triangles;
2. preserve NV/PV/MV/TV as explicit commands and show their meaning in the UI;
3. show a projected movement shadow for the selected ship before resolving a turn;
4. restore helm controls through ±4;
5. restore explicit Babor/Estribor fire commands, target, section, aim and ammunition controls;
6. restore tactical firing arcs and hover information;
7. restore right-button map panning, camera recentering and keyboard shortcuts, with zoom added as a non-destructive enhancement;
8. distinguish actual state from ordered state visually;
9. keep orders independent per controlled ship in the 2v2 scenario;
10. do not claim that restored legacy UI/mechanics are finalized historical physics merely because they existed in the prototype.

## Architectural consequence

This does **not** reverse the decision to separate the shared simulation engine from the UI. Interaction parity is a product requirement for the replacement, not a reason to keep the old monolithic architecture.

The restored 2v2 page remains a regression scenario and development surface. Common mechanics should still migrate into the shared historical engine.

## Validation requirement

Automated tests may verify the presence and wiring of interaction features, but visual/ergonomic acceptance requires an actual human playtest. Therefore this ADR remains proposed until the corrected development deployment is visually reviewed.
