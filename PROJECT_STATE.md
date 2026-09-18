# PROJECT STATE

Last updated: 2026-09-18

## Canonical branch

`develop/historical-simulator`

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

## Current status

- Original playable prototype frozen at `archive/prototype-v1`, pointing to commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8` (the last prototype commit before project-structure metadata was added).
- `main` remains the stable/default branch and contains the project pointer used to discover the canonical development branch.
- Canonical historical-simulator development branch created at `develop/historical-simulator`.
- ChatGPT Project configured to use GitHub as the source of truth.
- Startup/recovery workflow established through `PROJECT_POINTER.md` on `main` and `START_HERE.md` on the canonical branch.
- Velmad v1.2 recovered and adopted as the foundational mechanics baseline.
- Historical-enhancement policy agreed: improve Velmad mechanics when solid historical, technical, or physical evidence supports a better model.
- Render connection verified: `batalla-naval-juego-1` is the current functional Node service on `main`; the older `batalla-naval-juego` service is a failed Docker deployment and is not the stable reference.
- No simulation-engine refactor has started yet.
- An early visible development pilot has been approved: four real historical ships in a limited 2v2 scenario, with balance achieved through historical ship selection rather than invented stat bonuses.

## Branch roles

- `archive/prototype-v1`: immutable historical snapshot of the current prototype; do not develop on this branch.
- `main`: stable/default branch and discovery entry point. Do not use for normal development.
- `develop/historical-simulator`: canonical integration branch for the new historical simulator.
- `feature/*`: short-lived branches for substantial mechanics, architecture, UI, data, or multiplayer work; merge back into the canonical development branch after validation.

Long-term, stable releases from the historical simulator may be promoted to `main` once they are ready. The archived prototype remains available regardless.

## Immediate objective

Execute the first visible vertical pilot: replace generic/approximate ship definitions with sourced historical ship records and add a second ship to each side in a controlled 2v2 development scenario.

This pilot must not turn into a general fleet-battle implementation. Its purpose is to validate historical ship data, rendering, ship identity/state, targeting and multi-ship assumptions while preserving the existing mechanics as much as practical.

Detailed plan: `docs/plans/HISTORICAL_SHIPS_2V2_PILOT.md`.

## Next task

In a new dedicated chat:

1. Research candidate ships from the 18th or early 19th century.
2. Select four real vessels with strong source coverage and sufficiently comparable pair composition.
3. Document dated configurations, dimensions, armament, crew, rig/sailing evidence, history, plans/illustrations and confidence/provenance.
4. Inspect the current code for one-player/one-AI/one-ship assumptions.
5. Create a dedicated `feature/*` branch only after the research/specification is sufficiently concrete.
6. Implement the smallest safe 2v2 vertical slice.
7. Deploy only to a development Render service, leaving `batalla-naval-juego-1` untouched as the stable reference.

The mechanics matrix remains required, but it will now be expanded incrementally by subsystem rather than blocking all early experimentation.

## Important decisions

- GitHub is the project source of truth.
- Old chats are supporting history, not authoritative project state.
- Velmad v1.2 is a strong baseline, not an immutable canon.
- Improvements require solid documentary support; intuition alone is insufficient.
- The first major polished deliverable remains the historical 1v1 simulator.
- A limited 2v2 development pilot is permitted before that milestone to expose multi-ship assumptions and make the transition to real historical ships visible.
- Every pilot ship must be a real historical vessel in a dated configuration.
- Do not alter historical ship characteristics merely to balance the scenario.
- If one primary ship is stronger, compensate first through selection of the second historical ship on each side; document any residual asymmetry.
- Preserve the frozen current prototype while the replacement engine is developed and validated.
- Do not maintain two independently evolving simulator codebases. Preserve the old executable as an archive; evolve the new simulator on the canonical branch and use explicit rulesets/configuration when baseline-vs-enhanced behavior must remain comparable.
- Major visual redesign remains deferred, but historically differentiated ship scale/silhouette and technical data are in scope for the 2v2 pilot.

## Explicitly deferred

- full fleet-battle command beyond the limited 2v2 pilot;
- naval career progression;
- rank and command auctions;
- disciplinary/court-martial system;
- corsairs and pirates;
- scheduled large historical multiplayer battles;
- forums/community systems;
- admiral/division signal command;
- major presentation/UI redesign unrelated to the historical-ship pilot.

## Known reference material

- Velmad — Sea at War / Battles at Sea — Rules v1.2.
- Digital archaeology/recovery report for Velmad and surviving community sources.
- Existing `batalla-naval-juego` prototype code, frozen at `archive/prototype-v1`.

Source files should be added to the repository only when licensing/copyright and repository-size considerations are appropriate. Derived research notes must clearly identify provenance.
