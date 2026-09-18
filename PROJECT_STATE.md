# PROJECT STATE

Last updated: 2026-09-18

## Canonical branch

`develop/historical-simulator`

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

## Current status

- Existing prototype preserved and runnable on `main`.
- Canonical historical-simulator development branch created.
- ChatGPT Project configured to use GitHub as the source of truth.
- Startup/recovery workflow established through `PROJECT_POINTER.md` on `main` and `START_HERE.md` on the canonical branch.
- Velmad v1.2 recovered and adopted as the foundational mechanics baseline.
- Historical-enhancement policy agreed: improve Velmad mechanics when solid historical, technical, or physical evidence supports a better model.
- No simulation-engine refactor has started yet.

## Immediate objective

Create the complete mechanics inventory and gap analysis before changing simulation behavior.

The inventory must compare:

1. Velmad v1.2 documented mechanics.
2. Mechanics currently implemented in the existing prototype.
3. Missing mechanics.
4. Candidate historical improvements.
5. Evidence required before changing each mechanic.

## Next task

Build `docs/rules/MECHANICS_MATRIX.md`, beginning with:

- sailing speed;
- points of sail;
- rudder and turn inertia;
- tacking and wearing;
- sail states;
- wind strength and direction;
- heel;
- leeway;
- mast/rigging damage effects on sailing.

Do not alter gameplay code until this first mechanics inventory is sufficiently complete to define the navigation work.

## Important decisions

- GitHub is the project source of truth.
- Old chats are supporting history, not authoritative project state.
- Velmad v1.2 is a strong baseline, not an immutable canon.
- Improvements require solid documentary support; intuition alone is insufficient.
- The first major playable deliverable is the 1v1 historical simulator, not career/meta systems.
- Preserve the current prototype while the replacement engine is developed and validated.
- Major visual redesign is deferred until core mechanics and damage systems are substantially mature.

## Explicitly deferred

- naval career progression;
- rank and command auctions;
- disciplinary/court-martial system;
- corsairs and pirates;
- scheduled large historical multiplayer battles;
- forums/community systems;
- large-scale fleet command;
- major presentation/UI redesign.

## Known reference material

- Velmad — Sea at War / Battles at Sea — Rules v1.2.
- Digital archaeology/recovery report for Velmad and surviving community sources.
- Existing `batalla-naval-juego` prototype code.

Source files should be added to the repository only when licensing/copyright and repository-size considerations are appropriate. Derived research notes must clearly identify provenance.
