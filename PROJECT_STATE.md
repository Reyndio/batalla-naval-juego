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
- No simulation-engine refactor has started yet.

## Branch roles

- `archive/prototype-v1`: immutable historical snapshot of the current prototype; do not develop on this branch.
- `main`: stable/default branch and discovery entry point. Do not use for normal development.
- `develop/historical-simulator`: canonical integration branch for the new historical simulator.
- `feature/*`: short-lived branches for substantial mechanics, architecture, UI, data, or multiplayer work; merge back into the canonical development branch after validation.

Long-term, stable releases from the historical simulator may be promoted to `main` once they are ready. The archived prototype remains available regardless.

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
- Preserve the frozen current prototype while the replacement engine is developed and validated.
- Do not maintain two independently evolving simulator codebases. Preserve the old executable as an archive; evolve the new simulator on the canonical branch and use explicit rulesets/configuration when baseline-vs-enhanced behavior must remain comparable.
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
- Existing `batalla-naval-juego` prototype code, frozen at `archive/prototype-v1`.

Source files should be added to the repository only when licensing/copyright and repository-size considerations are appropriate. Derived research notes must clearly identify provenance.
