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
- Historical 2v2 candidate research has started. The current working quartet is **HMS Bellerophon + HMS Conqueror versus Montañés + Bahama**, all to be represented in their **21 October 1805 / Trafalgar** configurations.
- The pilot's side-composition rule is now explicit: each side must be a coherent single navy/nation; do not create mixed-national teams merely because the nations were allies.
- The quartet is not yet frozen for implementation. Exact dated configuration conflicts remain open, especially Conqueror's 1805 upperworks armament, Montañés's 76/80-piece discrepancy, Bellerophon's borne-vs-action complement, Bahama's 689/702 complement discrepancy, and the Montañés 190/194 Spanish-foot length convention.
- Research note: `docs/research/HISTORICAL_SHIPS_2V2_CANDIDATE_SELECTION.md`.

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

**Research gate:** do not begin programming the 2v2 pilot until the four dated ship configurations, source provenance and important unresolved discrepancies have been documented to an acceptable level.

## Next task

Continue research on the working quartet before any code changes:

1. Resolve HMS Conqueror's exact Trafalgar upperworks battery/carronade fit.
2. Resolve Montañés's 76-versus-80 counted-piece discrepancy directly from the 19 October 1805 force state or an authoritative reproduction.
3. Resolve dated complement fields for Bellerophon and Bahama while preserving distinctions such as men borne versus men available in action.
4. Resolve Montañés's 190-versus-194 Spanish-foot length field by identifying the measurement convention in the original plan material.
5. Document British and Spanish measurement/weight conventions before converting values for simulation.
6. Extract dated dimensions, armament, crew, rig/sailing evidence, history, plans/illustrations and confidence/provenance into one technical sheet per ship.
7. Review image/plan licensing and attribution requirements.
8. Only after the research gate is closed: inspect current code for one-player/one-AI/one-ship assumptions, create a dedicated `feature/*` branch, implement the smallest safe 2v2 vertical slice, and deploy only to a development Render service.

The mechanics matrix remains required, but it will now be expanded incrementally by subsystem rather than blocking all early experimentation.

## Important decisions

- GitHub is the project source of truth.
- Old chats are supporting history, not authoritative project state.
- Velmad v1.2 is a strong baseline, not an immutable canon.
- Improvements require solid documentary support; intuition alone is insufficient.
- The first major polished deliverable remains the historical 1v1 simulator.
- A limited 2v2 development pilot is permitted before that milestone to expose multi-ship assumptions and make the transition to real historical ships visible.
- Every pilot ship must be a real historical vessel in a dated configuration.
- For the 2v2 pilot, each opposing side must be nationally coherent: two vessels from one navy versus two vessels from another navy. Mixed-national allied teams are out of scope for this pilot.
- Do not alter historical ship characteristics merely to balance the scenario.
- If one primary ship is stronger, compensate first through selection of the second historical ship on each side; document any residual asymmetry.
- Do not begin 2v2 implementation until historical source/configuration research is sufficiently resolved.
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
- `docs/research/HISTORICAL_SHIPS_2V2_CANDIDATE_SELECTION.md`.
- Digital archaeology/recovery report for Velmad and surviving community sources.
- Existing `batalla-naval-juego` prototype code, frozen at `archive/prototype-v1`.

Source files should be added to the repository only when licensing/copyright and repository-size considerations are appropriate. Derived research notes must clearly identify provenance.
