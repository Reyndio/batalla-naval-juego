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
- An early visible development pilot has been approved: four real historical ships in a limited 2v2 scenario, with balance achieved through historical ship/configuration selection rather than invented stat bonuses.
- Historical 2v2 candidate research has started. The current working quartet is **HMS Bellerophon + HMS Conqueror versus Montañés + Bahama**.
- The pilot's side-composition rule is explicit: each side must be a coherent single navy/nation; do not create mixed-national teams merely because the nations were allies.
- The initial common-date target was 21 October 1805 / Trafalgar, but the pilot may now select a different documented dated configuration for an individual vessel when several historically valid configurations exist and doing so improves overall 2v2 balance.
- This configuration freedom is strictly evidence-bounded: do not synthesize a best-of-all-dates ship, do not treat source uncertainty as a tuning slider, and use the better-supported interpretation when evidence is unequal.
- If the final quartet uses different configuration dates, the pilot will be described as a historically plausible development scenario rather than an exact Trafalgar-date recreation.
- The quartet is not yet frozen for implementation. Important configuration/source conflicts remain open, especially Conqueror's upperworks armament, Montañés's counted-piece discrepancy, Bellerophon's borne-vs-action complement, Bahama's complement discrepancy, and the Montañés Spanish-foot length convention.
- Research note: `docs/research/HISTORICAL_SHIPS_2V2_CANDIDATE_SELECTION.md`.
- Balance/configuration policy: `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`.

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

**Research gate:** do not begin programming the 2v2 pilot until the four selected dated ship configurations, source provenance and important unresolved discrepancies have been documented to an acceptable level.

## Next task

Continue research on the working quartet before any code changes:

1. Build the set of genuinely documented dated configurations available for HMS Bellerophon, HMS Conqueror, Montañés and Bahama in the relevant period.
2. Resolve HMS Conqueror's conflicting upperworks battery/carronade evidence and identify which dated configurations are supportable.
3. Resolve Montañés's counted-piece discrepancy from the 19 October 1805 force state or an authoritative reproduction, while checking whether other dated configurations are better documented and useful for balance.
4. Resolve dated complement fields for Bellerophon and Bahama while preserving distinctions such as men borne versus men available in action.
5. Resolve Montañés's Spanish-foot length field by identifying the measurement convention in the original plan material.
6. Document British and Spanish measurement/weight conventions before converting values for simulation.
7. Compare the historically valid configuration combinations at pair level and select the quartet configuration set that gives the best balance without violating evidence quality or internal coherence.
8. Extract dimensions, armament, crew, rig/sailing evidence, history, plans/illustrations and confidence/provenance into one technical sheet per selected dated configuration.
9. Review image/plan licensing and attribution requirements.
10. Only after the research gate is closed: inspect current code for one-player/one-AI/one-ship assumptions, create a dedicated `feature/*` branch, implement the smallest safe 2v2 vertical slice, and deploy only to a development Render service.

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
- For this pilot, when an individual vessel has multiple genuinely documented and internally coherent dated configurations, balance may be used to choose among those configurations.
- Historical configuration choice must not become free tuning: no synthetic best-of-all-dates configuration, no arbitrary interpolation, and no use of weak source uncertainty merely because one value is convenient for balance.
- If one interpretation is materially better supported than another, the better-supported interpretation takes precedence over balance.
- If configuration choice is insufficient, compensate through ship selection and document residual asymmetry rather than inventing modifiers.
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
- `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`.
- Digital archaeology/recovery report for Velmad and surviving community sources.
- Existing `batalla-naval-juego` prototype code, frozen at `archive/prototype-v1`.

Source files should be added to the repository only when licensing/copyright and repository-size considerations are appropriate. Derived research notes must clearly identify provenance.
