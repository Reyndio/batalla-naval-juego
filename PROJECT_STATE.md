# PROJECT STATE

Last updated: 2026-09-18

## Canonical branch

`develop/historical-simulator`

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

## Current status

- Original playable prototype frozen at `archive/prototype-v1`, pointing to commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8` (the last prototype commit before project-structure metadata was added).
- `main` remains the stable/default branch and contains the project pointer used to discover the canonical development branch.
- Canonical historical-simulator development branch: `develop/historical-simulator`.
- ChatGPT Project configured to use GitHub as the source of truth.
- Velmad v1.2 recovered and adopted as the foundational mechanics baseline, subject to evidence-based historical improvement.
- Render connection verified: `batalla-naval-juego-1` is the current functional Node service on `main`; the older `batalla-naval-juego` service is a failed Docker deployment and is not the stable reference.
- No simulation-engine refactor has started yet.
- An early visible development pilot is approved: four real historical ships in a limited 2v2 scenario, with balance achieved through historical ship/configuration selection rather than invented stat bonuses.
- Side-composition rule: each side must be one coherent navy/nation; no mixed-national allied teams in this pilot.
- Working quartet: **HMS Bellerophon + HMS Conqueror versus Montañés + Bahama**.
- ADR-0002 allows balance to choose among genuinely documented dated configurations of an individual vessel, but forbids synthetic best-of-all-dates ships, arbitrary interpolation and use of weak source uncertainty as a tuning slider.
- The configuration-envelope research pass is complete. It found that the best-balanced supportable set is still the common **19–21 October 1805 / Trafalgar configuration set** rather than a mixture of dates.
- The four working pilot configurations are now frozen for data-spec work unless stronger primary evidence forces correction:
  - **HMS Bellerophon, 21 Oct 1805:** 28 x 32-pdr, 28 x 18-pdr, 18 x 9-pdr, 2 x 32-pdr carronades, 6 x 18-pdr carronades; working action complement 522, with men-borne/muster fields to remain separate.
  - **HMS Conqueror, 21 Oct 1805:** 28 x 32-pdr, 30 x 18-pdr, 16 x 9-pdr, 2 x 32-pdr carronades, 6 x 18-pdr carronades; working action complement 573. The stronger 1803 establishment remains documented as an alternative but is not selected.
  - **Montañés, 19–21 Oct 1805:** 28 x 36-lb, 30 x 18-lb, 8 x 8-lb, 10 x 30-lb obuses; **76 counted principal combat pieces**; working complement 749. Do not convert the later `76/80` wording into four unidentified combat guns.
  - **Bahama, 19–21 Oct 1805:** 28 x 24-lb, 30 x 18-lb, 10 x 8-lb, 6 x 30-lb obuses, 4 x 24-lb obuses; **78 counted principal pieces**; small pedreros documented separately; working operational complement 689, while 702 remains recorded as a secondary-source discrepancy.
- Coarse pair-level screening using nominal projectile mass gives approximately 790.6 kg per full broadside for the selected British pair and 800.6 kg for the selected Spanish pair, about a 1.3% Spanish aggregate edge. This is a screening diagnostic only, not a combat-value score.
- The selected pairs remain tactically different: the British pair has more nominal long-gun broadside mass on this screen, while the Spanish pair has more nominal projectile mass in short obus armament. Obuses and carronades are not treated as equivalent weapons.
- Crew headcount remains substantially asymmetric: selected action/operational figures total 1,095 British versus 1,438 Spanish. This will not be tuned away by cross-date crew cherry-picking; crew composition and evidence-based quality/training must be modeled separately.
- Montañés working technical length is now **190 pies de Burgos**; the 194-foot value remains documented as a conflicting secondary figure pending direct primary-plan dimension extraction.
- Research notes:
  - `docs/research/HISTORICAL_SHIPS_2V2_CANDIDATE_SELECTION.md`
  - `docs/research/HISTORICAL_SHIPS_2V2_CONFIGURATION_ENVELOPE.md`
- Balance/configuration policy: `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`.

## Branch roles

- `archive/prototype-v1`: immutable historical snapshot of the current prototype; do not develop on this branch.
- `main`: stable/default branch and discovery entry point. Do not use for normal development.
- `develop/historical-simulator`: canonical integration branch for the new historical simulator.
- `feature/*`: short-lived branches for substantial mechanics, architecture, UI, data, or multiplayer work; merge back into the canonical development branch after validation.

Long-term, stable releases from the historical simulator may be promoted to `main` once ready. The archived prototype remains available regardless.

## Immediate objective

Finish the historical data specification for the selected four 1805 configurations, then execute the first visible vertical pilot: replace generic/approximate ship definitions with sourced historical ship records and add a second ship to each side in a controlled 2v2 development scenario.

This pilot must not turn into a general fleet-battle implementation. Its purpose is to validate historical ship data, rendering, ship identity/state, targeting and multi-ship assumptions while preserving existing mechanics as much as practical.

Detailed plan: `docs/plans/HISTORICAL_SHIPS_2V2_PILOT.md`.

**Research gate remains open:** configuration selection is frozen, but do not begin programming until the four ship technical sheets, measurement conventions, provenance and remaining important uncertainties are documented to an acceptable level.

## Next task

Complete the four selected 1805 technical sheets before code changes:

1. Create one sourced technical sheet each for Bellerophon, Conqueror, Montañés and Bahama, with every field labelled `documented`, `reconstructed`, `estimated` or `unknown`.
2. Preserve Bellerophon's `action complement` separately from `borne/on-books/muster` values instead of forcing one crew number.
3. Attach British and Spanish measurement/weight conventions to every dimension/calibre conversion; original historical units remain primary data and SI values derived metadata.
4. Extract mast/rig/sail evidence from surviving plans where supportable, especially the 1806 Montañés 13-plan set.
5. Record individual sailing-quality evidence without inventing polar curves or numerical performance not supported by sources.
6. Finish plan/illustration rights review: Montañés digital plans are CC BY 4.0 with required attribution; Royal Museums Greenwich material needs licensing review before redistribution as game assets.
7. Record crew composition and training evidence separately from raw headcount; do not assign arbitrary quality tiers merely to balance the scenario.
8. Once the research gate closes, inspect current code for one-player/one-AI/one-ship assumptions.
9. Only then create a dedicated `feature/*` branch, implement the smallest safe 2v2 vertical slice, add tests and deploy only to a development Render service.

The mechanics matrix remains required, but it will be expanded incrementally by subsystem rather than blocking all early experimentation.

## Important decisions

- GitHub is the project source of truth.
- Old chats are supporting history, not authoritative project state.
- Velmad v1.2 is a strong baseline, not an immutable canon.
- Improvements require solid documentary support; intuition alone is insufficient.
- The first major polished deliverable remains the historical 1v1 simulator.
- A limited 2v2 development pilot is permitted before that milestone to expose multi-ship assumptions and make the transition to real historical ships visible.
- Every pilot ship must be a real historical vessel in a dated configuration.
- Each 2v2 side must be nationally coherent: two vessels from one navy versus two from another.
- Balance may choose among genuinely documented, internally coherent dated configurations for an individual ship.
- Historical configuration choice must not become free tuning: no synthetic best-of-all-dates configuration, arbitrary interpolation or use of weak source uncertainty merely because one value is convenient.
- If one interpretation is materially better supported, evidence takes precedence over balance.
- The selected pilot configurations are all 19–21 October 1805; this was reached after comparing alternatives, not imposed in advance.
- Do not alter historical ship characteristics merely to force equality.
- Do not use raw crew totals as a proxy for crew quality or gunnery effectiveness.
- Do not directly compare British `tons burthen` with Spanish `arqueo/desplazamiento` as if they were identical measures.
- No programming until the historical data/specification gate is closed.
- Preserve the frozen current prototype while the replacement engine is developed and validated.
- Do not maintain two independently evolving simulator codebases.
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
- `docs/research/HISTORICAL_SHIPS_2V2_CONFIGURATION_ENVELOPE.md`.
- `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`.
- Digital archaeology/recovery report for Velmad and surviving community sources.
- Existing `batalla-naval-juego` prototype code, frozen at `archive/prototype-v1`.

Source files should be added to the repository only when licensing/copyright and repository-size considerations are appropriate. Derived research notes must clearly identify provenance.
