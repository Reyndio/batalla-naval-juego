# PROJECT STATE

Last updated: 2026-09-18

## Canonical branch

`develop/historical-simulator`

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

## Current status

- Original playable prototype frozen at `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`.
- `main` remains the stable/default discovery branch; normal development does not occur there.
- Canonical integration branch: `develop/historical-simulator`.
- Velmad v1.2 is the mechanics baseline, subject to evidence-based historical improvement.
- Stable Render reference service: `batalla-naval-juego-1` on `main`; it must remain untouched by pilot development.
- Early historical 2v2 vertical pilot approved to expose multi-ship assumptions before the full 1v1 engine refactor.
- Side rule fixed: one coherent navy per side; no mixed-national allied teams in this pilot.
- Selected quartet: **HMS Bellerophon + HMS Conqueror vs Montañés + Bahama**.
- ADR-0002 allows balance to choose among genuinely documented dated configurations, but forbids synthetic best-of-all-dates ships or arbitrary tuning of historical records.
- Configuration-envelope research found that the best-balanced supportable set remains the common **19–21 October 1805 / Trafalgar** set.
- Selected working configurations:
  - HMS Bellerophon: 28×32-pdr, 28×18-pdr, 18×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; action complement 522.
  - HMS Conqueror: 28×32-pdr, 30×18-pdr, 16×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; action complement 573.
  - Montañés: 28×36-lb, 30×18-lb, 8×8-lb, 10×30-lb obuses; 76 counted principal combat pieces; complement 749.
  - Bahama: 28×24-lb, 30×18-lb, 10×8-lb, 6×30-lb obuses, 4×24-lb obuses; 78 counted principal pieces; operational complement 689, with 702 retained as a secondary-source discrepancy.
- Coarse nominal broadside screen: British pair ≈790.6 kg, Spanish pair ≈800.6 kg, about 1.3% Spanish aggregate edge. This is a research diagnostic, not a combat-value score.
- Research gate for the **limited first playable 2v2 vertical slice is now CLOSED**. Four sourced technical sheets and a machine-readable implementation data specification exist.
- Unsupported individual sailing curves, crew-quality modifiers, reload bonuses and structural hit points remain outside the historical data layer. The first pilot may use shared provisional 74-gun mechanics so long as they are not presented as sourced ship characteristics.
- Current prototype code audit confirms strong one-player/one-AI/one-target assumptions in the monolithic `index.html`: globals `miNavio`, `navioObjetivo`, singular turn resolution, collision, animation, fatigue, targeting and UI paths. A separate limited 2v2 vertical slice is the smallest safe first implementation, while the legacy page remains non-evolving reference code until the later shared-engine refactor.

## Historical research files

- `docs/research/HISTORICAL_SHIPS_2V2_CANDIDATE_SELECTION.md`
- `docs/research/HISTORICAL_SHIPS_2V2_CONFIGURATION_ENVELOPE.md`
- `docs/research/HISTORICAL_SHIPS_2V2_DATA_SPEC.md`
- `docs/research/ships/BELLEROPHON_1805.md`
- `docs/research/ships/CONQUEROR_1805.md`
- `docs/research/ships/MONTANES_1805.md`
- `docs/research/ships/BAHAMA_1805.md`
- `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`

## Branch roles

- `archive/prototype-v1`: immutable prototype snapshot; never develop here.
- `main`: stable/default and discovery entry point; do not use for normal development.
- `develop/historical-simulator`: canonical integration branch.
- `feature/*`: temporary implementation branches, merged back only after validation.

## Immediate objective

Build the first playable historical 2v2 vertical slice using the frozen 1805 ship records without modifying `main` or the stable Render service.

The pilot must validate:

- four distinct historical ship records;
- two ships per national side;
- per-ship movement/damage state;
- target selection;
- simultaneous turn resolution;
- Human side control of both Royal Navy ships;
- AI control of both Spanish ships;
- battle completion without state corruption;
- historically differentiated scale/silhouette derived from source dimensions;
- clear separation between historical data and provisional pilot mechanics.

The pilot is not the final fleet engine. Full command hierarchy, signals, career systems, large battles, final sailing physics and final damage physics remain deferred.

## Next task

1. Create a dedicated feature branch from `develop/historical-simulator`.
2. Externalize the four selected historical ship records into a data file.
3. Implement the smallest playable 2v2 vertical slice with one human controller issuing orders to both Royal Navy ships and AI controlling both Spanish ships.
4. Add automated integrity/simulation tests for four-ship state, targeting and battle completion.
5. Run local/static validation from repository files.
6. Deploy only to a new development Render service; leave `batalla-naval-juego-1` untouched.
7. Perform a manual smoke/playtest and record limitations.
8. Merge or leave a PR-ready feature branch only after tests and development deployment are healthy.

## Important decisions

- GitHub is the source of truth.
- Historical ship records are immutable inputs except when stronger evidence requires correction.
- Balance operates through sourced ship/configuration selection, not invented ship bonuses.
- Raw crew count is not a proxy for crew quality or gunnery efficiency.
- British tons BM and Spanish tonnage/displacement terminology are not directly interchangeable.
- The first 2v2 pilot may share provisional mechanics across all four 74s where ship-specific numerical evidence is not yet sufficient.
- Provisional mechanics must be labelled as mechanics, not historical facts.
- Do not evolve two permanent simulator codebases. The new pilot is a temporary vertical slice used to expose requirements before the later shared simulation-engine refactor; the legacy monolithic page is not to receive parallel feature development.
- Preserve the frozen prototype and the stable Render service throughout.

## Explicitly deferred

- full fleet command beyond 2v2;
- admiral/division signal systems;
- career/ranks/auctions;
- disciplinary/court-martial systems;
- corsairs and pirates;
- scheduled large multiplayer battles;
- forums/community systems;
- final sailing/impact/damage physics;
- major presentation redesign unrelated to the pilot.
