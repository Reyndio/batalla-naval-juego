# PROJECT STATE

Last updated: 2026-09-18

## Canonical branch

`develop/historical-simulator`

Active validated feature branch: `feature/historical-2v2-pilot`

## Current milestone

**Milestone 1 — Historical 1v1 Simulator**

The Historical 1v1 milestone remains the primary polished goal. The limited historical 2v2 pilot is now a playable validated development slice, not the final fleet engine.

## Current status

- Original playable prototype remains frozen at `archive/prototype-v1`, commit `31fe6620cf262bbe99cf680363a6962d4ddc26f8`.
- `main` remains the stable/default discovery branch and was not modified by this pilot.
- Canonical integration branch remains `develop/historical-simulator`.
- Stable Render reference service `batalla-naval-juego-1` remains on `main` and was not altered.
- Velmad v1.2 remains the foundational mechanics baseline, subject to evidence-based historical improvement.
- National-side rule remains fixed: one coherent navy per side; no mixed-national allied teams in this pilot.

### Historical 2v2 ship set

Selected October 1805 configurations:

- **Royal Navy**
  - HMS Bellerophon: 28×32-pdr, 28×18-pdr, 18×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; working action complement 522.
  - HMS Conqueror: 28×32-pdr, 30×18-pdr, 16×9-pdr, 2×32-pdr carronades, 6×18-pdr carronades; working action complement 573.
- **Real Armada**
  - Montañés: 28×36-lb, 30×18-lb, 8×8-lb, 10×30-lb obuses; 76 counted principal combat pieces; working complement 749.
  - Bahama: 28×24-lb, 30×18-lb, 10×8-lb, 6×30-lb obuses, 4×24-lb obuses; 78 counted principal pieces; working operational complement 689; 702 retained as a secondary-source discrepancy.

Coarse nominal broadside screening remains approximately 790.6 kg for the British pair versus 800.6 kg for the Spanish pair, about a 1.3% Spanish aggregate edge. This remains a research diagnostic, not a combat-value score.

### Research gate

The research gate for the **limited first playable 2v2 vertical slice is closed**.

Four sourced technical sheets and an implementation data specification exist. Unsupported individual sailing curves, crew-quality multipliers, reload bonuses, structural HP and similar values remain outside the historical ship-data layer and are explicitly provisional mechanics.

### Playable implementation

The feature branch now contains:

- `data/historical_ships_1805.json` — externalized sourced ship records;
- `src/pilot2v2-core.js` — reusable four-ship pilot simulation core;
- `pilot-2v2.html` — playable browser interface;
- `tests/pilot2v2.test.js` — state, targeting, battle-completion, UI-wiring and HTTP route tests;
- Render-ready `/pilot` and `/health` routes in `server.js`.

Human control:

- one player issues independent orders to HMS Bellerophon and HMS Conqueror;
- each ship can retain its own target, sail, rudder, fire and aim orders.

AI control:

- Montañés and Bahama are independently controlled by the pilot AI;
- AI now closes range, seeks broadside geometry, retains firing solutions and recovers from map boundaries.

### Validation

A test added after the first deployment intentionally required an AI-vs-AI engagement to reach a battle result. It exposed a genuine manoeuvre-loop defect: the first AI could remain in combat indefinitely. The failing deployment was not accepted. AI manoeuvring was corrected and the benchmark then passed.

The validated build subsequently passed:

- historical side coherence;
- frozen ship-data integrity;
- independent four-ship state;
- side-safe targeting;
- long-run numerical integrity;
- AI-vs-AI battle completion;
- independent human-side orders/targets;
- pilot page wiring;
- real localhost HTTP smoke checks for `/health`, `/pilot` and the ship-data JSON.

Latest fully observed test run: **9 tests, 9 passed, 0 failed**.

### Development deployment

Dedicated Render service:

- service name: `batalla-naval-2v2-dev`
- branch: `feature/historical-2v2-pilot`
- public base URL: `https://batalla-naval-2v2-dev.onrender.com`
- playable route: `https://batalla-naval-2v2-dev.onrender.com/pilot`
- build command: `npm install && npm test`
- start command: `npm start`
- auto-deploy: enabled

The deployment is isolated from the stable reference service.

Validation report:

- `docs/reports/HISTORICAL_2V2_PILOT_PLAYTEST.md`

### Known limitations / technical debt

- The pilot is a historically plausible development scenario, not an exact historical 2v2 action at Trafalgar.
- Sailing response remains a shared provisional 74-gun baseline; documented qualitative differences are recorded but not converted into invented numerical bonuses.
- Hull/rig HP, range falloff, collision damage, casualties and AI logic remain provisional mechanics.
- Current pilot damage uses documented long-gun broadside mass as historical input; British carronades and Spanish obuses are stored separately and are not treated as equivalent.
- Component damage, final artillery, ammunition, smoke, morale, fatigue, fire, flooding, surrender, capture and boarding remain future subsystem work.
- Full browser visual automation has not been performed; the build does exercise the page/data through an actual local HTTP server.
- `npm install` reports 15 inherited dependency vulnerabilities: 2 low, 3 moderate, 9 high and 1 critical. No blind `npm audit fix --force` was applied. Dependency remediation requires a separate controlled pass.

## Historical research files

- `docs/research/HISTORICAL_SHIPS_2V2_CANDIDATE_SELECTION.md`
- `docs/research/HISTORICAL_SHIPS_2V2_CONFIGURATION_ENVELOPE.md`
- `docs/research/HISTORICAL_SHIPS_2V2_DATA_SPEC.md`
- `docs/research/ships/BELLEROPHON_1805.md`
- `docs/research/ships/CONQUEROR_1805.md`
- `docs/research/ships/MONTANES_1805.md`
- `docs/research/ships/BAHAMA_1805.md`
- `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`
- `docs/reports/HISTORICAL_2V2_PILOT_PLAYTEST.md`

## Branch roles

- `archive/prototype-v1`: immutable prototype snapshot; never develop here.
- `main`: stable/default discovery entry point; do not use for normal development.
- `develop/historical-simulator`: canonical integration branch.
- `feature/historical-2v2-pilot`: validated implementation branch for this vertical slice; ready for PR/review into the canonical integration branch.

## Next task

After integration of the validated pilot, do **not** keep expanding `pilot-2v2.html` into a permanent fleet engine.

Use the pilot findings to begin the shared historical simulation-engine separation, starting with the subsystem that most affects both 1v1 and multi-ship behavior:

1. define a durable ship-state/data boundary based on the externalized historical records;
2. separate turn/order resolution from the UI;
3. begin evidence-backed sailing/manoeuvre modeling (wind, sail state, inertia, leeway, tacking/wearing and heel) while retaining a Velmad-comparable baseline mode;
4. add subsystem tests before replacing provisional pilot constants;
5. preserve 1v1 as the first polished milestone while retaining the 2v2 pilot as a regression/test scenario.

## Important decisions

- GitHub remains the source of truth.
- Historical ship records are immutable inputs except when stronger evidence requires correction.
- Balance operates through sourced ship/configuration selection, not invented bonuses.
- Raw crew count is not a proxy for crew quality or gunnery efficiency.
- British tons BM and Spanish tonnage/displacement terminology are not directly interchangeable.
- Provisional mechanics must remain clearly labelled as mechanics, not historical facts.
- Do not evolve two permanent simulator codebases; use the pilot to expose requirements, then move shared behavior into the common simulation engine.
- Preserve the frozen prototype and stable Render service throughout.

## Explicitly deferred

- full fleet command beyond the limited 2v2 regression scenario;
- admiral/division signal systems;
- career/ranks/auctions;
- disciplinary/court-martial systems;
- corsairs and pirates;
- scheduled large multiplayer battles;
- forums/community systems;
- final sailing/impact/damage physics;
- major presentation redesign unrelated to the historical simulator.
