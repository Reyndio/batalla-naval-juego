# ROADMAP

## Milestone 1 — Historical 1v1 Simulator

Goal: deliver a deep, historically grounded duel simulator between real age-of-sail warships using one shared simulation engine for Human vs Human, Human vs AI, and AI vs AI.

### Phase 0 — Project foundation

- GitHub as source of truth.
- Canonical development branch and minimal-recovery workflow.
- Preserve current prototype.
- Establish documentation, research, decision, and testing conventions.

### Phase 1 — Mechanics archaeology and specification

- Extract Velmad v1.2 mechanics into a structured matrix.
- Audit the current prototype against that matrix.
- Mark retained, missing, simplified, uncertain, and candidate-improvement mechanics.
- Research historical evidence for improvements before changing behavior.

### Phase 2 — Simulation architecture

- Separate simulation state/rules from UI and rendering.
- Define deterministic turn-resolution pipeline where practical.
- Introduce seeded randomness for reproducible tests and replays.
- Define ship/component data schemas independent of UI.

### Phase 3 — Sailing and wind

- Points of sail and ship-specific sailing performance.
- Wind direction and strength.
- Sail states and transitions.
- Acceleration/deceleration and loss of way.
- Rudder response and turning inertia.
- Tacking and wearing.
- Leeway.
- Heel and its consequences.
- Rigging/mast damage effects on maneuvering.
- Sea-state interactions where evidence supports them.

### Phase 4 — Artillery and ammunition

- Batteries by deck/side and actual weapon types.
- Historical calibers and carronades where period-appropriate.
- Reload state carried between turns.
- Round shot, bar/chain shot, grape, double shot, and historically justified combinations.
- Firing arcs, elevation, range, dispersion, smoke, heel, and crew effects.

### Phase 5 — Impact and damage model

- Resolve impacts against physical/functional ship components rather than only global hit points.
- Hull structure and waterline consequences.
- Masts, yards, standing/running rigging, sails.
- Guns and gun crews.
- Rudder and steering system.
- Crew and officers.
- Fallen/dragging masts.
- Fire, flooding, pumps, emergency work parties.
- Operational degradation, surrender, capture, and boarding.

### Phase 6 — Visibility and battle environment

- Smoke accumulation and drift.
- Light/time-of-day effects.
- Weather and visibility.
- Line of sight and target identification where appropriate.

### Phase 7 — Historical ship data

- External ship database with dated configurations.
- Dimensions, armament, crew, rig, refits, known sailing qualities, and provenance.
- Technical sheet, history, plans, and illustrations for each playable ship.
- Explicit confidence/provenance for documented, reconstructed, estimated, and unknown values.

### Phase 8 — Play modes

- Human vs AI.
- Human vs Human.
- AI vs AI for testing and model tournaments.
- Shared rules and no hidden gameplay advantages by controller type.

### Phase 9 — Validation and first polished scenario

- Automated rule tests.
- Reproducible benchmark scenarios.
- Historical plausibility review.
- One complete historical or historically plausible 1v1 duel using real ships.
- Player-facing UI refinement after core mechanics stabilize.

## Later milestones — intentionally deferred

- Multi-ship fleet battles.
- Historical signal command and admiral/captain hierarchy.
- Long asynchronous official battles.
- Career, ranks, merit, command assignment/auction systems.
- Discipline and courts martial.
- Community/forum layer.
- Corsairs and pirates.
