# START HERE

Project: historical age-of-sail naval combat simulator.

## Source of truth

This repository is the canonical source for project state, design decisions, research policy, code, tests, and historical data.

Canonical development branch: `develop/historical-simulator`.

Branch roles:
- `archive/prototype-v1`: immutable snapshot of the original playable prototype. Never use it for normal development.
- `main`: stable/default branch and discovery entry point through `PROJECT_POINTER.md`.
- `develop/historical-simulator`: canonical integration branch for the new historical simulator.
- `feature/*`: temporary branches for substantial isolated work, merged back after validation.

## Required startup sequence

Before doing project work in a fresh chat or agent session:

1. Read `PROJECT_STATE.md`.
2. Read `ROADMAP.md` only as needed for the current task.
3. Read the relevant files under `docs/` for the task at hand.
4. Inspect the affected code before changing it.
5. When comparing against the untouched original prototype, use `archive/prototype-v1`.
6. Do not reconstruct current state from old chats when GitHub contains newer information.

## Historical simulation principle

Velmad v1.2 is a foundational, well-informed baseline for mechanics and battle dynamics.

It is not an immutable canon. A Velmad mechanic may be improved when there is solid historical, technical, or physical evidence supporting a better representation.

Rules:
- preserve useful depth already present in Velmad;
- improve mechanics when evidence supports the improvement;
- do not add "realism" based only on intuition;
- distinguish documented fact, reconstruction, estimate, and hypothesis;
- document important sources and design decisions.

## First major playable milestone

`Historical 1v1 Simulator`

Before career systems, auctions, corsairs, pirates, or large multiplayer battles, the project must deliver a deep 1v1 simulator with:

- improved sailing and maneuvering;
- wind, sails, inertia, leeway, tacking, wearing, and heel;
- historical artillery and ammunition;
- deep impact and damage modeling;
- hull, masts, yards, rigging, sails, rudder, and batteries;
- crew, fatigue, morale, casualties, and operational degradation;
- fire, flooding, surrender, capture, and boarding where applicable;
- smoke, visibility, light, and environmental effects;
- Human vs Human, Human vs AI, and AI vs AI;
- real historical ships with dated technical sheets;
- plans, illustrations, history, and source provenance;
- at least one complete historical or historically plausible 1v1 scenario.

## Development discipline

- Preserve `archive/prototype-v1` as an untouched historical reference.
- Do not develop directly on `main`.
- Do not maintain two independently evolving simulator copies; evolve the historical simulator through the canonical branch and use explicit rulesets/configuration when baseline behavior must remain comparable.
- Use feature branches for substantial changes.
- Add or update tests for simulation rules.
- Record durable decisions under `docs/decisions/`.
- Update `PROJECT_STATE.md` after meaningful work so a new chat can resume with minimal prompt.

When the user says only `Continuar proyecto`, recover context from GitHub first, then report briefly: canonical branch, current milestone, current state, and next task.
