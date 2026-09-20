# START HERE

Project: historical age-of-sail naval combat simulator.

## Source of truth

This repository is the canonical source for project state, design decisions, research policy, code, tests, and historical data.

Canonical integration branch: `develop/historical-simulator`.

Branch roles:
- `archive/prototype-v1`: immutable snapshot of the original playable prototype. Never use it for normal development.
- `main`: stable/default branch and discovery entry point through `PROJECT_POINTER.md`.
- `develop/historical-simulator`: canonical integration branch for the new historical simulator.
- `feature/*`: temporary branches for substantial isolated work, merged back after validation.

## Required startup sequence

Before doing project work in a fresh chat or agent session:

1. Read `PROJECT_STATE.md` on `develop/historical-simulator`.
2. If `PROJECT_STATE.md` names an **active work/validation branch or open PR**, switch conceptually to that branch before inspecting or changing implementation. Read that branch's `PROJECT_STATE.md` and the explicitly referenced decisions/reports.
3. Read `ROADMAP.md` only as needed for the current task.
4. Read the relevant files under `docs/` for the task at hand.
5. Inspect the affected code before changing it.
6. When comparing against the untouched original prototype, use `archive/prototype-v1`.
7. When checking the currently deployed stable functional floor, use the service and commit recorded in `PROJECT_STATE.md`.
8. Do not reconstruct current state from old chats when GitHub contains newer information.

## Historical simulation principle

Velmad v1.2 is the mandatory foundational baseline for mechanics and battle dynamics.

Implementation order is governed by ADR-0004: **first reach complete parity with every applicable rule explicitly described in the Velmad v1.2 manual; only then modify, replace or extend those mechanics.**

Rules:
- no applicable Velmad mechanic may be silently omitted;
- reproduce stated Velmad thresholds, percentages, dependencies, state transitions and consequences before claiming parity;
- add tests for each reproduced rule;
- improve a Velmad mechanic only when strong historical, technical or physical evidence supports the change;
- add mechanics beyond Velmad only when they are well documented and explicitly identified as additions;
- do not add "realism" based only on intuition;
- distinguish documented fact, reconstruction, estimate and hypothesis;
- document important sources and design decisions.

Where the Velmad manual explicitly omits an algorithm because the computer handled it, do not invent an algorithm and call it Velmad. Use recoverable original/stable behavior as a documented implementation reference until stronger evidence justifies a replacement.

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
- Do not maintain two independently evolving simulator copies; evolve the historical simulator through the canonical branch and explicit feature branches.
- Use feature branches for substantial changes.
- Add or update tests for simulation rules.
- Record durable decisions under `docs/decisions/`.
- Update `PROJECT_STATE.md` after meaningful work so a new chat can resume with minimal prompt.
- Do not merge a validation branch merely to simplify handoff; preserve open validation gates recorded in `PROJECT_STATE.md`.

When the user says only `Continuar proyecto`, recover context from GitHub first, then report briefly: canonical branch, active work branch if any, current milestone, current state, and next task.