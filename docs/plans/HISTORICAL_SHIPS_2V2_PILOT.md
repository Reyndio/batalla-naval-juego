# Historical Ships 2v2 Pilot

Status: **playable vertical slice validated on development service**
Date: 2026-09-18

## Purpose

Make the first visible, testable upgrade to the current prototype by replacing generic/approximate ship representations with historically grounded real ships and by adding a second real ship to each side.

This is a development pilot, not the final historical-battle format. The formal first major milestone remains the deeply validated historical 1v1 simulator. The 2v2 pilot is allowed earlier because it is useful for validating ship data, rendering, multi-ship state handling, targeting, AI/controller assumptions, and force-composition balance without yet committing to large fleet battles.

## Core rule

Every playable ship in this pilot must correspond to a real historical vessel in a dated configuration.

Do not invent balancing bonuses or fictional ship statistics. When an individual vessel has several genuinely documented and internally coherent historical configurations in the relevant period, the pilot may select the documented configuration that best improves overall force balance. Balance may choose among historically supported configurations; it may not create a new one.

Do not combine values from incompatible dates merely to obtain a stronger or weaker synthetic version. Source uncertainty is not a balancing slider: when one interpretation is materially better supported, use the better-supported interpretation.

If the first ship on one side is materially stronger than its counterpart, compensate first through historically supported configuration selection and force composition by selecting the second historical ship so the two-ship forces are as comparable as reasonably possible.

Balance is secondary to historical fidelity. Any remaining asymmetry must be documented rather than hidden by arbitrary modifiers.

Detailed decision: `docs/decisions/ADR-0002-2v2-historical-configuration-balance.md`.

## Selected forces

Royal Navy:

- HMS Bellerophon — 21 October 1805 configuration.
- HMS Conqueror — 21 October 1805 configuration.

Real Armada:

- Montañés — 19–21 October 1805 configuration.
- Bahama — 19–21 October 1805 configuration.

The pair-level research and configuration rationale are documented under `docs/research/`.

## Historical data required per ship

At minimum:

- ship name and nation;
- class/rate and dated configuration;
- launch/build/refit dates relevant to the chosen configuration;
- principal dimensions with source and measurement convention;
- displacement/burthen where documented, with terminology preserved;
- armament by deck, type and caliber;
- nominal and actual crew where supportable;
- mast/rig/sail information where supportable;
- known sailing qualities when documented;
- battle/service history summary;
- plans, draughts, profiles and illustrations with provenance/licensing status;
- confidence labels: documented, reconstructed, estimated, unknown.

These requirements are satisfied to the level needed for the limited vertical slice through the four ship sheets and `docs/research/HISTORICAL_SHIPS_2V2_DATA_SPEC.md`. Unsupported numerical sailing/crew-quality values remain outside the historical data layer rather than being invented.

## First implementation scope

The first implementation is deliberately limited to a visible and testable vertical slice:

1. Externalize ship definitions from hard-coded player/AI assumptions where necessary.
2. Add four historical ship records.
3. Render all four ships with historically differentiated scale/silhouette as far as the available sources support.
4. Add a second ship to each side.
5. Make selection, targeting, movement state, damage state and turn resolution work for four ships without state corruption.
6. Preserve the original prototype at `archive/prototype-v1`.
7. Deploy the pilot only to the development Render service, never directly over the stable reference service.

## Implemented control model

The pilot uses one human controller for both Royal Navy vessels and AI control for both Spanish vessels.

The human can assign independent ship orders including target, sail state, rudder, fire/no-fire and hull/rigging aim. The architecture no longer assumes that one side equals one ship within the pilot core.

## What is explicitly not required in this pilot

This pilot does not require the complete future fleet-command system.

Do not add yet:

- admirals and flag-signal command;
- divisions or formal line-of-battle doctrine;
- career/ranks/auctions;
- official historical event scheduling;
- large multiplayer fleets;
- complete new damage physics;
- complete new sailing physics.

Those systems will be built later on the common simulation engine.

## Balance methodology

Do not manufacture equality by editing historical ship characteristics.

Use this order:

1. Choose historically comparable vessels.
2. For each vessel, identify the historically documented dated configurations that are sufficiently well supported and internally coherent.
3. When more than one such configuration exists, select among them with pair-level balance as one criterion, subject to the evidence rules in ADR-0002.
4. Balance the pair composition by the choice of the second vessel on each side.
5. Use scenario geometry, wind and starting position only when historically/plausibly justified and explicitly documented.
6. Record residual asymmetry.
7. Later, once the enhanced simulation engine exists, validate balance empirically through repeated AI-vs-AI benchmark runs.

Early balance assessment may consider documented armament, broadside composition, crew, hull size, sailing qualities and current-engine behavior, but no single arbitrary points formula should be treated as historical truth.

The selected pair remains very close on a coarse nominal projectile-mass screen, while preserving different weapon mixes. This screen is not treated as a combat-value formula.

## Delivered artifacts

- Research comparison and source-quality notes.
- Final four-ship selection and configuration rationale.
- Four sourced technical sheets.
- Externalized machine-readable ship data.
- Feature branch `feature/historical-2v2-pilot`.
- Reusable pilot simulation core.
- Playable browser UI at `/pilot`.
- Automated multi-ship state, targeting, battle-completion and HTTP route tests.
- Isolated Render development deployment.
- Validation/playtest report: `docs/reports/HISTORICAL_2V2_PILOT_PLAYTEST.md`.
- Updated `PROJECT_STATE.md`.

## Development deployment

Service: `batalla-naval-2v2-dev`

Playable route:

`https://batalla-naval-2v2-dev.onrender.com/pilot`

The stable service `batalla-naval-juego-1` remains untouched on `main`.

## Success criteria — current result

- four real historical ships appear and behave as distinct ship records — **met**;
- the two sides can complete a battle without state/targeting corruption — **met in automated AI-vs-AI benchmark**;
- the original stable simulator remains available and untouched — **met**;
- historical data can be traced to sources — **met**;
- no balancing statistic was invented merely to force equality — **met**;
- selected historical configurations remain source-supported and internally coherent — **met for pilot gate**;
- the new architecture makes later 1v1 and multi-ship scenarios easier rather than harder — **partially met**: ship data and pilot core are externalized, but the next step is the shared-engine refactor rather than further growth of the temporary page.

## Exit rule

The pilot has served its purpose once integrated and retained as a regression scenario. Do not continue turning `pilot-2v2.html` into a second permanent simulator. The next durable development work must move common state/order/sailing/combat behavior into the shared historical simulation engine that will support the primary 1v1 milestone and later multi-ship scenarios.
