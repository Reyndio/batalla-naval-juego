# Historical Ships 2v2 Pilot

Status: planned
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

## Ship selection criteria

The four ships should:

- belong to the project's main period of interest: the 18th century or early 19th century;
- be real, individually identified historical vessels;
- have sufficiently documented dimensions, armament, crew, rig, service configuration, and history;
- preferably have surviving plans, draughts, museum material, or reliable contemporary/near-contemporary illustrations;
- preferably come from the same broad historical period so that armament and sailing characteristics are meaningfully comparable;
- form two coherent national sides;
- permit a reasonably balanced 2v2 development scenario without artificial stat bonuses.

The selection must be researched before implementation. Do not choose ships merely because they are famous.

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

## First implementation scope

The first implementation should be deliberately limited to a visible and testable vertical slice:

1. Externalize ship definitions from hard-coded player/AI assumptions where necessary.
2. Add four historical ship records.
3. Render all four ships with historically differentiated scale/silhouette as far as the available sources support.
4. Add a second ship to each side.
5. Make selection, targeting, movement state, damage state and turn resolution work for four ships without breaking the existing mechanics.
6. Preserve the original prototype at `archive/prototype-v1`.
7. Deploy the pilot only to the development Render service, never directly over the stable reference service.

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

## Control model for the pilot

Initial implementation may use one controller per side controlling both ships, or AI support for the second ship, depending on the smallest safe change to the current architecture.

The implementation chat must inspect the current code before deciding this detail. The long-term architecture must not assume permanently that one side equals one ship.

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

If different configuration dates are selected for the four ships, the pilot should be presented as a historically plausible development scenario, not as an exact recreation of a single historical battle date.

## Deliverables for the dedicated chat

The dedicated chat for this change should produce, in order:

1. Research note comparing candidate ships and source quality.
2. Final four-ship selection with rationale.
3. Historical data files and provenance.
4. Feature branch for implementation.
5. Automated tests for multi-ship state/targeting where practical.
6. Development deployment on Render.
7. Manual playtest report comparing stable prototype vs 2v2 pilot.
8. Updated `PROJECT_STATE.md` and affected documentation.

## Success criteria

The pilot is successful when:

- four real historical ships appear and behave as distinct ship records;
- the two sides can complete a battle without state/targeting corruption;
- the original stable simulator remains available and untouched;
- historical data can be traced to sources;
- no balancing statistic was invented merely to force equality;
- selected historical configurations remain source-supported and internally coherent;
- the new architecture makes later 1v1 and multi-ship scenarios easier rather than harder.
