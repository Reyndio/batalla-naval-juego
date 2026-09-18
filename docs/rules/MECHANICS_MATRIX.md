# MECHANICS MATRIX

Status: initial scaffold

Purpose: compare the documented Velmad v1.2 mechanics, the current prototype, and historically supported improvements before simulation behavior is changed.

## Status labels

- `PRESENT` — substantially implemented in the current prototype.
- `PARTIAL` — implemented in simplified or incomplete form.
- `MISSING` — absent from the current prototype.
- `UNCERTAIN` — implementation or historical interpretation requires investigation.
- `RESEARCH` — candidate improvement requiring evidence.

## Navigation and wind

| Mechanic | Velmad v1.2 baseline | Current prototype | Status | Historical improvement / question | Evidence needed | Decision |
|---|---|---|---|---|---|---|
| Sailing speed by vessel | Speed varies by vessel class and condition | Generic sail-state distances modified by wind/damage | PARTIAL | Replace class-only abstraction with dated ship-specific sailing characteristics where documented | Trials, logs, ship studies, naval architecture sources | Pending |
| Sail states | Multiple sail states affect speed and fatigue | NV/PV/MV/TV implemented | PRESENT/PARTIAL | Model actual effective sail area and transitions without losing playable orders | Period seamanship sources | Pending |
| Relative wind angle | Strongly affects sailing performance | Implemented through relative-angle efficiency | PARTIAL | Continuous polar-like sailing model by ship/rig if evidence permits | Historical sailing trials / naval architecture | Pending |
| Wind strength | Wind affects movement | CALMA/MEDIA/FUERTE | PARTIAL | Continuous or banded force model tied to sail force, heel, and sea state | Historical/technical sources | Pending |
| Rudder inertia | Previous helm position constrains next turn | Prototype has rudder-change constraints | PARTIAL | Couple rudder authority to speed, damage, sea state, and vessel properties | Seamanship/naval architecture | Pending |
| Tacking | Bow crossing wind causes maneuver penalties | Simplified/needs audit | UNCERTAIN | Model loss of way, failed tack risk, crew/ship effects if supportable | Period maneuvering sources | Pending |
| Wearing | Distinct maneuver around stern | Needs audit | UNCERTAIN | Explicitly model preserved way and larger turning space | Period maneuvering sources | Pending |
| Leeway | Not fully represented in recovered baseline | Not implemented as independent state | MISSING | Add wind-driven lateral drift depending on point of sail, hull, sail, sea | Historical/technical evidence | Pending |
| Heel | Velmad represents windward/leeward firing consequences via abstractions | Not modeled as continuous physical state | MISSING | Compute heel from wind, relative angle, sail force, and vessel stability | Naval architecture, period accounts, plans | Pending |
| Heel → gunnery | Windward/leeward affects gun inclination, smoke, target distribution, and lower battery usability | Not physically modeled | PARTIAL/MISSING | Derive firing consequences from actual heel/battery geometry rather than fixed percentages when evidence supports it | Gunnery/seamanship sources, ship geometry | Pending |
| Mast loss | Reduces speed and maneuver; total dismasting stops vessel | Individual mast health exists; speed consequences implemented in simplified form | PARTIAL | Component damage to masts/rigging/yards rather than simple HP thresholds | Structural/historical evidence | Pending |
| Fallen mast dragging | Can fall to a side, obstruct battery, drag, alter turn/speed, require cutting party | Not fully implemented | MISSING/PARTIAL | Model entanglement and cleanup work explicitly | Period damage-control sources | Pending |
| Hull damage → sailing | Critical hull state reduces sailing ability | Simplified hull-efficiency reduction | PARTIAL | Couple flooding, trim, structural damage and drag to performance | Damage-control/naval architecture sources | Pending |

## Artillery and ammunition

To be expanded after the navigation section is audited.

## Damage and ship systems

To be expanded.

## Crew, fatigue, morale, surrender and boarding

To be expanded.

## Visibility, smoke, light and environment

To be expanded.

## Multiplayer, signals and command

Deferred beyond the first mechanics pass except where needed for Human vs Human 1v1.

## Working rule

Do not treat this matrix as finished documentation. Each row must eventually link to:

- exact Velmad rule location;
- exact current-code implementation;
- historical sources;
- final design decision;
- automated tests where applicable.
