# Velmad v1.2 — Mechanical compliance matrix

Date: 2026-09-20
Source: `reglamento_velmad_1.2.pdf`, 24 pages, Rules v1.2.
Purpose: exhaustive implementation gate. Nothing in this file is an optional suggestion merely because it is not yet implemented.

## Status vocabulary

- **VERIFIED** — implemented and covered by a test demonstrating the stated Velmad behavior.
- **PARTIAL** — some of the rule exists, but one or more stated values/interactions are missing or differ.
- **MISSING** — not implemented.
- **SOURCE-AMBIGUOUS** — the manual states the rule but its translated wording is not precise enough to encode one unique algorithm without further source work.
- **SOURCE-OMITTED** — the manual explicitly says the detailed algorithm was omitted because the computer automated it.

A feature is not allowed to be marked VERIFIED solely because a similar mechanic exists.

---

## 1. Morale and Combat Capability

Baseline rules to preserve:

- Morale also represents combat capability/readiness, not merely emotional state.
- Morale loss:
  - -2 after a bow raking broadside from less than 2 ship lengths, damage at least 150.
  - -3 when losing a mast.
  - -4 after stern raking fire from less than 2 lengths, damage at least 150.
  - raking damage 75–149 causes half the corresponding morale loss.
  - -1 after 100 damage points of grapeshot fire to the hull from less than 2 lengths.
  - -1 after receiving 500 or more total damage points in one broadside fired to the hull.
- Recovery:
  - a ship that has previously lost at least 3 morale may recover 1 point, up to 10 maximum, by knocking down an enemy mast or achieving a stern rake from less than 150 m.
  - recovery does not restore the intact ship's original combat-capability state.

Status: **MISSING/PARTIAL** — morale is not yet a complete Velmad subsystem in the historical 2v2 core.

## 2. Fatigue

Actions stated by the manual:

- one broadside fired: +10% fatigue;
- both broadsides fired: +30%;
- making full sail: +30%;
- `Remove all sailing`: +30% (retain this source wording until the exact intended transition is reconciled);
- collect all sail / pass to no sail: +40%;
- from no sail to few or medium sail: +20%;
- fire-fighting party: +10% per turn;
- cutting/unravelling/dislodging a fallen mast: +10% per turn;
- reload double shot: +10% per band.

Collision fatigue:

- full sail: +60%;
- medium or few sail: +40%;
- no sail: +0%.

Recovery/effects:

- fatigue affects shooting effectiveness and whether a ship can fire in a turn;
- fatigue affects boarding;
- if a ship performs none of the first-list fatigue actions during the turn, it recovers 10% for the next turn;
- if current fatigue is over 80%, it is reduced by 20% under the stated recovery rule.

Status: **PARTIAL** — the branch has independent fatigue, but the complete Velmad action-cost table and exact recovery rules are not yet all reproduced.

## 3. Vessel classes

Classification stated by the manual must remain available because other mechanics depend on class/decks:

- first class: 100+ official guns, 3 deckers (with Santísima Trinidad noted as four-decker);
- second class: 90/98 gun 3-deckers; 80-gun English 3-deckers; 80-gun French/Spanish 2-deckers;
- third class: 74/70 gun 2-deckers; Dutch 68/64 gun 2-deckers;
- fourth class: 64/60/56/50 gun 2-deckers; 44-gun frigates as 2-deckers;
- fifth class: 36/32/28 gun frigates; 24-gun corvettes;
- sixth class: 18-gun brigs.

Status: **PARTIAL** — historical ship records exist, but the Velmad class system is not yet a complete mechanical dependency layer.

## 4. Sailing speed

Class-relative baseline, using a 74 as reference:

- first class: 80%;
- second class: 90%;
- third class: 100%;
- fourth class: 110%;
- fifth class: 120%;
- sixth class: 125%.

Rigging thresholds:

- classes 1–3: 2800 and 1800 rigging points;
- classes 4–5 and two-decker frigates: 2500 and 1500;
- class 6: 1350 and 350.

Damage/state modifiers:

- each fallen mast: -30% speed;
- dismasted: stopped;
- below first rigging threshold: max 90% speed;
- below second threshold: max 80%, with the manual's special first-mast/90% wording preserved;
- hull 0 or 1: max 70% speed;
- dragging a mast: max 90% speed.

Status: **PARTIAL** — current pilot speed effects do not yet reproduce this complete table exactly.

## 5. Manoeuvring

- Each rudder point turns 15 degrees.
- Normal rudder history constraint:
  - previous turn port: may put all rudder to port next turn;
  - previous turn starboard: may put all rudder to starboard next turn;
  - previous turn centered/opposite: only one point in the new direction;
  - with one mast lost: maximum one point;
  - dismasted: cannot turn.
- Independent chance to use two rudder points regardless of prior rudder position:
  - first class 25%;
  - second class 50%;
  - third class 75%;
  - fourth/fifth/sixth 100%.
- Close-hauled differences between real ships are explicitly not modeled by Velmad; all ships may beat to windward, with severe speed/manoeuvre penalties.

Status: **PARTIAL** — current pilot inherited a different prototype helm model; this must be reconciled to the actual Velmad rule before parity is claimed.

## 6. Tacking

- When turning and the bow reaches exactly the wind direction, no remaining rudder points may produce further rotation that turn.
- When leaving that situation, only one rudder point may be used regardless of ordered helm.
- Wearing is distinguished from tacking.

Status: **MISSING**.

## 7. Crew quality

Four levels:

- Beginner;
- Normal;
- Veteran;
- Elite.

Shooting/fatigue/manoeuvre effects:

- Beginner: 6% firing penalty for each 10% fatigue; may fire up to 100% fatigue; chance of two-point manoeuvre from class table is halved.
- Normal: 5% firing penalty for each 10% fatigue; may fire up to 100%; uses normal class two-point manoeuvre chance.
- Veteran: 4% firing penalty per 10% fatigue; may fire with 120% fatigue; may manoeuvre any ship two points.
- Elite: 3% firing penalty per 10% fatigue; may fire with 120%; may manoeuvre any ship to all rudder.
- Crew quality also modifies boarding combat using ordered quality levels.

Status: **PARTIAL** — current branch has experience/fatigue concepts but not this exact four-level Velmad table.

## 8. Ammunition, shooting and damage

### 8.1 Round shot

- main penetration/range/accuracy ammunition;
- primarily hull-directed;
- may cause fires and magazine criticals;
- fired at rigging: 50% damage;
- rigging damage beyond 7 lengths is capped at the damage that would be received at 7 lengths.

### 8.2 Bar and chain shot

- treated as one ammunition type;
- primarily rigging-directed;
- fired at hull: 50% damage;
- beyond 7 lengths: damage divided by 3.

### 8.3 Grapeshot

- close-range anti-crew ammunition;
- hull damage: 50%;
- rigging damage: one third;
- triple the crew losses of round shot fired at hull;
- double the crew losses of chain shot fired at rigging;
- morale interaction applies.

### 8.4 Double shot

- round shot must already be loaded in that band before double shot can be reloaded;
- band cannot fire during the turn in which double shot is reloaded;
- reloading does not require firing the current round;
- +10% fatigue per band to reload;
- effective range 112 m; beyond it damage divided by 5;
- hull damage +25%;
- artillery pieces dismounted +50%;
- crew losses double those of single round shot;
- against rigging in battle range: three times less damage than bar/chain; out of range: five times less.

### 8.5 Loading sequence

- The captain selects what ammunition each band that fires will reload.
- That selected ammunition is available on the following turn.

### 8.6 Battery section / geometry

- Target can be in arc of complete battery or only bow/stern section.

### 8.7 Distance and base damage effects

- Each ship length of distance reduces about 10% of minimum base and maximum accuracy, and therefore damage.
- General range is just over 10 lengths.
- Normal computed damage is distributed 90%/10% between hull and rigging according to selected target area, subject to later wind-position rules.
- At 112 m or less, firing is always carried out as hull-targeted.
- From a little over 6 lengths, hull-directed damage becomes 50% of the otherwise corresponding amount.
- At one length maximum effectiveness is already reached; getting closer increases minimum possible damage, not maximum.

### 8.8 Rigging target modifier by target sail state

- medium sail: normal;
- full sail: +50%;
- collected/no sail: -50%;
- few sail: -10%.

### 8.9 Shooter sail-state effects

- shooter at no sail/anchored: bonus equivalent to having 10% less fatigue;
- shooter at full sail:
  - upper-deck battery (forecastle/quarterdeck/poop) cannot be used;
  - despite this, 20% fire risk exists;
  - firing penalty equivalent to +10% fatigue.
- firing one broadside costs +10% fatigue.
- if there is insufficient crew to serve all guns, only guns for which servants are available fire.

Status: **PARTIAL** — several ammunition concepts are present but the complete Velmad ammunition set, loading sequence and exact modifiers are not yet reproduced.

## 9. Wind position and shooting effects

Windward/leeward is determined using a 30-degree arc relative to wind at firing position.

Shooting at a target to windward:

- hull aim: 60% hull, 30% rigging, 10% lost;
- rigging aim: 90% rigging, 0% hull, 10% lost.

Shooting at a target to leeward:

- hull aim: 100% hull, 0% rigging;
- rigging aim: 40% hull, 60% rigging.

The manual supplies physical rationale involving heel, waterline exposure and smoke, but the percentages above are the normative Velmad baseline.

Status: **MISSING**.

## 10. Carronades

Carronade contribution to broadside power by distance:

- 300 m or less: one third of capacity;
- 225 m or less: half;
- 150 m or less: 100%.

Status: **MISSING/PARTIAL** — historical carronades are recorded in data, but their Velmad distance contribution is not yet fully used.

## 11. Boarding

Eligibility:

- ships must be close enough;
- target must have sails gathered/stopped (voluntarily or by collision) or at least one fallen mast;
- target morale must be below 10.
- if both attempt to board, higher morale boards; if equal, greater crew boards.

Combat-force calculation:

- if a ship ordered any battery fire, available boarding force is free men after gun-service requirements for that band;
- if it does not fire, combat force is 2/3 of crew;
- calculate attacker/defender ratio; final result must exceed 1 for capture;
- if defender fired grapeshot at attacker this turn, ratio ×0.6;
- each morale point difference: ±0.075;
- fatigue comparison contributes ±0.075;
- each crew-quality level difference: ±0.10;
- attacker receives -0.1 per deck disadvantage; no bonus for deck advantage;
- luck factor: -0.20 to +0.20.

Casualties/resistance:

- boarding causes casualties, fewer for higher crew quality;
- if target has not already suffered minimum casualties, boarding casualties for both are doubled and attacker receives -0.075;
- minimum pre-boarding casualties:
  - first class 100;
  - second class 80;
  - 74-gun ship 60;
  - other 2-deckers 40;
  - frigates 20;
  - smaller 0.
- failed boarding: attacker suffers extra casualties;
- successful boarding: target captured, white flag, prisoners, prize crew assigned;
- a vessel already captured earlier and held by the enemy may be recaptured without combat.

Status: **MISSING**.

## 12. Surrender

- At morale 0, a ship surrenders when receiving a new broadside.
- At 1000 or fewer hull points, each broadside received from less than 300 m triggers a morale roll 1–10; if result is greater than ship morale, it surrenders.

Status: **MISSING**.

## 13. White flag state

For one turn after surrender:

- cannot navigate;
- cannot turn;
- cannot board;
- cannot fire;
- cannot be fired upon;
- cannot be boarded.

Status: **MISSING**.

## 14. Captured ships / prizes

Captured vessel restrictions:

- cannot use full sail;
- cannot fire;
- cannot board another vessel;
- cannot be fired upon by a vessel of the same flag.

Prize crew required by captured ship class:

- first: 50;
- second: 40;
- third: 30;
- fourth: 20;
- fifth/sixth: 10.

Recapture:

- if a captured ship is more than 525 m from nearest friendly vessel, original crew retakes control and captures the prize crew;
- any recaptured vessel, whether by its own crew or an allied vessel, goes to 120% fatigue and white-flag state.

Status: **MISSING**.

## 15. Hull 0 and Hull 1

This rule is mandatory and supersedes any pilot shortcut of `HP 0 = sunk`.

- Hull 0 remains operational and can still navigate and fight subject to penalties.
- Uncaptured hull-0 ship has 10% chance each turn to begin sinking.
- Once sinking begins, ship is out of combat, cannot navigate and is removed from play.
- Hull 0 may be repaired/pumped to hull 1 if fatigue is at most 100%; doing so adds 20% fatigue.
- At hull 0, first/main/bottom battery cannot be used.
- At hull 1, first battery may be used again.
- The stated design intent is that sustained fire can repeatedly force the ship from hull 1 back to hull 0, while a disengaged ship may stabilize and recover some combat ability.
- Sailing-speed rule separately caps hull 0/1 at 70% speed.

Status: **MISSING/PARTIAL** — current pilot still needs this exact state machine.

## 16. Critical mast knockdown

- With 3 masts remaining: if a mast has fewer than 500 points, a hit causing more than 50 damage knocks it down.
- With 2 masts remaining: affected mast must have fewer than 300 points for the critical knockdown.
- With only 1 mast remaining: it must be reduced to 0 to fall.

Status: **MISSING/PARTIAL**.

## 17. Fallen mast / dragging mast

- When a mast falls: 50% chance it remains tangled, covering one side and dragging in the sea.
- If tangled:
  - 75% chance to fall in the direction the wind pushes it: wind entering port -> mast falls starboard, and vice versa;
  - 25% chance to fall on the opposite side.
- Firing from the covered side:
  - 50% fire risk;
  - shooting precision/power penalty equivalent to +20% fatigue.
- If an incoming broadside is aimed at the side covered by the fallen mast, fire chance is a percentage equal to broadside power divided by 10.
- Each turn while dragging:
  - ship automatically turns one rudder point toward that side regardless of rudder position;
  - speed penalty from sailing-speed chapter applies (90% maximum).
- Cutting party:
  - +10% fatigue each turn used;
  - 50% chance of success.

Status: **MISSING** as a complete state/action loop.

## 18. Critical impacts, magazine and captain

- Round-shot broadside at less than 300 m: 1% base chance of critical impact.
- If critical occurs, manual defines magazine-explosion chance from number of guns greater than 24-pounder (counted ×2) plus number of 24-pounders, with source wording that must be preserved/reconciled before encoding an exact formula.
- If magazine explosion does not occur, ship is set on fire.
- Modifiers stated:
  - below 2000 hull, critical percentage is related to `damage/100` as written in the manual;
  - at hull 0/1 probabilities increase tenfold.
- For each quarterdeck piece destroyed: 10% chance of hitting captain, wounding or killing him.
- Following captain hit, surrender threshold changes from 1000 to 1500 hull according to the manual wording.
- Captain killed: -1 morale.

Status: **SOURCE-AMBIGUOUS / MISSING** — exact translation of the critical percentage formula must be resolved without invention.

## 19. Helm damage states

Four states:

1. intact;
2. damaged: cannot turn two rudder points;
3. very damaged: chance of turning one point, otherwise straight:
   - first-class three-decker 20%;
   - second-class three/two-decker 40%;
   - 74-gun 60%;
   - fourth class 80%;
   - inferior classes always;
4. destroyed/blocked/disabled: half the one-point-turn chance of `very damaged`.

Status: **PARTIAL** — current binary damaged-rudder behavior is insufficient.

## 20. Fires

Five fire levels:

1. local;
2. extended;
3. serious;
4. widespread/general;
5. ship in flames.

Escalation/stacking:

- a new fire starts at level 1;
- an additional declared fire raises existing fire one level;
- without assigned fire-fighting team, fire rises one level each turn.

Damage/explosion:

- level 3: each turn, randomly damage one mast or hull by 50; 33% explosion risk;
- level 4: each turn, damage both by 100; 66% explosion risk;
- if no mast remains, fire damage applies to hull until hull 0;
- level 5: crew abandons ship; ship out of combat and later explodes or burns out and sinks.

Fire-fighting party:

- +10% fatigue each turn assigned;
- level-1 control chance 50%; subtract 10 percentage points for each higher fire level;
- on success:
  - reduce fire 1 level if ship ordered any battery fire or sail change;
  - otherwise reduce 2 levels;
- on failure: 50% chance fire increases one level, 50% chance it remains.

Fire transmission:

- two collided/entangled ships may transmit fire each turn;
- chance = 10% × fire intensity level.

Status: **MISSING**.

## 21. Fear / preservation incentive

- In ranking/captain-ladder games, owner of a lost/captured/sunk/destroyed ship receives only 10% of the points that ship had obtained in battle.
- This system is intentionally designed to discourage unrealistic fighting to destruction.

Status: **MISSING**.

## 22. End of battle

Battle can end by:

- elimination of one fleet or capture of its remaining ships;
- scenario turn limit;
- both admirals decided previous turn to break contact;
- after turn 40: 3 turns without shooting;
- after turn 60: 1 turn without shooting.

Status: **PARTIAL/MISSING**.

## 23. Score and victory

- each hull/rigging damage point caused: 1 point;
- sunk/exploded ship: 1000;
- captured ship: 2000;
- mast knocked down: 300;
- points earned by a ship's shooting are lost if that ship is captured or sunk;
- recapturing a ship restores its points and subtracts the enemy's 2000 prize points;
- no class/size distinction in these score awards.

Status: **MISSING**.

## 24. Signals

Communication types:

- voice/horns to vessel within 150 m, max about 100 characters/letters;
- flags using separate signal book/code not reproduced in this manual.

Multiplayer message timing/command hierarchy:

- scenario determines whether pre-battle planning is allowed and whether it occurs before enemy deployment or at turn 0;
- after battle begins, communication is through game signals;
- each ship may send one message per turn, received at start of following turn; may receive unlimited messages;
- admiral may message whole fleet or one ship;
- squadron/division leader may message whole subordinate group or any one fleet ship;
- other ships may message one recipient per turn.

Status: **MISSING**.

## 25. Wind change and visibility

- each turn: 5% wind-change probability;
  - 4% slight;
  - 1% abrupt;
- scenario may override/define this;
- visibility may change turn by turn, tending to become limited because of fog or sunset, as scenario-defined.

Status: **PARTIAL** — wind exists but this exact probability model and visibility system are not complete.

## 26. Court-martial

- admiral and squadron/division leader may mark subordinate ships as defendants of court-martial;
- such ships do not receive distributed fleet points after battle;
- they do receive points obtained by themselves and half the points of their prizes.

Status: **MISSING**.

## 27. Time scale and conventions

- one Velmad turn = 5 minutes of action;
- movement is closer to 2.5 minutes, intentionally compressed for playability;
- one `ship length` used by the rules = 75 m, including bowsprit and chosen as a round measure.

Status: **MISSING/PARTIAL** — these conventions must become explicit constants/metadata where relevant.

## 28. Explicitly omitted algorithms in the v1.2 manual

The manual explicitly says the following were omitted because the computer automated them:

- detailed movement calculation system;
- detailed combat damage calculation system.

Status: **SOURCE-OMITTED**.

These cannot be reconstructed from the manual by intuition and then labelled Velmad. The stable playable implementation, archived code, recoverable original Velmad behavior and historical research must be separately identified as evidence for those algorithms.

---

# Release gate

The historical simulator must not be described as having `Velmad v1.2 mechanical parity` until every applicable row above is VERIFIED, with any SOURCE-AMBIGUOUS or SOURCE-OMITTED item explicitly resolved/documented.

After that baseline exists, proposed changes follow ADR-0001:

1. state the Velmad rule being replaced;
2. identify the phenomenon represented;
3. provide strong historical/technical/physical evidence;
4. compare expected behavior;
5. document uncertainty;
6. approve the change explicitly;
7. retain regression tests for both the former baseline and new intended behavior where useful.

No addition or realism improvement is accepted merely because it seems plausible.