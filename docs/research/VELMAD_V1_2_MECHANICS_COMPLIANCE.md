# Velmad v1.2 — Mechanical compliance matrix

Date: 2026-09-20
Source: `reglamento_velmad_1.2.pdf`, 24 pages, Rules v1.2.
Purpose: exhaustive implementation gate. Nothing in this file is optional merely because it is not yet implemented.

## Status vocabulary

- **VERIFIED** — implemented and covered by deterministic tests demonstrating the stated Velmad behavior.
- **PARTIAL** — some of the rule exists, but one or more stated values/interactions remain missing or differ.
- **MISSING** — not implemented.
- **SOURCE-AMBIGUOUS** — the manual states a rule, but the translated wording does not define one unique algorithm safely enough to encode without further source work.
- **SOURCE-OMITTED** — the manual explicitly says the detailed algorithm was omitted because the computer automated it.

A feature is not VERIFIED merely because a similar mechanic exists. Verification evidence for the current Hull 0 / Hull 1 and fatigue/crew slice is in `tests/velmad-hull-fatigue.test.js`.

---

## 1. Morale and Combat Capability

Velmad baseline:

- morale represents crew state, readiness and combat capability;
- -2 after a bow rake from less than 2 ship lengths with at least 150 damage;
- -3 when losing a mast;
- -4 after a stern rake from less than 2 lengths with at least 150 damage;
- rake damage 75–149 causes half the corresponding morale loss;
- -1 after 100 damage points of grapeshot to the hull from less than 2 lengths;
- -1 after receiving 500 or more total damage points in one broadside fired to the hull;
- a ship that previously lost at least 3 morale may recover 1 point, up to 10, by knocking down an enemy mast or achieving a stern rake from less than 150 m;
- recovery does not restore the intact ship's original combat-capability state.

Status: **MISSING/PARTIAL** — no complete Velmad morale subsystem yet.

## 2. Fatigue

Manual action costs:

- one broadside fired: +10%;
- both broadsides fired: +30%;
- making full sail: +30%;
- `Remove all sailing`: +30% — source wording retained as ambiguous until reconciled;
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

- fatigue affects shooting effectiveness and whether a ship may fire;
- fatigue affects boarding;
- if none of the first-list fatigue actions was performed, recover 10% for the next turn;
- if current fatigue is over 80%, the stated recovery is 20%.

Current implementation evidence:

- exact constants/helpers and deterministic tests exist for one broadside +10, both broadsides +30, making full sail +30, collecting all sail +40, no sail to few/medium +20, collision 60/40/0, normal recovery 10 and >80 recovery 20;
- firing effectiveness and firing eligibility use the four crew-quality fatigue tables;
- +10 hooks exist for double-shot reload, fire-fighting party and cutting party, but the complete dependent action systems are not yet implemented;
- the translated `Remove all sailing: 30%` line is deliberately not guessed;
- the current battle UI does not yet support a true two-broadside-in-one-turn order, although the +30 rule is encoded/tested.

Status: **PARTIAL** — exact unambiguous costs/recovery and shooting effects are implemented, but dependent actions, two-broadside execution, boarding interaction and the ambiguous source line still prevent full verification.

## 3. Vessel classes

Manual classification required because other mechanics depend on it:

- first class: 100+ official guns, 3-deckers; Santísima Trinidad noted as four-decker;
- second class: 90/98-gun 3-deckers; 80-gun English 3-deckers; 80-gun French/Spanish 2-deckers;
- third class: 74/70-gun 2-deckers; Dutch 68/64-gun 2-deckers;
- fourth class: 64/60/56/50-gun 2-deckers; 44-gun frigates as 2-deckers;
- fifth class: 36/32/28-gun frigates; 24-gun corvettes;
- sixth class: 18-gun brigs.

Status: **PARTIAL** — historical records exist, but Velmad class is not yet a complete mechanical dependency layer.

## 4. Sailing speed

Class-relative baseline using a 74 as reference:

- first 80%; second 90%; third 100%; fourth 110%; fifth 120%; sixth 125%.

Rigging thresholds:

- classes 1–3: 2800 / 1800;
- classes 4–5 and two-decker frigates: 2500 / 1500;
- class 6: 1350 / 350.

State modifiers:

- each fallen mast: -30% speed;
- dismasted: stopped;
- below first rigging limit: max 90%;
- below second: max 80%, retaining the manual's special first-mast/90% wording;
- hull 0 or 1: max 70%;
- dragging a mast: max 90%.

Current implementation: the hull 0/1 70% cap is implemented and tested.

Status: **PARTIAL** — the rest of the complete Velmad speed/class/rigging table is not yet reproduced exactly.

## 5. Manoeuvring

- each rudder point turns 15°;
- previous-turn rudder history controls whether all rudder or only one point may be applied;
- previous port allows all port next turn; previous starboard allows all starboard;
- centered or changing to the opposite side allows only one point;
- with one mast lost: maximum one point; dismasted: none;
- independent chance to use two points regardless of previous rudder: first 25%, second 50%, third 75%, fourth/fifth/sixth 100%;
- all ships may beat close to wind in Velmad despite historical differences, with severe speed/manoeuvre penalties.

Status: **PARTIAL** — current pilot still uses the restored stable-prototype helm model. Crew-quality manoeuvre traits are recorded but are not considered verified until this Velmad helm/class rule is implemented.

## 6. Tacking

- when the bow reaches exactly the wind direction while turning, no remaining rudder points may rotate the ship farther that turn;
- when leaving that situation, only one rudder point may be used regardless of ordered helm;
- wearing is distinguished from tacking.

Status: **MISSING**.

## 7. Crew quality

Four levels and stated shooting limits:

- Beginner: 6% firing penalty per 10% fatigue; may fire through 100%; class two-point manoeuvre chance halved;
- Normal: 5% per 10%; may fire through 100%; normal class two-point chance;
- Veteran: 4% per 10%; may fire with 120%; may manoeuvre any ship two points;
- Elite: 3% per 10%; may fire with 120%; may manoeuvre any ship to all rudder;
- crew quality also modifies boarding combat by ordered quality levels.

Current implementation evidence:

- all four levels exist (`NOVATA`, `NORMAL`, `VETERANA`, `ELITE`, with English aliases where useful);
- exact discrete firing penalties per 10% fatigue are implemented and tested;
- exact 100/120% firing limits are implemented and tested;
- manoeuvre properties are represented in the quality profiles but not yet wired into the still-provisional helm model;
- boarding quality effects await the boarding subsystem.

Status: **PARTIAL** — shooting/fatigue portion verified; manoeuvring and boarding portions remain pending.

## 8. Ammunition, shooting and damage

### 8.1 Round shot

- principal penetration/range/accuracy ammunition;
- primarily hull-directed;
- may cause fires and magazine criticals;
- against rigging: 50% damage;
- rigging damage beyond 7 lengths capped at the 7-length value.

### 8.2 Bar/chain shot

- treated as one ammunition type;
- primarily rigging-directed;
- against hull: 50% damage;
- beyond 7 lengths: damage divided by 3.

### 8.3 Grapeshot

- close-range anti-crew ammunition;
- hull damage 50%; rigging damage one third;
- triple crew losses of round shot to hull;
- double crew losses of chain shot to rigging;
- morale interaction applies.

### 8.4 Double shot

- round shot must already be loaded in that band;
- band cannot fire during the turn double shot is reloaded;
- reloading does not require firing the current round;
- reload +10% fatigue per band;
- effective range 112 m; beyond it damage /5;
- hull damage +25%; artillery dismounting +50%; crew losses ×2 versus single round;
- against rigging: one third of bar/chain damage in battle range and one fifth outside it.

### 8.5 Loading sequence

- captain chooses ammunition to reload for each band that fires;
- selected ammunition is available next turn.

### 8.6 Battery section / geometry

- target may be in arc of the whole battery or only bow/stern section.

### 8.7 Distance/base damage

- each ship length reduces about 10% of minimum base and maximum accuracy/damage;
- general range a little over 10 lengths;
- normal computed damage distributed 90/10 between selected target area and the other area, subject to wind-position rules;
- at 112 m or less fire is always hull-targeted;
- from a little over 6 lengths, hull-directed damage is 50%;
- at one length maximum effectiveness is already reached; getting closer raises minimum possible damage, not maximum.

### 8.8 Rigging aim by target sail state

- medium: normal; full: +50%; no/collected: -50%; few: -10%.

### 8.9 Shooter sail state / crew service

- no sail/anchored: bonus equivalent to 10% less fatigue;
- full sail: upper-deck battery cannot be used, 20% fire risk remains, firing penalty equivalent to +10% fatigue;
- one broadside costs +10% fatigue;
- insufficient crew means only guns with enough servants may fire.

Status: **PARTIAL** — round/grape/double concepts and side gun losses exist, but the full four-ammunition model, exact loading restrictions, distance/sail modifiers and crew-service rule remain incomplete.

## 9. Wind position and shooting effects

Windward/leeward is determined by a 30° arc relative to wind at firing position.

Target to windward:

- hull aim: 60% hull, 30% rigging, 10% lost;
- rigging aim: 90% rigging, 0% hull, 10% lost.

Target to leeward:

- hull aim: 100% hull, 0% rigging;
- rigging aim: 40% hull, 60% rigging.

Status: **MISSING**.

## 10. Carronades

Contribution to broadside power:

- at 300 m or less: one third;
- at 225 m or less: one half;
- at 150 m or less: 100%.

Status: **MISSING/PARTIAL** — carronades are recorded historically but not yet applied by this exact range table.

## 11. Boarding

Eligibility:

- ships close enough;
- target has sails gathered/stopped, is stopped by collision, or has at least one fallen mast;
- target morale below 10;
- if both board, higher morale is boarder; tie -> greater crew.

Combat:

- if a ship ordered any battery fire, boarding force is free men after gun-service needs for that band;
- otherwise combat force is 2/3 crew;
- attacker/defender ratio must finish >1;
- defender grapeshot against attacker that turn: ratio ×0.6;
- each morale point difference ±0.075;
- fatigue comparison ±0.075;
- each crew-quality level difference ±0.10;
- attacker -0.1 per deck disadvantage; no bonus for deck advantage;
- luck -0.20 to +0.20.

Resistance/casualties:

- higher crew quality lowers boarding casualties;
- if target has not reached minimum prior casualties, casualties for both double and attacker gets -0.075;
- minimum prior casualties: first 100, second 80, 74-gun 60, other 2-deckers 40, frigates 20, smaller 0;
- failed boarding gives attacker extra casualties;
- successful boarding captures target, raises white flag, makes prisoners and assigns prize crew;
- a previously captured ship in enemy possession may be recaptured without combat.

Status: **MISSING**.

## 12. Surrender

- morale 0: surrender when receiving a new broadside;
- hull <=1000: each broadside from <300 m triggers a 1–10 morale roll; roll greater than morale -> surrender.

Status: **MISSING**.

## 13. White flag

For one turn after surrender the ship cannot navigate, turn, board or fire and cannot be fired upon or boarded.

Status: **MISSING**.

## 14. Captured ships / prizes

Captured ship:

- cannot use full sail, fire or board;
- cannot be fired upon by a vessel of the same flag.

Prize crew required:

- first 50; second 40; third 30; fourth 20; fifth/sixth 10.

Recapture:

- captured ship >525 m from nearest friendly vessel: original crew retakes control and captures prize crew;
- any recaptured vessel goes to 120% fatigue and white-flag state.

Status: **MISSING**.

## 15. Hull 0 and Hull 1

Mandatory baseline replacing the former `HP 0 = sunk` shortcut:

- Hull 0 remains operational and may still navigate/fight subject to penalties;
- an uncaptured Hull-0 ship has a 10% chance every turn to begin sinking;
- only when actual sinking begins is the vessel out of combat, unable to navigate and removed from play;
- Hull 0 may be pumped/repaired to Hull 1 if fatigue is at most 100%; cost +20% fatigue;
- Hull 0 cannot use the first/main/bottom battery;
- Hull 1 may use that battery again;
- sustained incoming fire may force a repaired Hull 1 back to Hull 0;
- Hull 0 and Hull 1 are capped at 70% speed.

Implementation:

- explicit Hull 0, Hull 1 and `sinking` state behavior;
- deterministic `<10%` sinking check and non-trigger case;
- lower-deck long-gun broadside removed from available firepower at Hull 0 and restored at Hull 1;
- 0→1 pump eligibility at fatigue <=100 and exact +20 fatigue cost;
- 70% speed cap at Hull 0/1;
- minimal player damage-control UI for ordering pump/repair;
- old immediate sinking and extra destruction-casualty shortcut removed.

Verification: `tests/velmad-hull-fatigue.test.js`.

Status: **VERIFIED**.

## 16. Critical mast knockdown

- 3 masts remaining: mast below 500 points falls if it then suffers >50 damage;
- 2 masts remaining: affected mast must be below 300 for the critical knockdown;
- 1 mast remaining: must be reduced to 0.

Status: **MISSING/PARTIAL**.

## 17. Fallen / dragging mast

- 50% chance fallen mast remains tangled, covers one side and drags;
- if tangled, 75% chance it falls in wind-pushed direction, 25% opposite;
- wind entering port -> falls starboard and vice versa;
- firing from covered side: 50% fire risk and precision/power penalty equivalent to +20% fatigue;
- incoming broadside aimed at covered side: fire chance = broadside power /10 percent;
- while dragging, automatically turn one rudder point toward that side each turn and max speed 90%;
- cutting party costs +10% fatigue per turn and has 50% success.

Status: **MISSING** as a complete state/action loop.

## 18. Critical impacts, magazine and captain

- round-shot broadside from <300 m: 1% base critical chance;
- after critical, magazine-explosion chance uses guns >24-pdr counted ×2 plus 24-pdr guns, but translated formula wording requires reconciliation before exact encoding;
- if magazine explosion does not occur, ship catches fire;
- below 2000 hull, critical percentage is related to `damage/100` as written;
- at Hull 0/1 probabilities increase tenfold;
- each quarterdeck piece destroyed: 10% chance of hitting captain;
- captain hit changes surrender range from 1000 to 1500 hull according to manual wording;
- captain killed: -1 morale.

Status: **SOURCE-AMBIGUOUS / MISSING** — do not invent the ambiguous percentage formula.

## 19. Helm damage states

1. intact;
2. damaged: cannot turn two points;
3. very damaged: chance to turn one point, otherwise straight — first-class 3-decker 20%, second-class 3/2-decker 40%, 74-gun 60%, fourth 80%, inferior classes always;
4. destroyed/blocked/disabled: half the one-point chance of very damaged.

Status: **PARTIAL** — current binary damaged-rudder behavior is insufficient.

## 20. Fires

Levels:

1. local; 2. extended; 3. serious; 4. widespread/general; 5. ship in flames.

Rules:

- new fire starts level 1; another declared fire raises level by 1;
- without assigned fire-fighting team, level rises by 1 each turn;
- level 3: randomly damage one mast or hull by 50 and 33% explosion risk each turn;
- level 4: damage both by 100 and 66% explosion risk;
- with no mast remaining, fire damage goes to hull down to 0;
- level 5: crew abandons ship; vessel out of combat and later explodes/burns out/sinks;
- fire-fighting party +10% fatigue per assigned turn;
- level-1 control chance 50%, minus 10 percentage points per higher level;
- success reduces 1 level if ship ordered battery fire or sail change, otherwise 2;
- failure: 50% increase one level / 50% remain;
- collided/entangled ships transmit fire with 10% × fire level chance per turn.

Status: **MISSING**.

## 21. Fear / preservation incentive

- in ranking/captain-ladder games, owner of a captured/sunk/destroyed ship receives only 10% of the points that vessel earned;
- mechanic intentionally discourages unrealistic fighting to destruction.

Status: **MISSING**.

## 22. End of battle

Battle may end by:

- elimination of a fleet or capture of remaining ships;
- scenario turn limit;
- both admirals having chosen previous turn to break contact;
- after turn 40: 3 turns without shooting;
- after turn 60: 1 turn without shooting.

Status: **PARTIAL/MISSING**.

## 23. Score and victory

- 1 point per hull/rigging damage point caused;
- sunk/exploded ship: 1000;
- captured ship: 2000;
- mast knocked down: 300;
- points earned by a ship's shooting are lost if that ship is captured or sunk;
- recapture restores its points and removes enemy's 2000 capture points;
- no size/class distinction in these awards.

Status: **MISSING**.

## 24. Signals

- voice/horns to vessel within 150 m, about 100 characters maximum;
- flags use a separate Velmad code not reproduced in this manual;
- scenario determines whether pre-battle planning is allowed and whether before enemy deployment or at turn 0;
- after start, communication is through game signals;
- each ship may send one message per turn, received at start of next turn, and receive unlimited messages;
- admiral may message whole fleet or one ship;
- squadron/division leader may message subordinate group or one fleet ship;
- other ships may message one recipient per turn.

Status: **MISSING**.

## 25. Wind change and visibility

- every turn: 5% wind-change probability — 4% slight, 1% abrupt;
- scenario may override/define this;
- visibility may change turn by turn and tend to be limited by fog/sunset as scenario-defined.

Status: **PARTIAL** — wind exists, but the current prototype wind-change algorithm is not this exact table and visibility is incomplete.

## 26. Court-martial

- admiral and squadron/division leaders may mark subordinate ships for court-martial;
- such ships receive no distributed fleet points after battle;
- they retain points earned themselves and half points from prizes.

Status: **MISSING**.

## 27. Time scale and conventions

- one turn = 5 minutes of action;
- movement is closer to 2.5 minutes, deliberately compressed;
- one rules `ship length` = 75 m, including bowsprit, selected as a round measure.

Status: **MISSING/PARTIAL** — must become explicit constants/metadata wherever applicable.

## 28. Algorithms explicitly omitted by the v1.2 manual

The manual explicitly omits because the original computer handled them:

- detailed movement calculation system;
- detailed combat-damage calculation system.

Status: **SOURCE-OMITTED**.

These algorithms must not be invented and labelled as Velmad. Stable/original implementation behavior and later historical/technical research must be identified separately as evidence.

---

# Current verified slice — 2026-09-20

The first exact mechanical contradiction closed under ADR-0004 is **Hull 0 / Hull 1 / sinking** (section 15).

The same implementation unit also advanced section 2 and section 7:

- exact unambiguous fatigue costs/recovery are now encoded and tested where the required action exists or has a testable cost hook;
- the four crew-quality levels now reproduce Velmad's shooting penalties and 100/120% firing limits;
- both sections deliberately remain PARTIAL because their manoeuvre, boarding and dependent-action interactions are not all implemented yet.

No historical improvement or rebalance was introduced in this slice; it is baseline restoration only.

# Release gate

The historical simulator must not be described as having `Velmad v1.2 mechanical parity` until every applicable row above is VERIFIED and every SOURCE-AMBIGUOUS/SOURCE-OMITTED item is explicitly resolved/documented.

After that baseline exists, changes follow ADR-0001:

1. state the Velmad rule being replaced;
2. identify the represented phenomenon;
3. provide strong historical/technical/physical evidence;
4. compare expected behavior;
5. document uncertainty;
6. approve the change explicitly;
7. retain useful regression coverage for baseline and replacement.

No addition or realism improvement is accepted merely because it seems plausible.
