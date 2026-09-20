# Velmad v1.2 — Mechanical compliance matrix

Date: 2026-09-20
Source: `reglamento_velmad_1.2.pdf`, 24 pages, Rules v1.2.
Purpose: exhaustive implementation gate. Nothing in this file is optional merely because it is not yet implemented.

## Status vocabulary

- **VERIFIED** — implemented and covered by deterministic tests demonstrating the stated source behavior.
- **PARTIAL** — some of the rule exists, but one or more stated values/interactions remain missing or differ.
- **MISSING** — not implemented.
- **SOURCE-AMBIGUOUS** — the manual states a rule, but the translated wording does not define one unique algorithm safely enough to encode without further source work.
- **SOURCE-OMITTED** — the manual explicitly says the detailed algorithm was omitted because the computer automated it.
- **PROJECT-RECONSTRUCTION** — playable behavior chosen where source/original algorithms are incomplete; never presented as literal source text.
- **PROJECT-DIVERGENCE** — an explicit project rule intentionally differs from recoverable source text and therefore cannot count toward literal parity.
- **PROTOTYPE-PARITY** — behavior restored from the frozen stable prototype because the project owner requires the established playable control model.

Current playable overrides are documented in ADR-0006, ADR-0007 and ADR-0008. Tests for source behavior and playable divergences intentionally coexist; a source-rule test does not imply that the same control semantics are the current player-facing runtime.

---

## 1. Morale and Combat Capability

Source baseline:

- morale represents crew state/readiness/combat capability;
- -2 after bow rake from <2 ship lengths with at least 150 damage;
- -3 when losing a mast;
- -4 after stern rake from <2 lengths with at least 150 damage;
- rake damage 75–149 causes half the corresponding morale loss;
- -1 after 100 grapeshot hull damage from <2 lengths;
- -1 after receiving >=500 total damage in one hull-directed broadside;
- a ship that previously lost at least 3 morale may recover 1, up to 10, by knocking down an enemy mast or achieving a stern rake from <150 m;
- recovery does not restore the intact ship's original combat-capability state.

Status: **MISSING/PARTIAL** — no complete morale subsystem yet.

## 2. Fatigue

Source action costs:

- one broadside +10%; both broadsides +30%; making full sail +30%;
- `Remove all sailing` +30%; `Collect all the sail (pass to no sail)` +40%;
- no sail -> few or medium +20%;
- fire-fighting party +10%/turn;
- cutting/unravelling/dislodging fallen mast +10%/turn;
- reload double shot +10% per band.

Collision fatigue: TV +60%; MV/PV +40%; NV +0%.

Recovery/effects:

- fatigue affects shooting eligibility/effectiveness and boarding;
- if none of the first-list fatigue actions occurred, recover 10%; if current fatigue >80%, recover 20%.

Current implementation:

- one-broadside, collision, recovery, shooting-quality and double-reload effects are implemented/tested;
- the new carpenter/cutting action has an owning loop, costs +10% on the turn assigned, and uses the source 50% cutting-success rule;
- fire-fighting owning loop remains incomplete;
- true two-broadside-in-one-turn execution remains absent;
- sail-change fatigue is **PROJECT-DIVERGENCE** under ADR-0006: `NV→PV→MV→TV`, +10% for each adjacent point crossed, so direct jumps cost 10/20/30 symmetrically.

Status: **PARTIAL / PROJECT-DIVERGENCE**.

## 3. Vessel classes

Source classification:

- first: 100+ official guns, 3-deckers; Santísima Trinidad noted four-decker;
- second: 90/98-gun 3-deckers; 80-gun English 3-deckers; 80-gun French/Spanish 2-deckers;
- third: 74/70-gun 2-deckers; Dutch 68/64-gun 2-deckers;
- fourth: 64/60/56/50-gun 2-deckers; 44-gun frigates as 2-deckers;
- fifth: 36/32/28-gun frigates; 24-gun corvettes;
- sixth: 18-gun brigs.

Current four ships are documented 74-gun/74-gun-class two-deckers and resolve to class 3. Tests cover their classification and dependent class tables.

Status: **VERIFIED for the current four-ship classification/dependency path**.

## 4. Sailing speed

Source class factors relative to a 74: first 80%, second 90%, third 100%, fourth 110%, fifth 120%, sixth 125%.

Rig thresholds:

- classes 1–3: 2800 / 1800;
- classes 4–5 and two-decker frigates: 2500 / 1500;
- class 6: 1350 / 350.

State rules:

- each fallen mast -30% speed; dismasted stopped;
- below first rig limit max90%; below second max80%, retaining the special first-mast/90% wording;
- Hull0/1 max70%; dragging mast max90%.

Current implementation has class factors, fallen-mast penalty, dismasted stop and Hull0/1 cap. Current rig scale remains inherited `BASE_RIG=1200`, so literal threshold conversion is unresolved. Ordinary dragging-mast 90% cap remains incomplete. Translational inertia is a separate **PROJECT-RECONSTRUCTION** under ADR-0007.

Status: **PARTIAL**.

## 5. Manoeuvring

Source baseline:

- 0/1/2 rudder points; each point 15°;
- previous helm side governs access to full two-point helm;
- centred/opposite side normally permits one point;
- one mast lost max1; dismasted none;
- independent two-point chance by class: 25/50/75/100/100/100%;
- the rules deliberately do not model ship-specific close-hauled differences.

Source mechanics remain implemented and deterministically tested in the baseline core/test layer.

### Current playable runtime override

ADR-0008 restores the stable-prototype player control model:

- helm positions -4..+4;
- NV/PV turn table: 1=10°, 2=20°, 3=30°, 4/T=45°;
- MV factor .7; TV factor .4;
- maximum change/turn: NV/PV4, MV3, TV2;
- maximum absolute helm: NV/PV4, MV4, TV3;
- TV never allows ±4 and can reach ±3 only progressively from ±2;
- damaged rudder max ±1.

Therefore the previously verified source 0/1/2 model is **not the current player-facing control semantics**.

Status: **SOURCE BASELINE VERIFIED / PLAYABLE PROJECT-DIVERGENCE + PROTOTYPE-PARITY**. Literal runtime parity is intentionally broken under ADR-0008.

## 6. Tacking

Source:

- when bow reaches exactly wind direction while turning, no remaining rudder points rotate farther that turn;
- when leaving that situation, only one point may be used;
- wearing is distinct from tacking.

Current head-to-wind stop/departure layer remains active over the restored prototype helm pending further validation.

Status: **VERIFIED source rule, with playable integration requiring continued regression testing after ADR-0008**.

## 7. Crew quality

Source shooting/manoeuvre table:

- Beginner: 6% firing penalty per10 fatigue, fires through100, class two-point chance halved;
- Normal: 5%, through100, normal chance;
- Veteran: 4%, through120, may manoeuvre any ship two points;
- Elite: 3%, through120, may manoeuvre any ship to all rudder;
- quality also modifies boarding by ordered quality level.

Shooting fatigue tables remain implemented/tested. Source 0/1/2 manoeuvre quality effects remain baseline-tested but are no longer the current playable helm semantics under ADR-0008. Boarding effects remain pending.

Status: **PARTIAL / PLAYABLE MANOEUVRE DIVERGENCE**.

## 8. Ammunition, shooting and damage

### Round shot

- primary hull ammunition; may cause fire/magazine criticals;
- rigging damage 50%; rigging damage beyond 7 lengths capped at 7-length value.

### Bar/chain

- one ammo family; hull damage50%; beyond7 lengths damage /3.

### Grapeshot

- anti-crew; hull damage50%, rigging one-third;
- triple crew losses of round shot to hull; double crew losses of chain to rigging; morale interaction.

### Double shot

- requires round already loaded in that band;
- band cannot fire while reloading it; reload does not require firing current round;
- +10 fatigue per band;
- effective range112m; beyond /5;
- hull +25%, artillery dismount +50%, crew losses x2 vs single round;
- rigging: one-third bar/chain in range, one-fifth outside.

### Loading/geometry/distance

- fired band selects ammo for next turn;
- target may be in complete or bow/stern battery section;
- each ship length decreases about10% of minimum base/max accuracy/damage;
- general range little over10 lengths; normal damage allocated90/10 chosen/other area subject to wind-position rules;
- <=112m forced hull; beyond little over6 lengths hull-directed damage50%; one-length max effectiveness.

### Sail-state effects

Target rigging factor: MV normal, TV +50%, NV -50%, PV -10%.

Shooter:

- NV/anchored bonus equal to 10 less fatigue;
- TV excludes upper-deck battery, retains 20% fire risk, and has accuracy penalty equal to +10 fatigue;
- insufficient crew limits number of guns served.

Current implementation:

- ammo families, modifiers, per-band loading, double reload, <=112 forced hull, target-sail factors, shooter NV/TV accuracy modifiers, upperworks/carronade exclusion and wind allocation are implemented/tested;
- TV accuracy penalty is active;
- **20% full-sail ignition risk is now implemented after an actual broadside**;
- owner-approved PROJECT-RECONSTRUCTION raises that risk to 30% when wind enters through the firing side (ADR-0008);
- source-omitted base-damage/range curve, literal long-range envelope, insufficient-crew gun service, morale consequences and true both-broadsides execution remain incomplete.

Status: **PARTIAL**.

## 9. Wind position and shooting effects

30° total wind fork.

Target windward:

- hull aim 60 hull /30 rig /10 lost;
- rig aim 0 hull /90 rig /10 lost.

Target leeward:

- hull aim100 hull;
- rig aim40 hull /60 rig.

Current classification/allocation plus crosswind90/10 are implemented/tested.

Status: **VERIFIED**.

## 10. Carronades

Contribution: >300m0; <=300 one-third; <=225 one-half; <=150 full.

Actual historical carronades use this table; Spanish obuses remain distinct pending evidence; TV excludes upperworks/carronade contribution.

Status: **VERIFIED for actual carronades in current historical data path**.

## 11. Boarding

Eligibility:

- close enough;
- target sails gathered/stopped, stopped by collision, or >=1 fallen mast;
- target morale<10;
- if both board: higher morale boards; tie greater crew.

Combat:

- if firing any battery, boarding force = free men after gun-service needs for that band; otherwise 2/3 crew;
- attacker/defender ratio must finish >1;
- defender grapeshot against attacker that turn x0.6;
- morale difference +/-0.075 each point;
- fatigue comparison +/-0.075;
- crew-quality level difference +/-0.10;
- attacker -0.1/deck disadvantage; no deck advantage bonus;
- luck -0.20..+0.20.

Resistance/casualties:

- higher quality lowers casualties;
- if target has not reached minimum prior casualties, both casualties double and attacker -0.075;
- minimum prior casualties: first100, second80, 74-gun60, other2-deckers40, frigates20, smaller0;
- failed boarding gives attacker extra casualties;
- success captures, raises white flag, prisoners/prize crew;
- captured enemy-held ship may be recaptured without combat.

Status: **MISSING**.

## 12. Surrender

- morale0: surrender upon receiving a new broadside;
- hull<=1000: every broadside from <300m triggers 1–10 morale roll; roll > morale => surrender.

Status: **MISSING**.

## 13. White flag

For one turn after surrender: cannot navigate, turn, board or fire; cannot be fired upon/boarded.

Status: **MISSING**.

## 14. Captured ships / prizes

Captured cannot full sail/fire/board and cannot be fired by same-flag vessel.

Prize crew: class1 50, class2 40, class3 30, class4 20, class5/6 10.

Captured >525m from nearest friendly -> original crew retakes/captures prize crew; recaptured vessel fatigue120 + white flag.

Status: **MISSING**.

## 15. Hull 0 and Hull 1

- Hull0 remains operational with penalties;
- uncaptured Hull0 has 10% chance/turn to begin sinking; only actual sinking removes it;
- Hull0 -> Hull1 by pumps/repair if fatigue<=100, cost+20;
- Hull0 cannot use first/main/bottom battery; Hull1 can;
- incoming damage can return repaired Hull1 to0;
- Hull0/1 speed cap70%.

Implemented/tested including damage-control UI.

Status: **VERIFIED**.

## 16. Critical mast knockdown

- 3 masts: mast below500 falls if then suffers >50 damage;
- 2 masts: affected mast must be below300;
- 1 mast: must reach0.

Current collision-specific weak-mast fall is an ADR-0008 project reconstruction and does not substitute for this general source critical rule.

Status: **MISSING/PARTIAL**.

## 17. Fallen / dragging mast

Source:

- 50% chance fallen mast remains tangled, covers a side and drags;
- if tangled, 75% falls wind-pushed direction,25% opposite; wind entering port -> falls starboard and vice versa;
- firing covered side: 50% fire risk + accuracy/power penalty equivalent +20 fatigue;
- incoming broadside at covered side: fire chance=broadside power/10 percent;
- dragging auto-turns one rudder point toward side each turn, max speed90%;
- cutting party +10 fatigue/turn, 50% success.

Current implementation:

- cutting-party +10 fatigue and 50% success now have a playable owning action;
- collision-specific weak mast may fall toward the colliding ship and entangle both; current project values are <=30% health, 50% fall check and 75% entanglement;
- entangled pair has no translational movement until cutting succeeds;
- ordinary non-collision 50% tangle, wind-driven fall side, covered-side firing/fire risk, dragging auto-turn and 90% cap remain incomplete.

Status: **PARTIAL + PROJECT-RECONSTRUCTION for collision-specific entanglement**.

## 18. Critical impacts, magazine and captain

- round-shot broadside <300m:1% base critical;
- magazine formula counts >24pdr x2 plus 24pdr guns, but translated wording remains ambiguous;
- if no explosion => fire;
- below2000 hull critical percentage related to damage/100 wording;
- Hull0/1 probabilities x10;
- each quarterdeck piece destroyed 10% captain hit;
- captain hit changes surrender threshold1000->1500 per wording;
- captain killed -1 morale.

Status: **SOURCE-AMBIGUOUS / MISSING**.

## 19. Helm damage states

1. intact;
2. damaged: cannot turn two source points;
3. very damaged: one-point chance — first-class3-decker20%, second-class3/2-decker40%, 74-gun60%, fourth80%, inferior100%;
4. destroyed/blocked/disabled: half state3 chance.

Current playable rudder remains binary damaged/not-damaged; damaged limits prototype helm to ±1.

Status: **PARTIAL / PLAYABLE DIVERGENCE**.

## 20. Fires

Source levels: 1 local,2 extended,3 serious,4 widespread/general,5 ship in flames.

Rules:

- new fire starts1; another declared fire +1;
- without team +1/turn;
- L3 random mast/hull50 and 33% explosion/turn;
- L4 both100 and66% explosion;
- no masts -> fire damage hull down0;
- L5 crew abandons/OOC/later explodes-burns-sinks;
- fire party +10 fatigue/turn;
- control chance L1 50%, -10pp/higher level;
- success reduces1 if battery fire/sail change, otherwise2;
- failure 50% +1 /50% remain;
- collided/entangled transmit chance10% x fire level/turn.

Current implementation now has persistent `fireLevel`/`onFire` state and an actual full-sail broadside can ignite level1 at source 20%. Wind entering firing side raises the playable probability to project-calibrated30%. The remaining progression, damage, explosion, firefighting and transmission loop is not yet implemented.

Status: **PARTIAL**.

## 21. Fear / preservation incentive

Owner of captured/sunk/destroyed ship receives only10% of points that vessel earned, discouraging unrealistic destruction fighting.

Status: **MISSING**.

## 22. End of battle

May end by fleet elimination/capture, scenario turn limit, both admirals breaking contact previous turn, after turn40 three turns without shooting, after turn60 one turn without shooting.

Status: **PARTIAL/MISSING**.

## 23. Score and victory

- 1 point per hull/rig damage;
- sunk/exploded1000; captured2000; mast down300;
- shooting points earned by ship lost if ship captured/sunk;
- recapture restores own points/removes enemy capture2000;
- no class distinction in awards.

Status: **MISSING**.

## 24. Signals

- voice/horns <=150m, about100 chars;
- flag code separate/not reproduced;
- scenario governs pre-battle planning/timing;
- after start, game signals only;
- each ship sends one message/turn, received next turn, receives unlimited;
- admiral may message fleet or one ship; squadron/division leader subordinate group or one fleet ship; others one recipient/turn.

Status: **MISSING**.

## 25. Wind change and visibility

- each turn 5% wind-change:4% slight,1% abrupt; scenario may override;
- visibility may change by scenario/fog/sunset.

Status: **PARTIAL** — wind exists, current prototype wind-change algorithm differs; visibility incomplete.

## 26. Court-martial

Admiral/squadron leaders may mark subordinate ships; they receive no distributed fleet points, retain own points and half prize points.

Status: **MISSING**.

## 27. Time scale and conventions

- one turn=5 minutes action;
- movement closer to2.5 minutes, deliberately compressed;
- one rules ship length=75m including bowsprit.

Status: **MISSING/PARTIAL** — 75m exists as explicit gunnery constant; timing metadata/mechanics incomplete.

## 28. Algorithms explicitly omitted by the manual

The source explicitly omits detailed movement calculation and detailed combat-damage calculation because the original computer handled them.

Status: **SOURCE-OMITTED**.

Do not invent these algorithms and label them source-derived. Stable-prototype behavior and later historical/technical research must be identified separately.

---

# Current source-verified / project-rule slice — 2026-09-20

Source-verified components currently include Hull0/1/sinking, current four-ship class dependency, baseline 0/1/2 helm logic as a source reference, head-to-wind tacking rule, windward/leeward fire allocation, actual-carronade range table, and several crew-quality shooting mechanics.

The playable runtime intentionally differs in important areas:

- ADR-0006: +10 fatigue per sail point crossed;
- ADR-0007: persistent translational inertia and strict T-like rake geometry;
- ADR-0008: stable-prototype nine-position helm; section-specific collision momentum; alignment-based stern rudder risk; collision weak-mast/entanglement behavior; wind-amplified full-sail ignition; hidden enemy fatigue.

A substantial ammunition/loading slice is implemented, but source-omitted base damage/range, crew service, morale and complete fire dependencies remain open.

# Release gate

The simulator must not be described as having complete literal v1.2 mechanical parity while any applicable row is MISSING/PARTIAL/SOURCE-AMBIGUOUS/SOURCE-OMITTED or while accepted PROJECT-DIVERGENCE rules replace the source behavior.

Every future replacement must state the source rule being replaced, the represented phenomenon, evidence/reconstruction basis, uncertainty and deterministic tests.