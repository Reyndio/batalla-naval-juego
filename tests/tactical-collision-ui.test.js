const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const Guard = require('../src/collision-guard.js');
const Combat = require('../src/combat-rules.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function read(name) {
  return fs.readFileSync(path.join(__dirname, '..', name), 'utf8');
}

test('swept collision detection catches ships that cross during a turn even when endpoints are separated', () => {
  const a = Core.buildInitialState(data).ships[0];
  const b = Core.buildInitialState(data).ships[2];
  const hit = Guard.detectSweptCollision(
    a,
    { x: 100, y: 100, heading: 90 },
    { x: 300, y: 100, heading: 90 },
    b,
    { x: 200, y: 0, heading: 180 },
    { x: 200, y: 200, heading: 180 },
    80
  );
  assert.equal(hit.collides, true);
  assert.ok(hit.t > 0 && hit.t < 1);
});

test('swept collision detection does not invent a collision for distant parallel tracks', () => {
  const state = Core.buildInitialState(data);
  const a = state.ships[0];
  const b = state.ships[2];
  const hit = Guard.detectSweptCollision(
    a,
    { x: 100, y: 100, heading: 90 },
    { x: 250, y: 100, heading: 90 },
    b,
    { x: 100, y: 300, heading: 90 },
    { x: 250, y: 300, heading: 90 },
    60
  );
  assert.equal(hit.collides, false);
});

test('collision consequences visibly affect hull crew fatigue and bow collision stops retained motion', () => {
  const state = Core.buildInitialState(data);
  const a = state.ships[0];
  const b = state.ships[2];
  a.sail = a.effectiveSail = 'TV';
  b.sail = b.effectiveSail = 'MV';
  const hull = a.hull;
  const crew = a.crew;
  const fatigue = a.fatigue;
  const result = Guard.applyCollisionConsequences(state, a, 'BOW', b, () => 0.99);
  assert.ok(result.impact > 0);
  assert.ok(a.hull < hull);
  assert.ok(a.crew < crew);
  assert.equal(a.fatigue, fatigue + Core.collisionFatigueCost('TV'));
  assert.equal(result.retention, 0);
  assert.equal(a.collisionMomentumRetention, 0);
  assert.match(state.log.at(-1), /queda detenido/);
});

test('impact section controls next-turn momentum: bow 0 center 25 percent stern 50 percent', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  const other = state.ships[2];
  ship.x = 200; ship.y = 200; ship.heading = 0;
  other.x = 300; other.y = 200; other.heading = 90;
  assert.equal(Guard.collisionMomentumRetention('BOW', ship, other), 0);
  assert.equal(Guard.collisionMomentumRetention('CENTER', ship, other), 0.25);
  assert.equal(Guard.collisionMomentumRetention('STERN', ship, other), 0.5);
});

test('exact rear collision preserves speed but raises rudder damage chance to 75 percent', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  const other = state.ships[2];
  ship.x = 200; ship.y = 200; ship.heading = 0;
  other.x = 200; other.y = 300; other.heading = 0;
  const relation = Guard.sternAlignment(ship, other);
  assert.equal(relation.offAxis, 0);
  assert.equal(Guard.collisionMomentumRetention('STERN', ship, other), 1);
  assert.equal(Guard.sternRudderDamageChance(ship, other), 0.75);
});

test('stern rudder risk drops continuously as the collision moves away from rudder-axis alignment', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  const other = state.ships[2];
  ship.x = 200; ship.y = 200; ship.heading = 0;
  other.x = 300; other.y = 300;
  const chance = Guard.sternRudderDamageChance(ship, other);
  assert.ok(chance > 0.25 && chance < 0.75);
  assert.equal(Guard.collisionMomentumRetention('STERN', ship, other), 0.5);
});

test('very weak collision-zone mast may fall toward the collider and strongly entangle both ships', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  const other = state.ships[2];
  ship.masts.fore.health = Math.floor(ship.masts.fore.max * 0.25);
  const outcome = Guard.damageCollisionMast(state, ship, 'BOW', other, 1, () => 0.1);
  assert.equal(outcome.key, 'fore');
  assert.equal(outcome.fallen, true);
  assert.equal(outcome.entangled, true);
  assert.equal(ship.masts.fore.fallen, true);
  assert.equal(ship.fallenMastTowardShipId, other.id);
  assert.equal(ship.entangledWith, other.id);
  assert.equal(other.entangledWith, ship.id);
});

test('carpenter cut party has deterministic 50 percent success and clears an entangled pair', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  const other = state.ships[2];
  Guard.linkEntanglement(state, ship, other, 'main');
  let result = Guard.resolveCutParty(state, ship, true, () => 0.50);
  assert.equal(result.attempted, true);
  assert.equal(result.success, false, '50 percent is strict below 0.50');
  assert.equal(ship.entangledWith, other.id);

  result = Guard.resolveCutParty(state, ship, true, () => 0.499999);
  assert.equal(result.success, true);
  assert.equal(ship.entangledWith, null);
  assert.equal(other.entangledWith, null);
});

test('full-sail firing risk is 10 percent normally 15 oblique and 20 with direct incoming wind on firing side', () => {
  assert.equal(Combat.windEnteringBand(0, 90), 'ESTRIBOR');
  assert.equal(Combat.windEnteringBand(0, 270), 'BABOR');
  assert.equal(Combat.fullSailFireRisk(0, 0, 'ESTRIBOR'), 0.10);
  assert.equal(Combat.fullSailFireRisk(0, 60, 'ESTRIBOR'), 0.15);
  assert.equal(Combat.fullSailFireRisk(0, 90, 'ESTRIBOR'), 0.20);
  assert.equal(Combat.fullSailFireRisk(0, 240, 'BABOR'), 0.15);
  assert.equal(Combat.fullSailFireRisk(0, 270, 'BABOR'), 0.20);
});

test('an actual logged full-sail broadside can ignite level-one fire using direct incoming wind risk', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 90 });
  const ship = state.ships[0];
  Combat.initializeShipCombatState(ship);
  const snapshot = {
    id: ship.id,
    name: ship.name,
    sail: 'TV',
    heading: 0,
    windFromDeg: 90,
    order: { fire: true, fireBand: 'ESTRIBOR' }
  };
  const outcome = Combat.applyFullSailIgnition(state, snapshot, [`${ship.name} dispara ESTRIBOR (COMPLETA)`], () => 0.199999);
  assert.equal(outcome.checked, true);
  assert.equal(outcome.chance, 0.20);
  assert.equal(outcome.exposure, 'DIRECT');
  assert.equal(outcome.ignited, true);
  assert.equal(ship.fireLevel, 1);
  assert.equal(ship.onFire, true);
});

test('full-sail ignition is not rolled when no broadside actually fired', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 90 });
  const ship = state.ships[0];
  Combat.initializeShipCombatState(ship);
  const snapshot = {
    id: ship.id,
    name: ship.name,
    sail: 'TV',
    heading: 0,
    windFromDeg: 90,
    order: { fire: true, fireBand: 'ESTRIBOR' }
  };
  const outcome = Combat.applyFullSailIgnition(state, snapshot, ['sin solución de tiro'], () => 0);
  assert.equal(outcome.checked, false);
  assert.equal(ship.fireLevel, 0);
});

test('playable page wires swept collision guard tactical overlays prototype rudder and combat privacy UI', () => {
  const html = read('pilot-2v2.html');
  const css = read('pilot-2v2.css');
  const polish = read('src/player-ui-polish.js');
  const combatUi = read('src/combat-ui-rules.js');
  assert.doesNotThrow(() => new Function(combatUi), 'combat-ui-rules.js must parse as browser JavaScript');
  assert.match(html, /src\/collision-guard\.js/);
  assert.match(html, /src\/prototype-rudder-runtime\.js/);
  assert.match(html, /src\/combat-rules\.js/);
  assert.match(html, /src\/combat-ui-rules\.js/);
  assert.match(html, /src\/player-ui-polish\.js/);
  assert.doesNotMatch(html, /Las reglas Velmad verificadas/);
  assert.match(css, /\.fire-row button\.fire-active/);
  assert.match(css, /\.tactical-ring/);
  assert.match(css, /\.threat-ring/);
  assert.match(css, /\.battery-side-highlight/);
  assert.match(polish, /targetShipHighlight/);
  assert.match(polish, /threatShipHighlight/);
  assert.match(polish, /selectedBatteryHighlight/);
  assert.match(combatUi, /Carpinteros: cortar palo aferrado/);
  assert.match(combatUi, /Oculta/);
});
