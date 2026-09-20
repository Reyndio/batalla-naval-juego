const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const Combat = require('../src/combat-rules.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function stateAndShip() {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  Combat.initializeShipCombatState(ship);
  return { state, ship };
}

function sequence(values, fallback = 0.99) {
  let i = 0;
  return () => i < values.length ? values[i++] : fallback;
}

test('unattended fire rises one level per turn', () => {
  const { state, ship } = stateAndShip();
  ship.fireLevel = 1;
  ship.onFire = true;
  const snap = { fireLevel: 1, sail: ship.sail, order: { fire: false, sail: ship.sail, fireFighting: false } };
  const result = Combat.processExistingFire(state, ship, snap, () => 0.99);
  assert.equal(result.processed, true);
  assert.equal(ship.fireLevel, 2);
  assert.equal(ship.onFire, true);
});

test('firefighting control chance falls ten points per fire level and successful free team reduces two levels', () => {
  assert.equal(Combat.fireControlChance(1), 0.50);
  assert.equal(Combat.fireControlChance(2), 0.40);
  assert.equal(Combat.fireControlChance(3), 0.30);
  assert.equal(Combat.fireControlChance(4), 0.20);
  const { state, ship } = stateAndShip();
  ship.fireLevel = 2;
  ship.onFire = true;
  const snap = { fireLevel: 2, sail: 'MV', order: { fire: false, sail: 'MV', fireFighting: true } };
  const result = Combat.processExistingFire(state, ship, snap, () => 0.1);
  assert.equal(result.controlSuccess, true);
  assert.equal(ship.fireLevel, 0);
  assert.equal(ship.onFire, false);
});

test('successful firefighting while firing or changing sail reduces only one level', () => {
  const { state, ship } = stateAndShip();
  ship.fireLevel = 3;
  ship.onFire = true;
  const snap = { fireLevel: 3, sail: 'MV', order: { fire: true, sail: 'TV', fireFighting: true } };
  const result = Combat.processExistingFire(state, ship, snap, sequence([0.1, 0.99, 0.99]));
  assert.equal(result.controlSuccess, true);
  assert.equal(ship.fireLevel, 2);
});

test('failed firefighting can increase fire one level', () => {
  const { state, ship } = stateAndShip();
  ship.fireLevel = 1;
  ship.onFire = true;
  const snap = { fireLevel: 1, sail: 'MV', order: { fire: false, sail: 'MV', fireFighting: true } };
  const result = Combat.processExistingFire(state, ship, snap, sequence([0.9, 0.1]));
  assert.equal(result.controlSuccess, false);
  assert.equal(ship.fireLevel, 2);
});

test('level three fire damages hull or mast and uses 33 percent explosion risk', () => {
  const { state, ship } = stateAndShip();
  ship.fireLevel = 3;
  ship.onFire = true;
  const hull = ship.hull;
  const result = Combat.applyFireDamage(state, ship, sequence([0.1, 0.99]));
  assert.equal(result.level, 3);
  assert.equal(result.exploded, false);
  assert.equal(ship.hull, hull - Combat.FIRE_LEVEL3_DAMAGE);
});

test('level four fire can explode the ship at 66 percent risk', () => {
  const { state, ship } = stateAndShip();
  ship.fireLevel = 4;
  ship.onFire = true;
  const result = Combat.applyFireDamage(state, ship, sequence([0.5, 0.1, 0.1]));
  assert.equal(result.exploded, true);
  assert.equal(ship.sunk, true);
  assert.equal(ship.disabled, true);
  assert.equal(ship.hull, 0);
});

test('entangled fire transmits with ten percent per source fire level', () => {
  const state = Core.buildInitialState(data);
  const a = state.ships[0];
  const b = state.ships[2];
  Combat.initializeShipCombatState(a);
  Combat.initializeShipCombatState(b);
  a.entangledWith = b.id;
  b.entangledWith = a.id;
  a.fireLevel = 3;
  a.onFire = true;
  const events = Combat.transmitEntangledFire(state, () => 0.299999, new Set());
  assert.ok(events.some(e => e.from === a.id && e.to === b.id && e.chance === 0.30 && e.ignited));
  assert.equal(b.fireLevel, 1);
  assert.equal(b.onFire, true);
});

test('damage-control UI exposes firefighting action without revealing exact enemy fatigue', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'combat-ui-rules.js'), 'utf8');
  assert.doesNotThrow(() => new Function(source));
  assert.match(source, /Partida contra incendios \(\+10% fatiga\)/);
  assert.match(source, /Oculta/);
});
