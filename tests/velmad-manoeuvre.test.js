const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Core = require('../src/pilot2v2-core.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function freshShip(index = 0) {
  return Core.buildInitialState(data).ships[index];
}

test('all four pilot ships are Velmad third class from their documented 74-gun rating', () => {
  const state = Core.buildInitialState(data);
  for (const ship of state.ships) {
    assert.equal(Core.velmadClassOf(ship), 3);
    assert.equal(ship.velmadClass, 3);
    assert.equal(Core.velmadClassSpeedFactor(ship), 1);
    assert.equal(Core.velmadTwoPointBaseChance(ship), 0.75);
  }
});

test('Velmad helm uses two points maximum and each point turns 15 degrees', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0 });
  const ship = state.ships[0];
  ship.heading = 90;
  ship.rudder = 0;
  assert.equal(Core.MAX_RUDDER, 2);
  assert.equal(Core.RUDDER_POINT_DEG, 15);
  const one = Core.projectMovement(state, ship, { ...ship.order, sail: 'MV', rudder: 1 }, { rng: () => 0, resolveChance: true });
  assert.equal(one.heading, 105);
  const two = Core.projectMovement(state, ship, { ...ship.order, sail: 'MV', rudder: 2 }, { rng: () => 0, resolveChance: true });
  assert.equal(two.heading, 120);
});

test('normal third-class crew gets exact 75 percent independent two-point chance', () => {
  const ship = freshShip();
  ship.crewExperience = 'NORMAL';
  ship.rudder = 0;
  assert.equal(Core.twoPointChance(ship), 0.75);
  assert.equal(Core.resolveRudderOrder(ship, 2, () => 0.749999, false).value, 2);
  assert.equal(Core.resolveRudderOrder(ship, 2, () => 0.75, false).value, 1);
});

test('previous-turn helm already on the same side permits two points without the class roll', () => {
  const ship = freshShip();
  ship.crewExperience = 'NOVATA';
  ship.rudder = -1;
  const result = Core.resolveRudderOrder(ship, -2, () => 0.999999, false);
  assert.equal(result.value, -2);
  assert.equal(result.rolled, false);
});

test('Beginner halves class chance while Veteran and Elite can always use two points', () => {
  const ship = freshShip();
  ship.rudder = 0;
  ship.crewExperience = 'NOVATA';
  assert.equal(Core.twoPointChance(ship), 0.375);
  assert.equal(Core.resolveRudderOrder(ship, 2, () => 0.374999, false).value, 2);
  assert.equal(Core.resolveRudderOrder(ship, 2, () => 0.375, false).value, 1);
  for (const quality of ['VETERANA', 'ELITE']) {
    ship.crewExperience = quality;
    assert.equal(Core.twoPointChance(ship), 1);
    assert.equal(Core.resolveRudderOrder(ship, 2, () => 0.999999, false).value, 2);
  }
});

test('one fallen mast limits helm to one point and a dismasted ship cannot turn', () => {
  const ship = freshShip();
  ship.masts.fore.fallen = true;
  assert.equal(Core.availableRudderPointsByMasts(ship), 1);
  assert.equal(Core.validateRudderOrder(ship, 2).valid, false);
  assert.equal(Core.validateRudderOrder(ship, 1).valid, true);
  ship.masts.main.fallen = true;
  ship.masts.mizzen.fallen = true;
  assert.equal(Core.availableRudderPointsByMasts(ship), 0);
  assert.equal(Core.validateRudderOrder(ship, 1).valid, false);
});

test('tacking stops exactly head-to-wind and departure is limited to one point', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0 });
  const ship = state.ships[0];
  ship.heading = 350;
  let result = Core.turnWithTacking(state, ship, 2);
  assert.equal(result.heading, 0);
  assert.equal(result.usedPoints, 1);
  assert.equal(result.hitWind, true);
  ship.heading = 0;
  ship.tackingAgainstWind = true;
  result = Core.turnWithTacking(state, ship, 2);
  assert.equal(result.heading, 15);
  assert.equal(result.usedPoints, 1);
  assert.equal(result.leavingWind, true);
});

test('direct NV to TV and TV to NV cross three sail points and cost 30 fatigue each', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0 });
  const ship = state.ships[0];
  ship.sail = 'NV';
  ship.effectiveSail = 'NV';
  let projection = Core.projectMovement(state, ship, { ...ship.order, sail: 'TV', rudder: 0 }, { rng: () => 0, resolveChance: true });
  assert.equal(projection.sail, 'TV');
  assert.equal(Core.sailChangeFatigueCost('NV', 'TV'), 30);
  ship.sail = 'TV';
  ship.effectiveSail = 'TV';
  projection = Core.projectMovement(state, ship, { ...ship.order, sail: 'NV', rudder: 0 }, { rng: () => 0, resolveChance: true });
  assert.equal(projection.sail, 'NV');
  assert.equal(Core.sailChangeFatigueCost('TV', 'NV'), 30);
});

test('runtime core exposes sail-point fatigue guidance and two-point helm UI', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'pilot2v2-core.js'), 'utf8');
  assert.match(source, /velmadNoSail/);
  assert.match(source, /velmadFullSail/);
  assert.match(source, /cada punto de velamen NV↔PV↔MV↔TV cuesta \+10%/);
  assert.match(source, /Timón Velmad — 1 punto = 15°/);
});
