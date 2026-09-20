const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const Rudder = require('../src/prototype-rudder-runtime.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function freshShip() {
  return Core.buildInitialState(data, { windFromDeg: 180, windStrength: 'MEDIA' }).ships[0];
}

test('playable prototype rudder restores all nine positions from -4 through +4', () => {
  assert.equal(Rudder.MAX_RUDDER, 4);
  const html = fs.readFileSync(path.join(__dirname, '..', 'pilot-2v2.html'), 'utf8');
  for (const point of [-4,-3,-2,-1,0,1,2,3,4]) assert.match(html, new RegExp(`data-rudder=["']${point}["']`));
});

test('prototype rudder base turn points are 10 20 30 and 45 degrees at NV/PV', () => {
  assert.equal(Rudder.rudderTurnDegrees('PV', 1), 10);
  assert.equal(Rudder.rudderTurnDegrees('PV', 2), 20);
  assert.equal(Rudder.rudderTurnDegrees('PV', 3), 30);
  assert.equal(Rudder.rudderTurnDegrees('PV', 4), 45);
  assert.equal(Rudder.rudderTurnDegrees('NV', -4), -45);
});

test('medium and full sail apply the original 0.7 and 0.4 rudder effectiveness factors', () => {
  assert.equal(Rudder.rudderTurnDegrees('MV', 4), 31.499999999999996);
  assert.equal(Rudder.rudderTurnDegrees('TV', 3), 12);
  assert.equal(Rudder.rudderTurnDegrees('TV', 2), 8);
});

test('rudder change and amplitude limits match the stable prototype including TV no-extreme rule', () => {
  const ship = freshShip();
  ship.rudder = 0;
  assert.equal(Rudder.validateRudderOrder(ship, 4, 'PV').valid, true);
  assert.equal(Rudder.validateRudderOrder(ship, 3, 'MV').valid, true);
  assert.equal(Rudder.validateRudderOrder(ship, 4, 'MV').valid, false, 'MV may hold 4 but cannot jump from 0 to 4 in one turn');
  assert.equal(Rudder.validateRudderOrder(ship, 3, 'TV').valid, false, 'TV change limit is two points');
  assert.equal(Rudder.validateRudderOrder(ship, 4, 'TV').valid, false, 'TV never allows ±4');

  ship.rudder = 2;
  assert.equal(Rudder.validateRudderOrder(ship, 3, 'TV').valid, true, 'TV can progressively reach ±3');
  assert.equal(Rudder.validateRudderOrder(ship, 4, 'TV').valid, false);
});

test('damaged rudder remains restricted to one point', () => {
  const ship = freshShip();
  ship.rudderDamaged = true;
  assert.equal(Rudder.validateRudderOrder(ship, 1, 'PV').valid, true);
  assert.equal(Rudder.validateRudderOrder(ship, -1, 'PV').valid, true);
  assert.equal(Rudder.validateRudderOrder(ship, 2, 'PV').valid, false);
});

test('prototype movement projection uses 45 degree T turn at PV before inertia is layered', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 180, windStrength: 'MEDIA' });
  const ship = state.ships[0];
  ship.heading = 90;
  ship.rudder = 0;
  ship.sail = ship.effectiveSail = 'PV';
  const p = Rudder.projectMovement(state, ship, { ...ship.order, sail: 'PV', rudder: 4, fire: false });
  assert.equal(p.valid, true);
  assert.equal(p.heading, 135);
  assert.equal(p.turnDegrees, 45);
});

test('browser script order restores prototype rudder before inertia wraps movement', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'pilot-2v2.html'), 'utf8');
  const rudder = html.indexOf('src/prototype-rudder-runtime.js');
  const inertia = html.indexOf('src/inertia-model.js');
  const collision = html.indexOf('src/collision-guard.js');
  assert.ok(rudder > 0 && rudder < inertia && inertia < collision);
});