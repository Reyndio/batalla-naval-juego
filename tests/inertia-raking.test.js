const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const Inertia = require('../src/inertia-model.js');
const Raking = require('../src/raking-geometry.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function quietOrders(state) {
  for (const ship of state.ships) {
    ship.order = {
      ...ship.order,
      sail: ship.sail,
      rudder: 0,
      fire: false,
      reloadDoubleShot: false,
      fireFighting: false,
      cutMast: false
    };
  }
}

function shotState(attackerHeading) {
  const state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
  const attacker = state.ships[0];
  const defender = state.ships[2];
  attacker.x = 500; attacker.y = 450; attacker.heading = attackerHeading;
  defender.x = 500; defender.y = 300; defender.heading = 0;
  attacker.sail = attacker.effectiveSail = 'MV';
  defender.sail = defender.effectiveSail = 'MV';
  attacker.fatigue = 0;
  attacker.order = {
    ...attacker.order,
    sail: 'MV', rudder: 0, fire: true,
    fireBand: 'BABOR', fireSection: 'AUTO',
    ammo: 'ROUND_SHOT', aim: 'HULL', targetId: defender.id
  };
  Core.ensureAmmoState(attacker);
  return { state, attacker, defender };
}

test('third-class ships retain way when sail is removed instead of stopping instantly', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
  const ship = state.ships[0];
  assert.equal(Inertia.responseFor(ship), 0.40);
  assert.ok(ship.motionSpeed > 0, 'initial underway state must carry motion');

  const projection = Core.projectMovement(state, ship, { ...ship.order, sail: 'NV', rudder: 0, fire: false });
  const travelled = Math.hypot(projection.x - ship.x, projection.y - ship.y);
  assert.equal(projection.inertia.commandedSpeed, 0);
  assert.ok(travelled > 0, 'no-sail order must still carry existing way');
  assert.ok(projection.inertia.nextSpeed < projection.inertia.oldSpeed);
});

test('a ship starting from no way accelerates progressively rather than jumping to commanded speed', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
  const ship = state.ships[0];
  ship.sail = ship.effectiveSail = 'NV';
  ship.motionVx = 0;
  ship.motionVy = 0;
  ship.motionSpeed = 0;

  const projection = Core.projectMovement(state, ship, { ...ship.order, sail: 'TV', rudder: 0, fire: false });
  assert.ok(projection.inertia.commandedSpeed > 0);
  assert.ok(projection.inertia.movementSpeed > 0);
  assert.ok(projection.inertia.movementSpeed < projection.inertia.commandedSpeed);
  assert.ok(projection.inertia.nextSpeed < projection.inertia.commandedSpeed);
});

test('resolved no-sail turns keep diminishing residual motion over successive turns', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
  quietOrders(state);
  const ship = state.ships[0];
  const start = { x: ship.x, y: ship.y };
  const speed0 = ship.motionSpeed;
  ship.order.sail = 'NV';

  Core.resolveTurn(state, { rng: () => 0.5, autoSides: [] });
  const d1 = Math.hypot(ship.x - start.x, ship.y - start.y);
  const speed1 = ship.motionSpeed;
  assert.ok(d1 > 0);
  assert.ok(speed1 < speed0);

  const secondStart = { x: ship.x, y: ship.y };
  ship.order = { ...ship.order, sail: 'NV', rudder: 0, fire: false };
  Core.resolveTurn(state, { rng: () => 0.5, autoSides: [] });
  const d2 = Math.hypot(ship.x - secondStart.x, ship.y - secondStart.y);
  assert.ok(d2 > 0);
  assert.ok(ship.motionSpeed < speed1);
  assert.ok(d2 < d1);
});

test('stern or bow rake requires a T-like perpendicular geometry, not an oblique L-like geometry', () => {
  const valid = shotState(90);
  assert.equal(Raking.axisRelation(valid.defender, valid.attacker), 'STERN');
  assert.equal(Raking.isTPosition(valid.attacker, valid.defender), true);
  const validShot = Core.resolveShot(valid.state, valid.attacker, () => 0.5);
  assert.ok(validShot && validShot.fired);
  assert.equal(validShot.rake, 'STERN');

  const invalid = shotState(45);
  assert.equal(Raking.axisRelation(invalid.defender, invalid.attacker), 'STERN');
  assert.equal(Raking.isTPosition(invalid.attacker, invalid.defender), false);
  const corrected = Core.angleTo(invalid.defender, invalid.attacker);
  const rel = ((corrected - invalid.defender.heading) % 360 + 360) % 360;
  assert.ok(rel < 165 || rel > 195, `corrected defender-axis bearing ${rel}° must be outside rake cone`);
  const invalidShot = Core.resolveShot(invalid.state, invalid.attacker, () => 0.5);
  assert.ok(invalidShot && invalidShot.fired);
  assert.equal(invalidShot.rake, null);
});

test('playable page installs inertia before collision/gunnery and previews inertia explicitly', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'pilot-2v2.html'), 'utf8');
  const inertiaPos = html.indexOf('src/inertia-model.js');
  const collisionPos = html.indexOf('src/collision-guard.js');
  const rakePos = html.indexOf('src/raking-geometry.js');
  const gunneryPos = html.indexOf('src/velmad-gunnery.js');
  assert.ok(inertiaPos > 0 && inertiaPos < collisionPos);
  assert.ok(rakePos > collisionPos && rakePos < gunneryPos);
  assert.match(html, /posición prevista incluyendo inercia/);
});
