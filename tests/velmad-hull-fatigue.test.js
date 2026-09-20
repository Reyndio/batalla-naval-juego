const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Core = require('../src/pilot2v2-core.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function freshShip() {
  return Core.buildInitialState(data).ships[0];
}

test('Hull 0 remains operational until the 10 percent sinking check actually triggers', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  ship.hull = 0;
  Core.updateSpeedEfficiency(ship);
  assert.equal(ship.sunk, false);
  assert.equal(ship.sinking, false);
  assert.equal(Core.livingShips(state, ship.side).includes(ship), true);
  assert.equal(Core.checkHullZeroSinking(ship, () => 0.10, state), false);
  assert.equal(ship.sunk, false);
});

test('Hull 0 has an exact 10 percent per-turn sinking trigger and becomes out of combat when triggered', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  ship.hull = 0;
  assert.equal(Core.checkHullZeroSinking(ship, () => 0.099999, state), true);
  assert.equal(ship.sinking, true);
  assert.equal(ship.sunk, true);
  assert.equal(ship.disabled, true);
  assert.equal(Core.livingShips(state, ship.side).includes(ship), false);
});

test('Hull 0 and Hull 1 cap speed at 70 percent', () => {
  const ship = freshShip();
  ship.hull = 1;
  assert.ok(Core.updateSpeedEfficiency(ship) <= 0.70);
  ship.hull = 0;
  assert.ok(Core.updateSpeedEfficiency(ship) <= 0.70);
});

test('Hull 0 disables the lower/main battery while Hull 1 restores it', () => {
  const ship = freshShip();
  ship.hull = 0;
  assert.equal(Core.mainBatteryAvailable(ship), false);
  assert.ok(Core.availableBroadsidePowerFactor(ship) > 0 && Core.availableBroadsidePowerFactor(ship) < 1);
  ship.hull = 1;
  assert.equal(Core.mainBatteryAvailable(ship), true);
  assert.equal(Core.availableBroadsidePowerFactor(ship), 1);
});

test('Hull 0 can be pumped to Hull 1 at fatigue <= 100 for +20 fatigue', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  ship.hull = 0;
  ship.fatigue = 100;
  assert.equal(Core.canRepairHullZeroToOne(ship), true);
  const result = Core.repairHullZeroToOne(ship, state);
  assert.equal(result.success, true);
  assert.equal(ship.hull, 1);
  assert.equal(ship.fatigue, 120);

  const blocked = state.ships[1];
  blocked.hull = 0;
  blocked.fatigue = 101;
  assert.equal(Core.canRepairHullZeroToOne(blocked), false);
});

test('Velmad broadside and collision fatigue costs are exact', () => {
  assert.equal(Core.broadsideFatigueCost(1), 10);
  assert.equal(Core.broadsideFatigueCost(2), 30);
  assert.equal(Core.collisionFatigueCost('TV'), 60);
  assert.equal(Core.collisionFatigueCost('MV'), 40);
  assert.equal(Core.collisionFatigueCost('PV'), 40);
  assert.equal(Core.collisionFatigueCost('NV'), 0);
});

test('sail fatigue keeps explicit values while 30/30 applies only to the direct extreme reconstruction', () => {
  assert.equal(Core.sailChangeFatigueCost('MV', 'TV'), 30);
  assert.equal(Core.sailChangeFatigueCost('PV', 'TV'), 30);
  assert.equal(Core.sailChangeFatigueCost('NV', 'TV'), 30);
  assert.equal(Core.sailChangeFatigueCost('TV', 'NV'), 30);
  assert.equal(Core.sailChangeFatigueCost('PV', 'NV'), 0);
  assert.equal(Core.sailChangeFatigueCost('MV', 'NV'), 0);
  assert.equal(Core.sailChangeFatigueCost('NV', 'PV'), 20);
  assert.equal(Core.sailChangeFatigueCost('NV', 'MV'), 20);

  const ship = freshShip();
  ship.fatigue = 80;
  Core.recoverFatigue(ship);
  assert.equal(ship.fatigue, 70);
  ship.fatigue = 81;
  Core.recoverFatigue(ship);
  assert.equal(ship.fatigue, 61);
});

test('PV to NV is an ordinary reduction, not the reconstructed TV to NV +30 extreme action', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  ship.sail = 'PV';
  ship.effectiveSail = 'PV';
  ship.fatigue = 50;
  ship.order = { ...ship.order, sail: 'NV', rudder: 0, fire: false, reloadDoubleShot: false, fireFighting: false, cutMast: false };
  for (const other of state.ships.slice(1)) {
    other.order = { ...other.order, sail: other.sail, rudder: 0, fire: false, reloadDoubleShot: false, fireFighting: false, cutMast: false };
  }
  Core.resolveTurn(state, { rng: () => 0.5, autoSides: [] });
  assert.equal(ship.sail, 'NV');
  assert.equal(ship.fatigue, 40);
});

test('all four Velmad crew-quality firing penalties and firing fatigue limits are represented', () => {
  const ship = freshShip();
  const cases = [
    ['NOVATA', 0.94, 100],
    ['NORMAL', 0.95, 100],
    ['VETERANA', 0.96, 120],
    ['ELITE', 0.97, 120]
  ];

  for (const [quality, efficiencyAt10, maxFatigue] of cases) {
    ship.crewExperience = quality;
    ship.fatigue = 10;
    assert.equal(Core.fatigueEfficiency(ship), efficiencyAt10);
    ship.fatigue = maxFatigue;
    assert.equal(Core.canShipFire(ship), true);
    ship.fatigue = maxFatigue + 1;
    assert.equal(Core.canShipFire(ship), false);
  }

  assert.equal(Core.crewQualityProfile('NOVATA').twoPointChanceMultiplier, 0.5);
  assert.equal(Core.crewQualityProfile('VETERANA').veteranTwoPoint, true);
  assert.equal(Core.crewQualityProfile('ELITE').eliteAllRudder, true);
});

test('runtime core exposes the Velmad damage-control UI hook and Elite crew option', () => {
  const coreSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'pilot2v2-core.js'), 'utf8');
  assert.match(coreSource, /pumpHullAction/);
  assert.match(coreSource, /Bombear\/reparar casco 0→1/);
  assert.match(coreSource, /value='ELITE'/);
});
