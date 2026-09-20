const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Core = require('../src/pilot2v2-core.js');
const Gunnery = require('../src/velmad-gunnery.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function broadsideState(distance = 80, windFromDeg = 0) {
  const state = Core.buildInitialState(data, { windFromDeg, windStrength: 'MEDIA' });
  const attacker = state.ships.find(s => s.side === Core.SIDE_ROYAL_NAVY);
  const target = state.ships.find(s => s.side === Core.SIDE_REAL_ARMADA);
  attacker.x = 300; attacker.y = 300; attacker.heading = 0; attacker.sail = 'MV'; attacker.effectiveSail = 'MV';
  target.x = 300 + distance; target.y = 300; target.heading = 0; target.sail = 'MV'; target.effectiveSail = 'MV';
  Gunnery.ensureAmmoState(attacker);
  attacker.order = {
    ...attacker.order,
    fire: true,
    fireBand: 'ESTRIBOR',
    fireSection: 'COMPLETA',
    ammo: 'ROUND_SHOT',
    aim: 'HULL',
    targetId: target.id,
    reloadDoubleShot: false,
    reloadDoubleShotBand: null,
    sail: 'MV', rudder: 0
  };
  return { state, attacker, target };
}

test('Velmad explicit ammunition family contains round, bar/chain, grape and separately reloaded double shot', () => {
  assert.deepEqual(Gunnery.STANDARD_AMMO, ['ROUND_SHOT', 'BAR_CHAIN', 'GRAPE']);
  assert.deepEqual(Gunnery.ALL_AMMO, ['ROUND_SHOT', 'BAR_CHAIN', 'GRAPE', 'DOUBLE_SHOT']);
});

test('explicit ammunition damage modifiers follow v1.2 values', () => {
  assert.equal(Gunnery.ammoPowerModifier('ROUND_SHOT', 'HULL', 200), 1);
  assert.equal(Gunnery.ammoPowerModifier('ROUND_SHOT', 'RIGGING', 200), 0.5);
  assert.equal(Gunnery.ammoPowerModifier('BAR_CHAIN', 'HULL', 200), 0.5);
  assert.equal(Gunnery.ammoPowerModifier('BAR_CHAIN', 'RIGGING', 200), 1);
  assert.equal(Gunnery.ammoPowerModifier('BAR_CHAIN', 'RIGGING', 526), 1 / 3);
  assert.equal(Gunnery.ammoPowerModifier('GRAPE', 'HULL', 200), 0.5);
  assert.equal(Gunnery.ammoPowerModifier('GRAPE', 'RIGGING', 200), 1 / 3);
  assert.equal(Gunnery.ammoPowerModifier('DOUBLE_SHOT', 'HULL', 112), 1.25);
  assert.equal(Gunnery.ammoPowerModifier('DOUBLE_SHOT', 'HULL', 113), 0.25);
});

test('target sail state applies exact rigging-damage factors', () => {
  assert.equal(Gunnery.targetSailRiggingFactor('MV'), 1);
  assert.equal(Gunnery.targetSailRiggingFactor('TV'), 1.5);
  assert.equal(Gunnery.targetSailRiggingFactor('PV'), 0.9);
  assert.equal(Gunnery.targetSailRiggingFactor('NV'), 0.5);
});

test('windward and leeward allocations use the explicit Velmad percentages', () => {
  assert.deepEqual(Gunnery.distributeDamage(100, 'HULL', 'TARGET_WINDWARD'), { hull: 60, rig: 30, lost: 10 });
  assert.deepEqual(Gunnery.distributeDamage(100, 'RIGGING', 'TARGET_WINDWARD'), { hull: 0, rig: 90, lost: 10 });
  assert.deepEqual(Gunnery.distributeDamage(100, 'HULL', 'TARGET_LEEWARD'), { hull: 100, rig: 0, lost: 0 });
  assert.deepEqual(Gunnery.distributeDamage(100, 'RIGGING', 'TARGET_LEEWARD'), { hull: 40, rig: 60, lost: 0 });
  assert.deepEqual(Gunnery.distributeDamage(100, 'HULL', 'CROSSWIND'), { hull: 90, rig: 10, lost: 0 });
});

test('30 degree total wind fork classifies target windward/leeward around the wind axis', () => {
  let { state, attacker, target } = broadsideState(150, 90);
  assert.equal(Gunnery.windShotPosition(state, attacker, target), 'TARGET_WINDWARD');
  state.windFromDeg = 270;
  assert.equal(Gunnery.windShotPosition(state, attacker, target), 'TARGET_LEEWARD');
  state.windFromDeg = 0;
  assert.equal(Gunnery.windShotPosition(state, attacker, target), 'CROSSWIND');
});

test('carronades contribute by exact 300/225/150m table and Spanish obuses are not silently treated as carronades', () => {
  const state = Core.buildInitialState(data);
  const bellerophon = state.ships.find(s => s.id === 'bellerophon-1805');
  const montanes = state.ships.find(s => s.id === 'montanes-1805');
  assert.ok(Gunnery.carronadeBroadsideKg(bellerophon) > 0);
  assert.equal(Gunnery.carronadeBroadsideKg(montanes), 0);
  assert.equal(Gunnery.carronadeRangeFactor(301), 0);
  assert.equal(Gunnery.carronadeRangeFactor(300), 1 / 3);
  assert.equal(Gunnery.carronadeRangeFactor(225), 0.5);
  assert.equal(Gunnery.carronadeRangeFactor(150), 1);
});

test('full sail excludes upperworks long guns and carronades from firing power', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships.find(s => s.id === 'bellerophon-1805');
  ship.sail = 'MV';
  const mediumLong = Gunnery.longGunBroadsideKg(ship);
  const mediumCarr = Gunnery.carronadeBroadsideKg(ship);
  ship.sail = 'TV';
  assert.ok(Gunnery.longGunBroadsideKg(ship) < mediumLong);
  assert.ok(mediumCarr > 0);
  assert.equal(Gunnery.carronadeBroadsideKg(ship), 0);
});

test('no sail gives firing bonus equal to 10 less fatigue and full sail gives 10 more', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships[0];
  ship.crewExperience = 'NORMAL';
  ship.sail = 'MV';
  const medium = Gunnery.firingEfficiencyAt(ship, 40);
  ship.sail = 'NV';
  const noSail = Gunnery.firingEfficiencyAt(ship, 40);
  ship.sail = 'TV';
  const full = Gunnery.firingEfficiencyAt(ship, 40);
  assert.ok(noSail > medium);
  assert.ok(full < medium);
  assert.equal(noSail, Gunnery.firingEfficiencyAt({ ...ship, sail: 'MV' }, 30));
});

test('at 112m or less aiming is forced to hull', () => {
  const { state, attacker, target } = broadsideState(80, 0);
  attacker.order.aim = 'RIGGING';
  const shot = Gunnery.resolveShotVelmad(state, attacker, () => 0.5, { fatigueAtFire: 0, canFireAtStart: true, windFromDeg: 0 });
  assert.equal(shot.fired, true);
  assert.equal(shot.orderedAim, 'RIGGING');
  assert.equal(shot.effectiveAim, 'HULL');
  assert.ok(shot.hullDamage > 0);
  assert.ok(target.hull < target.maxHull);
});

test('a fired band reloads selected standard ammunition for the next turn while the opposite band retains its load', () => {
  const { state, attacker } = broadsideState(150, 0);
  attacker.loadedAmmoByBand.BABOR = 'GRAPE';
  attacker.loadedAmmoByBand.ESTRIBOR = 'ROUND_SHOT';
  attacker.order.ammo = 'BAR_CHAIN';
  const shot = Gunnery.resolveShotVelmad(state, attacker, () => 0.5, { fatigueAtFire: 0, canFireAtStart: true, windFromDeg: 0 });
  assert.equal(shot.fired, true);
  assert.equal(shot.ammo, 'ROUND_SHOT');
  assert.equal(attacker.loadedAmmoByBand.ESTRIBOR, 'BAR_CHAIN');
  assert.equal(attacker.loadedAmmoByBand.BABOR, 'GRAPE');
});

test('double shot reload requires round shot, costs 10 fatigue, blocks that band and becomes available next turn', () => {
  const { state, attacker, target } = broadsideState(150, 0);
  attacker.loadedAmmoByBand.ESTRIBOR = 'ROUND_SHOT';
  attacker.order.reloadDoubleShot = true;
  attacker.order.reloadDoubleShotBand = 'ESTRIBOR';
  attacker.order.fire = true;
  attacker.order.fireBand = 'ESTRIBOR';
  attacker.order.targetId = target.id;
  const targetHull = target.hull;
  Core.resolveTurn(state, { rng: () => 0.5, autoSides: [] });
  assert.equal(attacker.loadedAmmoByBand.ESTRIBOR, 'DOUBLE_SHOT');
  assert.equal(attacker.fatigue, 10);
  assert.equal(target.hull, targetHull);
  assert.equal(attacker.order.reloadDoubleShot, false);
});

test('double shot cannot be reloaded over non-round ammunition', () => {
  const { attacker } = broadsideState(150, 0);
  attacker.loadedAmmoByBand.BABOR = 'GRAPE';
  assert.equal(Gunnery.canReloadDoubleShot(attacker, 'BABOR'), false);
  attacker.loadedAmmoByBand.BABOR = 'ROUND_SHOT';
  assert.equal(Gunnery.canReloadDoubleShot(attacker, 'BABOR'), true);
});

test('pilot HTML loads Velmad gunnery layer and exposes bar/chain while double shot is a separate reload action', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'pilot-2v2.html'), 'utf8');
  const addon = fs.readFileSync(path.join(__dirname, '..', 'src', 'velmad-gunnery.js'), 'utf8');
  assert.match(html, /src="src\/velmad-gunnery\.js"/);
  assert.match(html, /value="BAR_CHAIN"/);
  assert.doesNotMatch(html, /<option value="DOUBLE_SHOT">/);
  assert.match(addon, /doubleReloadAction/);
  assert.match(addon, /Requiere bala redonda ya cargada/);
});
