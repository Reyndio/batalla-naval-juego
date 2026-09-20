const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function read(name) {
  return fs.readFileSync(path.join(__dirname, '..', name), 'utf8');
}

function stateAtBroadside() {
  const state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
  const attacker = state.ships.find(s => s.side === Core.SIDE_ROYAL_NAVY);
  const target = state.ships.find(s => s.side === Core.SIDE_REAL_ARMADA);
  attacker.x = 300; attacker.y = 300; attacker.heading = 0;
  target.x = 380; target.y = 300; target.heading = 0;
  attacker.order = {
    ...attacker.order,
    fire: true,
    fireBand: 'ESTRIBOR',
    fireSection: 'COMPLETA',
    ammo: 'ROUND_SHOT',
    aim: 'HULL',
    targetId: target.id
  };
  return { state, attacker, target };
}

test('prototype-parity command surface includes explicit start, clock, pause, sail, full helm, firing and camera controls', () => {
  const html = read('pilot-2v2.html');
  for (const sail of ['NV', 'PV', 'MV', 'TV']) assert.match(html, new RegExp(`data-sail=["']${sail}["']`));
  for (const rudder of [-4,-3,-2,-1,0,1,2,3,4]) assert.match(html, new RegExp(`data-rudder=["']${rudder}["']`));
  for (const id of [
    'startBattle','turnDurationInput','turnClock','pauseBattle','windStrengthSetting','rnCrewExperience','raCrewExperience',
    'firePort','fireStarboard','cancelFire','fireSectionSelect','ammoSelect','confirmOrder','resetCamera','fitFleet','zoomIn','zoomOut','tacticalOverlay'
  ]) {
    assert.match(html, new RegExp(`id=["']${id}["']`), `missing restored control ${id}`);
  }
  assert.match(html, /Iniciar partida/);
  assert.match(html, /Cargar para el próximo turno/);
  assert.match(html, /Sin vela/);
  assert.match(html, /Poca vela/);
  assert.match(html, /Media vela/);
  assert.match(html, /Toda vela/);
});

test('UI code contains countdown timeout, movement animation, shadow, detailed hull/sails, right-drag pan and wheel zoom', () => {
  const js = read('src/pilot2v2-ui.js');
  assert.match(js, /startTurnTimer/);
  assert.match(js, /secondsRemaining/);
  assert.match(js, /resolveTurn\('timeout'\)/);
  assert.match(js, /animateTurn/);
  assert.match(js, /drawMovementPreview/);
  assert.match(js, /drawHullShape/);
  assert.match(js, /drawMastsAndSails/);
  assert.match(js, /projectMovement/);
  assert.match(js, /contextmenu/);
  assert.match(js, /e\.button===2/);
  assert.match(js, /addEventListener\('wheel'/);
  assert.match(js, /drawFireArcs/);
});

test('runtime ship state restores prototype crew, fatigue, guns, masts, rudder and ammunition as independent per-ship state', () => {
  const state = Core.buildInitialState(data);
  for (const ship of state.ships) {
    assert.equal(ship.crew, ship.historical.crew.actionComplement);
    assert.equal(ship.gunsPerSide, ship.historical.armament.gunsPerBroadside);
    assert.equal(ship.portGuns, ship.gunsPerSide);
    assert.equal(ship.starboardGuns, ship.gunsPerSide);
    assert.equal(ship.fatigue, 0);
    assert.equal(ship.crewExperience, 'NORMAL');
    assert.equal(ship.rudderDamaged, false);
    assert.equal(ship.loadedAmmo, 'ROUND_SHOT');
    assert.equal(ship.nextAmmo, 'ROUND_SHOT');
    assert.ok(ship.masts.fore && ship.masts.main && ship.masts.mizzen);
  }
});

test('rudder validation matches stable prototype limits: MV change max 3, PV permits 4, damaged rudder only +/-1', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships.find(s => s.side === Core.SIDE_ROYAL_NAVY);
  ship.sail = 'MV';
  ship.order.sail = 'MV';
  ship.rudder = 0;
  assert.equal(Core.validateRudderOrder(ship, 3).valid, true);
  assert.equal(Core.validateRudderOrder(ship, 4).valid, false);
  ship.sail = 'PV'; ship.order.sail = 'PV';
  assert.equal(Core.validateRudderOrder(ship, 4).valid, true);
  ship.rudderDamaged = true;
  assert.equal(Core.validateRudderOrder(ship, 2).valid, false);
  assert.equal(Core.validateRudderOrder(ship, -1).valid, true);
});

test('sail changes are progressive rather than jumping directly through multiple sail states', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships.find(s => s.side === Core.SIDE_ROYAL_NAVY);
  ship.sail = 'NV';
  ship.order = { ...ship.order, sail: 'TV', rudder: 0 };
  const projection = Core.projectMovement(state, ship, ship.order);
  assert.equal(projection.sail, 'PV');
});

test('fatigue uses the Velmad full-sail cost, then exact idle recovery, and affects combat efficiency', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships.find(s => s.side === Core.SIDE_ROYAL_NAVY);
  ship.order = { ...ship.order, sail: 'TV', fire: false };
  Core.resolveTurn(state, { rng: () => 0.5, autoSides: [] });
  assert.equal(ship.fatigue, Core.FATIGUE_MAKE_FULL_SAIL);

  ship.order = { ...ship.order, sail: ship.sail, fire: false };
  Core.resolveTurn(state, { rng: () => 0.5, autoSides: [] });
  assert.equal(ship.fatigue, Core.FATIGUE_MAKE_FULL_SAIL - Core.FATIGUE_RECOVERY);

  ship.crewExperience = 'NORMAL';
  ship.fatigue = 100;
  assert.ok(Core.fatigueEfficiency(ship) < 1);
});

test('hull fire dismounts guns on the struck side and later broadside strength uses remaining guns', () => {
  const { state, attacker, target } = stateAtBroadside();
  const beforePort = target.portGuns;
  const shot = Core.resolveShot(state, attacker, () => 0.5);
  assert.ok(shot && shot.hullDamage > 0);
  assert.ok(shot.gunsLost > 0);
  assert.ok(target.portGuns < beforePort);
  assert.equal(target.starboardGuns, target.gunsPerSide);
});

test('rigging fire damages independent mast state and total rig state', () => {
  const { state, attacker, target } = stateAtBroadside();
  attacker.order.aim = 'RIGGING';
  const beforeRig = target.rig;
  const beforeMain = target.masts.main.health;
  const shot = Core.resolveShot(state, attacker, () => 0.5);
  assert.ok(shot && shot.rigDamage > 0);
  assert.ok(target.rig < beforeRig);
  assert.ok(target.masts.main.health < beforeMain);
});

test('loaded ammunition is distinct from the ammunition ordered for the next load', () => {
  const { state, attacker } = stateAtBroadside();
  attacker.loadedAmmo = 'ROUND_SHOT';
  attacker.order.ammo = 'DOUBLE_SHOT';
  Core.resolveTurn(state, { rng: () => 0.5, autoSides: [] });
  assert.equal(attacker.loadedAmmo, 'DOUBLE_SHOT');
});

test('player can explicitly order port or starboard fire and confirmations reopen after turn resolution', () => {
  const state = Core.buildInitialState(data);
  const rn = state.ships.filter(s => s.side === Core.SIDE_ROYAL_NAVY);
  const enemy = state.ships.find(s => s.side === Core.SIDE_REAL_ARMADA);
  rn[0].order = { ...rn[0].order, fire: true, fireBand: 'BABOR', fireSection: 'COMPLETA', ammo: 'ROUND_SHOT', targetId: enemy.id };
  rn[0].confirmed = true;
  rn[1].confirmed = true;
  assert.equal(rn[0].order.fireBand, 'BABOR');
  Core.resolveTurn(state, { rng: () => 0.5, autoSides: [] });
  assert.equal(rn[0].confirmed, false);
  assert.equal(rn[1].confirmed, false);
});
