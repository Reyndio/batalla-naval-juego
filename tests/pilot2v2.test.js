const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function byId(id) {
  return data.ships.find(s => s.id === id);
}

test('historical data contains exactly two coherent ships per national side', () => {
  assert.equal(data.ships.length, 4);
  assert.equal(data.ships.filter(s => s.side === Core.SIDE_ROYAL_NAVY).length, 2);
  assert.equal(data.ships.filter(s => s.side === Core.SIDE_REAL_ARMADA).length, 2);
  assert.equal(new Set(data.ships.map(s => s.id)).size, 4);
  assert.deepEqual(
    data.ships.filter(s => s.side === Core.SIDE_ROYAL_NAVY).map(s => s.navy),
    ['Royal Navy', 'Royal Navy']
  );
  assert.deepEqual(
    data.ships.filter(s => s.side === Core.SIDE_REAL_ARMADA).map(s => s.navy),
    ['Real Armada', 'Real Armada']
  );
});

test('selected 1805 ship records preserve frozen complements and principal batteries', () => {
  assert.equal(byId('bellerophon-1805').crew.actionComplement, 522);
  assert.equal(byId('bellerophon-1805').armament.principalPieces, 82);
  assert.equal(byId('conqueror-1805').crew.actionComplement, 573);
  assert.equal(byId('conqueror-1805').armament.principalPieces, 82);
  assert.equal(byId('montanes-1805').crew.actionComplement, 749);
  assert.equal(byId('montanes-1805').armament.principalPieces, 76);
  assert.equal(byId('bahama-1805').crew.actionComplement, 689);
  assert.equal(byId('bahama-1805').armament.principalPieces, 78);
});

test('initial 2v2 state is valid and keeps each ship independent', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
  assert.deepEqual(Core.validateState(state), []);
  assert.equal(state.ships.length, 4);
  assert.equal(state.ships.filter(s => s.side === Core.SIDE_ROYAL_NAVY).length, 2);
  assert.equal(state.ships.filter(s => s.side === Core.SIDE_REAL_ARMADA).length, 2);
  assert.equal(new Set(state.ships.map(s => `${s.x},${s.y}`)).size, 4);

  const a = state.ships[0];
  const b = state.ships[1];
  a.hull -= 100;
  assert.equal(b.hull, Core.BASE_HULL, 'damage on one ship must not leak into another ship state');
});

test('targeting is side-safe and AI assigns an enemy target', () => {
  const state = Core.buildInitialState(data);
  for (const ship of state.ships) {
    const order = Core.planAIOrder(state, ship);
    assert.ok(order.targetId);
    const target = state.ships.find(s => s.id === order.targetId);
    assert.ok(target);
    assert.notEqual(target.side, ship.side);
  }
});

test('seeded four-ship simulation remains numerically valid over many turns', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
  const rng = Core.seededRng(1805);
  for (let i = 0; i < 160 && !state.result; i++) {
    Core.resolveTurn(state, {
      rng,
      autoSides: [Core.SIDE_ROYAL_NAVY, Core.SIDE_REAL_ARMADA]
    });
    assert.deepEqual(Core.validateState(state), [], `state corruption at loop ${i}`);
    for (const ship of state.ships) {
      assert.ok(ship.hull >= 0 && ship.hull <= ship.maxHull);
      assert.ok(ship.rig >= 0 && ship.rig <= ship.maxRig);
      assert.ok(ship.crew >= 0 && ship.crew <= ship.initialCrew);
      assert.ok(ship.x >= 20 && ship.x <= Core.WORLD.width - 20);
      assert.ok(ship.y >= 20 && ship.y <= Core.WORLD.height - 20);
    }
  }
  assert.ok(state.turn > 1);
  assert.ok(state.log.length > 1);
});

test('both human-side ships can retain separate orders and targets', () => {
  const state = Core.buildInitialState(data);
  const rn = state.ships.filter(s => s.side === Core.SIDE_ROYAL_NAVY);
  const sp = state.ships.filter(s => s.side === Core.SIDE_REAL_ARMADA);

  rn[0].order = { sail: 'TV', rudder: 2, fire: true, aim: 'HULL', targetId: sp[0].id };
  rn[1].order = { sail: 'PV', rudder: -1, fire: false, aim: 'RIGGING', targetId: sp[1].id };

  assert.notDeepEqual(rn[0].order, rn[1].order);
  assert.equal(rn[0].order.targetId, sp[0].id);
  assert.equal(rn[1].order.targetId, sp[1].id);
});
