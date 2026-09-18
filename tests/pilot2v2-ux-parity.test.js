const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

function read(name) {
  return fs.readFileSync(path.join(__dirname, '..', name), 'utf8');
}

test('prototype-parity command surface restores sail, full helm, firing and camera controls', () => {
  const html = read('pilot-2v2.html');
  for (const sail of ['NV', 'PV', 'MV', 'TV']) assert.match(html, new RegExp(`data-sail=["']${sail}["']`));
  for (const rudder of [-4,-3,-2,-1,0,1,2,3,4]) assert.match(html, new RegExp(`data-rudder=["']${rudder}["']`));
  for (const id of ['firePort','fireStarboard','cancelFire','fireSectionSelect','ammoSelect','confirmOrder','resetCamera','fitFleet','zoomIn','zoomOut','tacticalOverlay']) {
    assert.match(html, new RegExp(`id=["']${id}["']`), `missing restored control ${id}`);
  }
  assert.match(html, /Sin vela/);
  assert.match(html, /Poca vela/);
  assert.match(html, /Media vela/);
  assert.match(html, /Toda vela/);
});

test('UI code contains movement shadow, detailed hull/sails, right-drag pan and wheel zoom', () => {
  const js = read('src/pilot2v2-ui.js');
  assert.match(js, /drawMovementPreview/);
  assert.match(js, /drawHullShape/);
  assert.match(js, /drawMastsAndSails/);
  assert.match(js, /projectMovement/);
  assert.match(js, /contextmenu/);
  assert.match(js, /e\.button===2/);
  assert.match(js, /addEventListener\('wheel'/);
  assert.match(js, /drawFireArcs/);
});

test('movement preview and resolver accept the prototype full helm range', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
  const ship = state.ships.find(s => s.side === Core.SIDE_ROYAL_NAVY);
  const starboard = Core.projectMovement(state, ship, { ...ship.order, sail: 'MV', rudder: 4 });
  const port = Core.projectMovement(state, ship, { ...ship.order, sail: 'MV', rudder: -4 });
  assert.equal(starboard.rudder, 4);
  assert.equal(port.rudder, -4);
  assert.notEqual(starboard.heading, port.heading);
});

test('player can explicitly order port or starboard fire', () => {
  const state = Core.buildInitialState(data);
  const ship = state.ships.find(s => s.side === Core.SIDE_ROYAL_NAVY);
  const enemy = state.ships.find(s => s.side === Core.SIDE_REAL_ARMADA);
  ship.order = {
    ...ship.order,
    fire: true,
    fireBand: 'BABOR',
    fireSection: 'COMPLETA',
    ammo: 'ROUND_SHOT',
    targetId: enemy.id
  };
  assert.equal(ship.order.fireBand, 'BABOR');
  assert.equal(ship.order.fireSection, 'COMPLETA');
});
