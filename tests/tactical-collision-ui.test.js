const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const Guard = require('../src/collision-guard.js');
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

test('collision consequences visibly affect hull, crew and fatigue', () => {
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
  assert.match(state.log.at(-1), /Colisión durante el movimiento/);
});

test('playable page wires swept collision guard and tactical player-facing overlays', () => {
  const html = read('pilot-2v2.html');
  const css = read('pilot-2v2.css');
  const polish = read('src/player-ui-polish.js');
  assert.match(html, /src\/collision-guard\.js/);
  assert.match(html, /src\/player-ui-polish\.js/);
  assert.doesNotMatch(html, /Las reglas Velmad verificadas/);
  assert.match(css, /\.fire-row button\.fire-active/);
  assert.match(css, /\.tactical-ring/);
  assert.match(css, /\.threat-ring/);
  assert.match(css, /\.battery-side-highlight/);
  assert.match(polish, /targetShipHighlight/);
  assert.match(polish, /threatShipHighlight/);
  assert.match(polish, /selectedBatteryHighlight/);
  assert.match(polish, /Timón Velmad/);
  assert.match(polish, /Artillería Velmad/);
});
