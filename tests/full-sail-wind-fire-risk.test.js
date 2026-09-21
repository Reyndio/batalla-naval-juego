const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const Core = require('../src/pilot2v2-core.js');
const Combat = require('../src/combat-rules.js');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'historical_ships_1805.json'), 'utf8'));

test('full-sail fire risk uses 10/15/20 percent bands from wind angle on either firing side', () => {
  assert.equal(Combat.FULL_SAIL_FIRE_RISK, 0.10);
  assert.equal(Combat.FULL_SAIL_OBLIQUE_WIND_FIRE_RISK, 0.15);
  assert.equal(Combat.FULL_SAIL_DIRECT_WIND_FIRE_RISK, 0.20);
  assert.equal(Combat.FULL_SAIL_DIRECT_WIND_TOLERANCE_DEG, 15);
  assert.equal(Combat.FULL_SAIL_SIDE_WIND_TOLERANCE_DEG, 45);

  // Heading north. Starboard firing normal is 90°, port is 270°.
  assert.equal(Combat.fullSailFireRisk(0, 0, 'ESTRIBOR'), 0.10);
  assert.equal(Combat.fullSailFireRisk(0, 44.999, 'ESTRIBOR'), 0.10);
  assert.equal(Combat.fullSailFireRisk(0, 45, 'ESTRIBOR'), 0.15);
  assert.equal(Combat.fullSailFireRisk(0, 74.999, 'ESTRIBOR'), 0.15);
  assert.equal(Combat.fullSailFireRisk(0, 75, 'ESTRIBOR'), 0.20);
  assert.equal(Combat.fullSailFireRisk(0, 90, 'ESTRIBOR'), 0.20);
  assert.equal(Combat.fullSailFireRisk(0, 105, 'ESTRIBOR'), 0.20);
  assert.equal(Combat.fullSailFireRisk(0, 105.001, 'ESTRIBOR'), 0.15);
  assert.equal(Combat.fullSailFireRisk(0, 135, 'ESTRIBOR'), 0.15);
  assert.equal(Combat.fullSailFireRisk(0, 135.001, 'ESTRIBOR'), 0.10);

  assert.equal(Combat.fullSailFireRisk(0, 270, 'BABOR'), 0.20);
  assert.equal(Combat.fullSailFireRisk(0, 240, 'BABOR'), 0.15);
  assert.equal(Combat.fullSailFireRisk(0, 180, 'BABOR'), 0.10);
});

test('wind exposure reports direct oblique or none using the same tolerances', () => {
  assert.equal(Combat.fullSailWindExposure(30, 120, 'ESTRIBOR').type, 'DIRECT');
  assert.equal(Combat.fullSailWindExposure(30, 150, 'ESTRIBOR').type, 'OBLIQUE');
  assert.equal(Combat.fullSailWindExposure(30, 180, 'ESTRIBOR').type, 'NONE');
  assert.equal(Combat.fullSailWindExposure(30, 300, 'BABOR').type, 'DIRECT');
});

test('actual full-sail ignition uses the direct-wind 20 percent risk', () => {
  const state = Core.buildInitialState(data, { windFromDeg: 90 });
  const ship = state.ships[0];
  Combat.initializeShipCombatState(ship);
  const snapshot = {
    id: ship.id,
    name: ship.name,
    sail: 'TV',
    heading: 0,
    windFromDeg: 90,
    order: { fire: true, fireBand: 'ESTRIBOR' }
  };
  const outcome = Combat.applyFullSailIgnition(
    state,
    snapshot,
    [`${ship.name} dispara ESTRIBOR (COMPLETA)`],
    () => 0.199999
  );
  assert.equal(outcome.checked, true);
  assert.equal(outcome.exposure, 'DIRECT');
  assert.equal(outcome.chance, 0.20);
  assert.equal(outcome.ignited, true);
  assert.equal(ship.fireLevel, 1);
});
