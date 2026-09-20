(function (root, factory) {
  const Core = root && root.Pilot2v2Core
    ? root.Pilot2v2Core
    : (typeof require !== 'undefined' ? require('./pilot2v2-core.js') : null);
  const api = factory(Core);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.CombatRules = api;
  if (root && root.document && Core) api.install();
})(typeof window !== 'undefined' ? window : globalThis, function (Core) {
  'use strict';

  if (!Core) throw new Error('CombatRules requires Pilot2v2Core.');

  // Source rule: firing at full sail retains a 20% fire risk.
  const FULL_SAIL_FIRE_RISK = 0.20;
  // Owner-approved project rule: if the wind enters through the firing side, risk rises.
  // 30% is the current explicit project calibration (1.5x the source baseline).
  const FULL_SAIL_WINDWARD_BATTERY_FIRE_RISK = 0.30;

  let installed = false;

  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function rngValue(rng) { return (rng || Math.random)(); }

  function windEnteringBand(heading, windFromDeg) {
    const relative = normalizeAngle(windFromDeg - heading);
    if (relative >= 45 && relative <= 135) return 'ESTRIBOR';
    if (relative >= 225 && relative <= 315) return 'BABOR';
    return null;
  }

  function fullSailFireRisk(heading, windFromDeg, firingBand) {
    return windEnteringBand(heading, windFromDeg) === firingBand
      ? FULL_SAIL_WINDWARD_BATTERY_FIRE_RISK
      : FULL_SAIL_FIRE_RISK;
  }

  function initializeShipCombatState(ship) {
    ship.fireLevel = 0;
    ship.onFire = false;
    ship.entangledWith = null;
    ship.entangledByMastOf = null;
    ship.entangledMastKey = null;
    ship.draggingMast = false;
    ship.fallenMastTowardShipId = null;
    ship.cutAwayMastKey = null;
    ship.collisionMomentumRetention = null;
    return ship;
  }

  function resetCombatState(state) {
    if (!state || !Array.isArray(state.ships)) return state;
    for (const ship of state.ships) initializeShipCombatState(ship);
    return state;
  }

  function shotLogged(lines, shipName, band) {
    const token = `${shipName} dispara ${band}`;
    return lines.some(line => typeof line === 'string' && line.includes(token));
  }

  function applyFullSailIgnition(state, snapshot, newLogs, rng) {
    if (!snapshot || snapshot.sail !== 'TV' || !snapshot.order || !snapshot.order.fire) return { checked: false, ignited: false, chance: 0 };
    const band = snapshot.order.fireBand;
    if (band !== 'BABOR' && band !== 'ESTRIBOR') return { checked: false, ignited: false, chance: 0 };
    if (!shotLogged(newLogs, snapshot.name, band)) return { checked: false, ignited: false, chance: 0 };
    const ship = state.ships.find(s => s.id === snapshot.id);
    if (!ship || ship.sunk || ship.sinking) return { checked: false, ignited: false, chance: 0 };

    const chance = fullSailFireRisk(snapshot.heading, snapshot.windFromDeg, band);
    const ignited = rngValue(rng) < chance;
    if (ignited) {
      ship.fireLevel = Math.min(5, Math.max(0, ship.fireLevel || 0) + 1);
      ship.onFire = ship.fireLevel > 0;
      const windLabel = chance > FULL_SAIL_FIRE_RISK ? ' con el viento entrando por la banda de disparo' : '';
      state.log.push(`¡INCENDIO! ${ship.name} provoca fuego al disparar a toda vela${windLabel}. Nivel de fuego: ${ship.fireLevel}.`);
    }
    return { checked: true, ignited, chance };
  }

  function install() {
    if (installed || Core.__combatRulesInstalled) return false;
    const baseBuildInitialState = Core.buildInitialState;
    const baseStartBattle = Core.startBattle;
    const baseResolveTurn = Core.resolveTurn;

    Core.buildInitialState = function (...args) {
      return resetCombatState(baseBuildInitialState.apply(Core, args));
    };

    Core.startBattle = function (state, ...args) {
      const result = baseStartBattle.call(Core, state, ...args);
      return resetCombatState(result);
    };

    Core.resolveTurn = function (state, options) {
      options = options || {};
      const windFromDeg = state.windFromDeg;
      const snapshots = state.ships.map(ship => ({
        id: ship.id,
        name: ship.name,
        sail: ship.sail,
        heading: ship.heading,
        windFromDeg,
        order: ship.order ? { ...ship.order } : null
      }));
      const logStart = state.log.length;
      const result = baseResolveTurn.call(Core, state, options);
      const newLogs = state.log.slice(logStart);
      for (const snap of snapshots) applyFullSailIgnition(state, snap, newLogs, options.rng);
      for (const ship of state.ships) {
        if (ship.order) ship.order.cutMast = false;
        if (ship.entangledWith) ship.forceTurnOnly = true;
      }
      return result;
    };

    Core.fullSailFireRisk = fullSailFireRisk;
    Core.windEnteringBand = windEnteringBand;
    Core.combatRules = api;
    Core.__combatRulesInstalled = true;
    installed = true;
    return true;
  }

  const api = {
    FULL_SAIL_FIRE_RISK,
    FULL_SAIL_WINDWARD_BATTERY_FIRE_RISK,
    windEnteringBand,
    fullSailFireRisk,
    initializeShipCombatState,
    resetCombatState,
    shotLogged,
    applyFullSailIgnition,
    install
  };

  return api;
});