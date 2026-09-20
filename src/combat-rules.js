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

  const FIRE_CONTROL_BASE_CHANCE = 0.50;
  const FIRE_CONTROL_LEVEL_PENALTY = 0.10;
  const FIRE_LEVEL3_DAMAGE = 50;
  const FIRE_LEVEL4_DAMAGE = 100;
  const FIRE_LEVEL3_EXPLOSION_CHANCE = 0.33;
  const FIRE_LEVEL4_EXPLOSION_CHANCE = 0.66;
  const FIRE_TRANSMISSION_PER_LEVEL = 0.10;

  let installed = false;

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function rngValue(rng) { return (rng || Math.random)(); }
  function activeShip(ship) { return !!ship && !ship.sunk && !ship.sinking && !ship.disabled; }

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

  function declareFire(state, ship, reason) {
    if (!ship || ship.sunk || ship.sinking) return 0;
    ship.fireLevel = Math.min(5, Math.max(0, ship.fireLevel || 0) + 1);
    ship.onFire = ship.fireLevel > 0;
    if (state && state.log) state.log.push(`¡INCENDIO! ${ship.name}${reason ? ` ${reason}` : ''}. Nivel de fuego: ${ship.fireLevel}.`);
    return ship.fireLevel;
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
      const windLabel = chance > FULL_SAIL_FIRE_RISK ? 'al disparar a toda vela con el viento entrando por la banda de disparo' : 'al disparar a toda vela';
      declareFire(state, ship, `provoca fuego ${windLabel}`);
    }
    return { checked: true, ignited, chance };
  }

  function syncRig(ship) {
    if (!ship || !ship.masts) return;
    ship.rig = Math.max(0, Object.values(ship.masts).reduce((sum, mast) => sum + Math.max(0, mast.health || 0), 0));
    ship.maxRig = Object.values(ship.masts).reduce((sum, mast) => sum + Math.max(0, mast.max || 0), 0);
  }

  function damageRandomStandingMast(ship, amount, rng, state) {
    const standing = ['fore', 'main', 'mizzen'].filter(key => ship.masts?.[key] && !ship.masts[key].fallen && ship.masts[key].health > 0);
    if (!standing.length) return { key: null, damage: 0, fallen: false };
    const index = Math.min(standing.length - 1, Math.floor(rngValue(rng) * standing.length));
    const key = standing[index];
    const mast = ship.masts[key];
    const before = mast.health;
    mast.health = Math.max(0, mast.health - amount);
    const fallen = before > 0 && mast.health === 0;
    if (fallen) mast.fallen = true;
    syncRig(ship);
    if (Core.updateSpeedEfficiency) Core.updateSpeedEfficiency(ship);
    if (state?.log) state.log.push(`${ship.name}: el incendio daña ${key === 'fore' ? 'trinquete' : key === 'main' ? 'palo mayor' : 'mesana'} -${before - mast.health}${fallen ? ' — CAE' : ''}.`);
    return { key, damage: before - mast.health, fallen };
  }

  function damageHullByFire(ship, amount, state) {
    const before = ship.hull;
    ship.hull = Math.max(0, ship.hull - Math.max(0, amount));
    if (Core.updateSpeedEfficiency) Core.updateSpeedEfficiency(ship);
    if (state?.log) state.log.push(`${ship.name}: incendio causa casco -${before - ship.hull}.`);
    return before - ship.hull;
  }

  function explodeShip(state, ship) {
    ship.hull = 0;
    ship.crew = 0;
    ship.disabled = true;
    ship.sunk = true;
    ship.sinking = false;
    ship.onFire = false;
    ship.fireLevel = 5;
    ship.motionVx = 0;
    ship.motionVy = 0;
    ship.motionSpeed = 0;
    if (state?.log) state.log.push(`¡${ship.name} EXPLOTA por el incendio y queda fuera de combate!`);
    return true;
  }

  function fireControlChance(level) {
    return clamp(FIRE_CONTROL_BASE_CHANCE - Math.max(0, level - 1) * FIRE_CONTROL_LEVEL_PENALTY, 0, 1);
  }

  function applyFireDamage(state, ship, rng) {
    const level = Math.max(0, ship.fireLevel || 0);
    if (!level || ship.sunk || ship.sinking) return { level, damage: false, exploded: false };

    if (level >= 5) {
      ship.disabled = true;
      ship.onFire = true;
      ship.motionVx = 0; ship.motionVy = 0; ship.motionSpeed = 0;
      if (state?.log) state.log.push(`${ship.name}: fuego nivel 5 — la tripulación abandona el buque; queda fuera de combate.`);
      return { level: 5, damage: true, exploded: false, abandoned: true };
    }

    let exploded = false;
    if (level === 3) {
      const standing = ['fore', 'main', 'mizzen'].some(key => ship.masts?.[key] && !ship.masts[key].fallen && ship.masts[key].health > 0);
      if (!standing || rngValue(rng) < 0.5) damageHullByFire(ship, FIRE_LEVEL3_DAMAGE, state);
      else damageRandomStandingMast(ship, FIRE_LEVEL3_DAMAGE, rng, state);
      exploded = rngValue(rng) < FIRE_LEVEL3_EXPLOSION_CHANCE;
    } else if (level === 4) {
      damageHullByFire(ship, FIRE_LEVEL4_DAMAGE, state);
      const standing = ['fore', 'main', 'mizzen'].some(key => ship.masts?.[key] && !ship.masts[key].fallen && ship.masts[key].health > 0);
      if (standing) damageRandomStandingMast(ship, FIRE_LEVEL4_DAMAGE, rng, state);
      else damageHullByFire(ship, FIRE_LEVEL4_DAMAGE, state);
      exploded = rngValue(rng) < FIRE_LEVEL4_EXPLOSION_CHANCE;
    }
    if (exploded) explodeShip(state, ship);
    return { level, damage: level >= 3, exploded };
  }

  function processExistingFire(state, ship, snapshot, rng) {
    const initialLevel = Math.max(0, snapshot?.fireLevel || 0);
    if (!initialLevel || !activeShip(ship)) return { processed: false, initialLevel, finalLevel: ship.fireLevel || 0 };

    ship.fireLevel = initialLevel;
    ship.onFire = true;
    const order = snapshot.order || {};
    const fighting = !!order.fireFighting;
    let controlSuccess = null;
    let chance = 0;

    if (fighting) {
      chance = fireControlChance(initialLevel);
      controlSuccess = rngValue(rng) < chance;
      if (controlSuccess) {
        const sailChanged = order.sail && order.sail !== snapshot.sail;
        const busy = !!order.fire || sailChanged;
        const reduction = busy ? 1 : 2;
        ship.fireLevel = Math.max(0, initialLevel - reduction);
        state.log.push(`${ship.name}: partida contra incendios tiene éxito (${Math.round(chance * 100)}%); fuego ${initialLevel}→${ship.fireLevel}.`);
      } else if (rngValue(rng) < 0.5) {
        ship.fireLevel = Math.min(5, initialLevel + 1);
        state.log.push(`${ship.name}: la partida contra incendios falla; fuego ${initialLevel}→${ship.fireLevel}.`);
      } else {
        ship.fireLevel = initialLevel;
        state.log.push(`${ship.name}: la partida contra incendios falla; el fuego permanece en nivel ${initialLevel}.`);
      }
    } else {
      ship.fireLevel = Math.min(5, initialLevel + 1);
      state.log.push(`${ship.name}: sin partida contra incendios, fuego ${initialLevel}→${ship.fireLevel}.`);
    }

    ship.onFire = ship.fireLevel > 0;
    const damage = ship.fireLevel > 0 ? applyFireDamage(state, ship, rng) : { level: 0, damage: false, exploded: false };
    if (!ship.fireLevel) ship.onFire = false;
    return { processed: true, initialLevel, finalLevel: ship.fireLevel, fighting, controlSuccess, chance, damage };
  }

  function transmitEntangledFire(state, rng, newlyIgnited) {
    const handled = new Set();
    const events = [];
    for (const ship of state.ships) {
      if (!ship.entangledWith || !ship.onFire || !ship.fireLevel || newlyIgnited.has(ship.id)) continue;
      const other = state.ships.find(s => s.id === ship.entangledWith);
      if (!other || other.sunk || other.sinking) continue;
      const key = [ship.id, other.id].sort().join('|');
      const directedKey = `${ship.id}->${other.id}`;
      if (handled.has(directedKey)) continue;
      handled.add(directedKey);
      const chance = clamp(ship.fireLevel * FIRE_TRANSMISSION_PER_LEVEL, 0, 1);
      if (rngValue(rng) < chance) {
        declareFire(state, other, `recibe fuego transmitido desde ${ship.name}`);
        events.push({ from: ship.id, to: other.id, chance, ignited: true, pair: key });
      } else events.push({ from: ship.id, to: other.id, chance, ignited: false, pair: key });
    }
    return events;
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
      const rng = options.rng;
      const windFromDeg = state.windFromDeg;
      const snapshots = state.ships.map(ship => ({
        id: ship.id,
        name: ship.name,
        sail: ship.sail,
        heading: ship.heading,
        fireLevel: ship.fireLevel || 0,
        windFromDeg,
        order: ship.order ? { ...ship.order } : null
      }));
      const logStart = state.log.length;
      const result = baseResolveTurn.call(Core, state, options);
      const newLogs = state.log.slice(logStart);

      // Existing fires evolve first. A newly ignited full-sail fire starts at level 1 and
      // is not immediately escalated in the same turn.
      for (const snap of snapshots) {
        const ship = state.ships.find(s => s.id === snap.id);
        if (ship) processExistingFire(state, ship, snap, rng);
      }

      const newlyIgnited = new Set();
      for (const snap of snapshots) {
        const outcome = applyFullSailIgnition(state, snap, newLogs, rng);
        if (outcome.ignited) newlyIgnited.add(snap.id);
      }

      transmitEntangledFire(state, rng, newlyIgnited);

      for (const ship of state.ships) {
        if (ship.order) {
          ship.order.cutMast = false;
          ship.order.fireFighting = false;
        }
        if (ship.entangledWith) ship.forceTurnOnly = true;
      }
      if (Core.evaluateResult) Core.evaluateResult(state);
      return result;
    };

    Core.fullSailFireRisk = fullSailFireRisk;
    Core.windEnteringBand = windEnteringBand;
    Core.declareFire = declareFire;
    Core.fireControlChance = fireControlChance;
    Core.combatRules = api;
    Core.__combatRulesInstalled = true;
    installed = true;
    return true;
  }

  const api = {
    FULL_SAIL_FIRE_RISK,
    FULL_SAIL_WINDWARD_BATTERY_FIRE_RISK,
    FIRE_CONTROL_BASE_CHANCE,
    FIRE_CONTROL_LEVEL_PENALTY,
    FIRE_LEVEL3_DAMAGE,
    FIRE_LEVEL4_DAMAGE,
    FIRE_LEVEL3_EXPLOSION_CHANCE,
    FIRE_LEVEL4_EXPLOSION_CHANCE,
    FIRE_TRANSMISSION_PER_LEVEL,
    windEnteringBand,
    fullSailFireRisk,
    initializeShipCombatState,
    resetCombatState,
    shotLogged,
    declareFire,
    applyFullSailIgnition,
    fireControlChance,
    damageRandomStandingMast,
    damageHullByFire,
    explodeShip,
    applyFireDamage,
    processExistingFire,
    transmitEntangledFire,
    install
  };

  return api;
});