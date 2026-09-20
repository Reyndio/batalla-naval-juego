(function (root, factory) {
  const Core = root && root.Pilot2v2Core
    ? root.Pilot2v2Core
    : (typeof require !== 'undefined' ? require('./pilot2v2-core.js') : null);
  const api = factory(root, Core);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.PrototypeRudderRuntime = api;
  if (root && root.document && Core) api.install();
})(typeof window !== 'undefined' ? window : globalThis, function (root, Core) {
  'use strict';

  if (!Core) throw new Error('PrototypeRudderRuntime requires Pilot2v2Core.');

  // Exact steering surface recovered from archive/prototype-v1.
  const MAX_RUDDER = 4;
  const BASE_TURN_DEG = { 1: 10, 2: 20, 3: 30, 4: 45 };
  const SAIL_TURN_FACTOR = { NV: 1, PV: 1, MV: 0.7, TV: 0.4 };
  const CHANGE_LIMIT = { NV: 4, PV: 4, MV: 3, TV: 2 };
  const AMPLITUDE_LIMIT = { NV: 4, PV: 4, MV: 4, TV: 3 };
  const SPECIAL_ACTION_FATIGUE = 10;

  let installed = false;
  let legacyResolveShot;
  let legacyRepairHullZeroToOne;
  let legacyCheckHullZeroSinking;
  let legacyEvaluateResult;
  let legacyMaybeChangeWind;

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function signedAngleDiff(target, current) {
    let d = normalizeAngle(target - current);
    if (d > 180) d -= 360;
    return d;
  }
  function activeShip(ship) { return !!ship && !ship.sunk && !ship.sinking && !ship.disabled; }
  function sailForValidation(ship, explicitSail) {
    const candidate = explicitSail || ship?.order?.sail || ship?.sail || 'MV';
    return Core.SAIL_ORDER.includes(candidate) ? candidate : (ship?.sail || 'MV');
  }

  function validateRudderOrder(ship, newRudder, explicitSail) {
    const raw = Number(newRudder);
    if (!Number.isFinite(raw) || !Number.isInteger(raw)) return { valid: false, reason: 'La orden de timón debe ser un punto entero entre -4 y +4.' };
    if (raw < -MAX_RUDDER || raw > MAX_RUDDER) return { valid: false, reason: 'El timón admite posiciones entre -4 y +4.' };
    const sail = sailForValidation(ship, explicitSail);
    const amplitude = Math.abs(raw);
    const current = Number(ship?.rudder) || 0;
    const change = Math.abs(raw - current);

    if (ship?.rudderDamaged && amplitude > 1) return { valid: false, reason: 'Timón dañado: sólo se puede usar ±1.' };
    if (amplitude > AMPLITUDE_LIMIT[sail]) {
      if (sail === 'TV' && amplitude === 4) return { valid: false, reason: 'A Toda Vela no se puede usar el timón en los extremos -4/+4.' };
      return { valid: false, reason: `Amplitud de timón ${raw} excede ${AMPLITUDE_LIMIT[sail]} puntos con ${sail}.` };
    }
    if (change > CHANGE_LIMIT[sail]) {
      return { valid: false, reason: `El cambio de timón de ${change} puntos excede el máximo de ${CHANGE_LIMIT[sail]} con ${sail}.` };
    }
    return { valid: true, value: raw, sail, change, changeLimit: CHANGE_LIMIT[sail], amplitudeLimit: AMPLITUDE_LIMIT[sail] };
  }

  function resolveRudderOrder(ship, requestedRudder, rng, preview, explicitSail) {
    const check = validateRudderOrder(ship, requestedRudder, explicitSail);
    if (!check.valid) return { value: Number(ship?.rudder) || 0, requested: Number(requestedRudder) || 0, valid: false, reason: check.reason, chance: 0, rolled: false };
    return { value: check.value, requested: check.value, valid: true, chance: 1, rolled: false };
  }

  function rudderTurnDegrees(sail, rudder) {
    const points = Math.abs(Number(rudder) || 0);
    if (!points) return 0;
    const base = BASE_TURN_DEG[points] || 0;
    return base * (SAIL_TURN_FACTOR[sail] == null ? 1 : SAIL_TURN_FACTOR[sail]) * Math.sign(rudder);
  }

  function crossesHeading(start, target, signedTurn) {
    if (!signedTurn) return false;
    const sign = Math.sign(signedTurn);
    const span = Math.abs(signedTurn);
    if (sign > 0) return normalizeAngle(target - start) <= span + 1e-9;
    return normalizeAngle(start - target) <= span + 1e-9;
  }

  function turnWithTacking(state, ship, rudder, sail) {
    let effectiveRudder = Number(rudder) || 0;
    const wind = normalizeAngle(state.windFromDeg);
    const leavingWind = !!ship.tackingAgainstWind || Math.abs(signedAngleDiff(wind, ship.heading)) < 1e-9;
    if (leavingWind && Math.abs(effectiveRudder) > 1) effectiveRudder = Math.sign(effectiveRudder);
    const requestedTurn = rudderTurnDegrees(sail, effectiveRudder);
    if (!requestedTurn) return { heading: ship.heading, usedPoints: 0, hitWind: false, leavingWind, turnDegrees: 0, effectiveRudder };
    if (!leavingWind && crossesHeading(ship.heading, wind, requestedTurn) && Math.abs(signedAngleDiff(wind, ship.heading)) > 1e-9) {
      const actual = signedAngleDiff(wind, ship.heading);
      return { heading: wind, usedPoints: Math.abs(effectiveRudder), hitWind: true, leavingWind, turnDegrees: actual, effectiveRudder };
    }
    return {
      heading: normalizeAngle(ship.heading + requestedTurn),
      usedPoints: Math.abs(effectiveRudder),
      hitWind: false,
      leavingWind,
      turnDegrees: requestedTurn,
      effectiveRudder
    };
  }

  function windSpeedModifier(ship, windFromDeg, windStrength) {
    const toward = normalizeAngle(windFromDeg + 180);
    const rel = Math.abs(signedAngleDiff(toward, ship.heading));
    if (windStrength === 'CALMA') return rel <= 45 ? 0.75 : rel >= 135 ? 0.45 : 0.60;
    if (windStrength === 'FUERTE') return rel <= 45 ? 1.35 : rel <= 110 ? 1.15 : rel <= 135 ? 0.80 : 0.35;
    return rel <= 45 ? 1.20 : rel >= 135 ? 0.50 : 1.00;
  }

  function projectMovement(state, ship, order) {
    if (!activeShip(ship)) return { x: ship.x, y: ship.y, heading: ship.heading, sail: ship.sail, rudder: ship.rudder, valid: true };
    order = order || ship.order || {};
    const sail = Core.SAIL_ORDER.includes(order.sail) ? order.sail : ship.sail;
    const rr = resolveRudderOrder(ship, order.rudder == null ? ship.rudder : order.rudder, null, false, sail);
    if (!rr.valid) return { x: ship.x, y: ship.y, heading: ship.heading, sail, rudder: ship.rudder, valid: false, reason: rr.reason, rudderResolution: rr };
    const turn = turnWithTacking(state, ship, rr.value, sail);
    const averageHeading = normalizeAngle(ship.heading + turn.turnDegrees / 2);
    const baseDistance = ship.forceTurnOnly || ship.collidedThisTurn || ship.entangledWith ? 0 : (Core.SAIL_SPEED[sail] || 0);
    const speed = baseDistance * windSpeedModifier(ship, state.windFromDeg, state.windStrength) * ship.speedEfficiency;
    const rad = averageHeading * Math.PI / 180;
    return {
      x: clamp(ship.x + speed * Math.sin(rad), 20, Core.WORLD.width - 20),
      y: clamp(ship.y - speed * Math.cos(rad), 20, Core.WORLD.height - 20),
      heading: turn.heading,
      sail,
      rudder: turn.effectiveRudder,
      valid: true,
      reason: null,
      rudderResolution: rr,
      turnDegrees: turn.turnDegrees,
      tackingAgainstWind: turn.hitWind || (turn.usedPoints === 0 && ship.tackingAgainstWind)
    };
  }

  function defaultOrder(ship, enemyId) {
    return {
      sail: ship.sail || 'MV', rudder: ship.rudder || 0, fire: false, fireBand: 'AUTO',
      fireSection: 'AUTO', ammo: ship.nextAmmo || 'ROUND_SHOT', aim: 'HULL', targetId: enemyId || null,
      repairHull: false, reloadDoubleShot: false, fireFighting: false, cutMast: false
    };
  }

  function chooseRudderTowardHeading(ship, desiredHeading, sail) {
    const err = signedAngleDiff(desiredHeading, ship.heading);
    if (Math.abs(err) <= 5) return 0;
    const sign = Math.sign(err);
    const target = Math.abs(err);
    const candidates = [4, 3, 2, 1];
    let fallback = 0;
    for (const points of candidates) {
      const candidate = sign * points;
      const check = validateRudderOrder(ship, candidate, sail);
      if (!check.valid) continue;
      if (!fallback) fallback = candidate;
      if (Math.abs(rudderTurnDegrees(sail, candidate)) <= target + 3) return candidate;
    }
    return fallback;
  }

  function planAIOrder(state, ship) {
    if (!activeShip(ship)) return defaultOrder(ship, null);
    const target = Core.nearestEnemy(state, ship);
    if (!target) return defaultOrder(ship, null);
    const d = Core.distance(ship, target);
    const bearing = Core.angleTo(ship, target);
    const arc = Core.broadsideArcFactor(ship, target);
    let desiredHeading = bearing;
    if (d <= 300) {
      const starboardBroadside = normalizeAngle(bearing - 90);
      const portBroadside = normalizeAngle(bearing + 90);
      desiredHeading = Math.abs(signedAngleDiff(starboardBroadside, ship.heading)) <= Math.abs(signedAngleDiff(portBroadside, ship.heading)) ? starboardBroadside : portBroadside;
    }
    let sail = d > 330 ? 'TV' : d < 120 ? 'PV' : 'MV';
    if (ship.entangledWith) sail = 'NV';
    let rudder = arc.factor > 0 && d <= 300 ? 0 : chooseRudderTowardHeading(ship, desiredHeading, sail);
    if (ship.x < 55 || ship.x > Core.WORLD.width - 55 || ship.y < 55 || ship.y > Core.WORLD.height - 55) {
      const centerBearing = Core.angleTo(ship, { x: Core.WORLD.width / 2, y: Core.WORLD.height / 2 });
      sail = 'MV';
      rudder = chooseRudderTowardHeading(ship, centerBearing, sail);
    }
    const fireArc = Core.broadsideArcFactor(ship, target);
    const fire = d < Core.MAX_FIRE_RANGE && fireArc.factor > 0 && Core.canShipFire(ship);
    const aim = target.rig > target.maxRig * 0.55 ? 'HULL' : 'RIGGING';
    return {
      sail, rudder, fire, fireBand: fireArc.band || 'AUTO', fireSection: 'AUTO',
      ammo: aim === 'RIGGING' ? 'DOUBLE_SHOT' : 'ROUND_SHOT', aim, targetId: target.id,
      repairHull: ship.hull === 0 && ship.fatigue <= 100,
      cutMast: !!ship.entangledWith
    };
  }

  function fireFatigue(ship) {
    return ship.order && ship.order.fire && Core.canShipFire(ship) ? Core.broadsideFatigueCost(ship.order.fireBoth ? 2 : 1) : 0;
  }
  function specialActionFatigue(ship) {
    const order = ship.order || {};
    let cost = 0;
    if (order.reloadDoubleShot) cost += SPECIAL_ACTION_FATIGUE;
    if (order.fireFighting) cost += SPECIAL_ACTION_FATIGUE;
    if (order.cutMast) cost += SPECIAL_ACTION_FATIGUE;
    return cost;
  }
  function applyFatigueEndTurn(ship, generated) {
    if (generated > 0) ship.fatigue = Math.max(0, ship.fatigue + generated);
    else Core.recoverFatigue(ship);
  }

  function resolveTurn(state, options) {
    options = options || {};
    const rng = options.rng || Math.random;
    const autoSides = options.autoSides || [Core.SIDE_REAL_ARMADA];
    if (state.result) return state;
    if (!state.gameStarted) state.gameStarted = true;
    state.log.push(`--- TURNO ${state.turn} ---`);

    for (const ship of state.ships) {
      if (!activeShip(ship)) continue;
      if (autoSides.includes(ship.side)) ship.order = planAIOrder(state, ship);
      if (!ship.order) ship.order = defaultOrder(ship, Core.nearestEnemy(state, ship)?.id || null);
      ship.nextAmmo = ship.order.ammo || ship.nextAmmo;
      ship.collidedThisTurn = false;
      ship.hullRepairUsedThisTurn = false;
      if (ship.entangledWith) ship.forceTurnOnly = true;
    }

    const fatigueGenerated = new Map();
    for (const ship of state.ships) {
      if (!activeShip(ship)) continue;
      if (ship.order && ship.order.repairHull) legacyRepairHullZeroToOne(ship, state);
    }

    const projections = new Map();
    for (const ship of state.ships) {
      if (!activeShip(ship)) continue;
      const p = projectMovement(state, ship, ship.order);
      projections.set(ship.id, p);
      const movement = Core.sailChangeFatigueCost(ship.sail, p.sail);
      fatigueGenerated.set(ship.id, movement + fireFatigue(ship) + specialActionFatigue(ship));
    }

    for (const ship of state.ships) {
      const p = projections.get(ship.id);
      if (!p) continue;
      ship.previousSail = ship.sail;
      ship.previousRudder = ship.rudder;
      ship.x = p.x; ship.y = p.y; ship.heading = p.heading;
      ship.effectiveSail = p.sail; ship.sail = p.sail; ship.rudder = p.rudder;
      ship.tackingAgainstWind = !!p.tackingAgainstWind;
    }

    const shooters = state.ships.filter(activeShip).map(s => s.id);
    for (const id of shooters) {
      const attacker = state.ships.find(s => s.id === id);
      if (activeShip(attacker)) legacyResolveShot(state, attacker, rng);
    }

    for (const ship of state.ships) {
      if (!ship) continue;
      const generated = fatigueGenerated.get(ship.id) || 0;
      if (!ship.hullRepairUsedThisTurn) applyFatigueEndTurn(ship, generated);
      else if (generated > 0) ship.fatigue += generated;
      ship.loadedAmmo = ship.nextAmmo;
      ship.confirmed = false;
      ship.forceTurnOnly = !!ship.entangledWith;
      Core.updateSpeedEfficiency(ship);
    }

    for (const ship of state.ships) if (activeShip(ship)) legacyCheckHullZeroSinking(ship, rng, state);
    legacyEvaluateResult(state);
    if (!state.result) legacyMaybeChangeWind(state, rng);
    state.turn += 1;
    if (!state.result) {
      state.log.push(`--- INICIO TURNO ${state.turn} ---`);
      for (const ship of state.ships) if (activeShip(ship) && autoSides.includes(ship.side)) ship.order = planAIOrder(state, ship);
    }
    return state;
  }

  function autoOrderSide(state, side) {
    for (const ship of state.ships) if (ship.side === side && activeShip(ship)) ship.order = planAIOrder(state, ship);
    return state;
  }

  function restoreRudderUi() {
    if (!root || !root.document) return;
    const doc = root.document;
    const buttons = doc.querySelectorAll('#rudderButtons [data-rudder]');
    buttons.forEach(btn => {
      btn.style.display = '';
      const v = Number(btn.dataset.rudder);
      btn.textContent = v === -4 ? 'T◀' : v === 4 ? 'T▶' : v > 0 ? `+${v}` : v === 0 ? '●' : String(v);
    });
    const row = doc.getElementById('rudderButtons');
    if (row && row.previousElementSibling) row.previousElementSibling.textContent = 'Timón — T◀ / T▶ = máximo · a TV no se admiten ±4';
  }

  function install() {
    if (installed || Core.__prototypeRudderRuntimeInstalled) return false;
    legacyResolveShot = Core.resolveShot;
    legacyRepairHullZeroToOne = Core.repairHullZeroToOne;
    legacyCheckHullZeroSinking = Core.checkHullZeroSinking;
    legacyEvaluateResult = Core.evaluateResult;
    legacyMaybeChangeWind = Core.maybeChangeWind;

    Core.MAX_RUDDER = MAX_RUDDER;
    Core.validateRudderOrder = validateRudderOrder;
    Core.resolveRudderOrder = resolveRudderOrder;
    Core.turnWithTacking = turnWithTacking;
    Core.projectMovement = projectMovement;
    Core.planAIOrder = planAIOrder;
    Core.autoOrderSide = autoOrderSide;
    Core.resolveTurn = resolveTurn;
    Core.prototypeRudderRuntime = api;
    Core.__prototypeRudderRuntimeInstalled = true;
    installed = true;

    if (root && root.document) {
      setTimeout(restoreRudderUi, 20);
      setInterval(restoreRudderUi, 500);
    }
    return true;
  }

  const api = {
    MAX_RUDDER,
    BASE_TURN_DEG,
    SAIL_TURN_FACTOR,
    CHANGE_LIMIT,
    AMPLITUDE_LIMIT,
    validateRudderOrder,
    resolveRudderOrder,
    rudderTurnDegrees,
    turnWithTacking,
    windSpeedModifier,
    projectMovement,
    chooseRudderTowardHeading,
    planAIOrder,
    resolveTurn,
    restoreRudderUi,
    install
  };

  return api;
});