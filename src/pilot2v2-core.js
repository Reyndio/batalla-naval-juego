(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.Pilot2v2Core = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';

  const SIDE_ROYAL_NAVY = 'royal-navy';
  const SIDE_REAL_ARMADA = 'real-armada';
  const WORLD = { width: 1000, height: 700 };
  const MAX_FIRE_RANGE = 400;
  const BASE_HULL = 1200;
  const BASE_RIG = 1200;
  const MAX_RUDDER = 4;

  const SAIL_SPEED = { NV: 0, PV: 20, MV: 40, TV: 60 };
  const SAIL_ORDER = ['NV', 'PV', 'MV', 'TV'];
  const RUDDER_DEG_PV = { 0: 0, 1: 10, 2: 20, 3: 30, 4: 45 };
  const RUDDER_EFFECT = { NV: 1, PV: 1, MV: 0.7, TV: 0.4 };
  const RUDDER_CHANGE_LIMIT = { NV: 4, PV: 4, MV: 3, TV: 2 };
  const RUDDER_AMPLITUDE_LIMIT = { NV: 4, PV: 4, MV: 4, TV: 3 };

  const FATIGUE_ACTION = 10;
  const FATIGUE_NV_PV = 20;
  const FATIGUE_RECOVERY = 20;
  const FATIGUE_THRESHOLD = { NOVATA: 35, NORMAL: 50, VETERANA: 85 };

  const MAST_WEIGHTS = { fore: 0.30, main: 0.45, mizzen: 0.25 };
  const SPEED_MAST_PENALTY = { fore: 0.30, main: 0.50, mizzen: 0.20 };

  const RAKE_ARC_DEGREES = 15;
  const STERN_RAKE_MULTIPLIER = 3;
  const BOW_RAKE_MULTIPLIER = 2.5;
  const RUDDER_DAMAGE_CHANCE_RAKE = 0.20;
  const MAST_DAMAGE_CHANCE_RAKE = 0.35;
  const MAST_DAMAGE_BONUS_PERCENT_RAKE = 0.25;

  const BASE_COLLISION_DAMAGE = 30;
  const RIGGING_DAMAGE_COLLISION_FACTOR = 0.20;
  const BASE_RUDDER_DAMAGE_CHANCE_STERN_COLLISION = 0.25;
  const RUDDER_DAMAGE_BONUS_PER_SAIL_DIFFERENCE = 0.25;
  const MAX_RUDDER_DAMAGE_CHANCE_STERN_COLLISION = 0.75;

  const CASUALTY_GRAPE_FACTOR = 0.20;
  const CASUALTY_ROUND_HULL_FACTOR = 0.18;
  const CASUALTY_MAST_FALL_PERCENT = 0.05;
  const CASUALTY_COLLISION_FACTOR = 0.08;
  const CASUALTY_BOW_RAKE_MULTIPLIER = 1.5;
  const CASUALTY_STERN_RAKE_MULTIPLIER = 2.0;
  const CASUALTY_HULL_DESTROYED_PERCENT = 0.25;

  function clone(v) { return JSON.parse(JSON.stringify(v)); }
  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function angleDiff(a, b) {
    let d = normalizeAngle(a - b);
    if (d > 180) d -= 360;
    return d;
  }
  function distance(a, b) { return Math.hypot(b.x - a.x, b.y - a.y); }
  function angleTo(a, b) {
    return normalizeAngle(Math.atan2(b.x - a.x, -(b.y - a.y)) * 180 / Math.PI);
  }
  function relativeBearing(attacker, target) {
    return normalizeAngle(angleTo(attacker, target) - attacker.heading);
  }
  function seededRng(seed) {
    let s = (seed >>> 0) || 1;
    return function () {
      s = (1664525 * s + 1013904223) >>> 0;
      return s / 4294967296;
    };
  }
  function rngValue(rng) { return (rng || Math.random)(); }

  function defaultOrder(ship, enemyId) {
    return {
      sail: ship.sail || 'MV',
      rudder: ship.rudder || 0,
      fire: false,
      fireBand: 'AUTO',
      fireSection: 'AUTO',
      ammo: ship.nextAmmo || 'ROUND_SHOT',
      aim: 'HULL',
      targetId: enemyId || null
    };
  }

  function syncRig(ship) {
    ship.rig = Math.max(0, ship.masts.fore.health + ship.masts.main.health + ship.masts.mizzen.health);
    ship.maxRig = ship.masts.fore.max + ship.masts.main.max + ship.masts.mizzen.max;
  }

  function newShipState(historical, slot, experience) {
    const foreMax = Math.round(BASE_RIG * MAST_WEIGHTS.fore);
    const mainMax = Math.round(BASE_RIG * MAST_WEIGHTS.main);
    const mizzenMax = BASE_RIG - foreMax - mainMax;
    const guns = historical.armament.gunsPerBroadside;
    const crew = historical.crew.actionComplement;
    return {
      id: historical.id,
      name: historical.name,
      side: historical.side,
      navy: historical.navy,
      nation: historical.nation,
      historical: clone(historical),
      x: slot.x,
      y: slot.y,
      heading: slot.heading,
      startX: slot.x,
      startY: slot.y,
      startHeading: slot.heading,
      sail: 'MV',
      previousSail: 'MV',
      effectiveSail: 'MV',
      rudder: 0,
      previousRudder: 0,
      hull: BASE_HULL,
      maxHull: BASE_HULL,
      rig: BASE_RIG,
      maxRig: BASE_RIG,
      masts: {
        fore: { health: foreMax, max: foreMax, fallen: false },
        main: { health: mainMax, max: mainMax, fallen: false },
        mizzen: { health: mizzenMax, max: mizzenMax, fallen: false }
      },
      crew,
      initialCrew: crew,
      fatigue: 0,
      crewExperience: experience || 'NORMAL',
      gunsPerSide: guns,
      portGuns: guns,
      starboardGuns: guns,
      rudderDamaged: false,
      speedEfficiency: 1,
      loadedAmmo: 'ROUND_SHOT',
      nextAmmo: 'ROUND_SHOT',
      sunk: false,
      disabled: false,
      confirmed: false,
      collidedThisTurn: false,
      forceTurnOnly: false,
      lastTargetId: null,
      order: null
    };
  }

  function buildInitialState(data, options) {
    options = options || {};
    if (!data || !Array.isArray(data.ships) || data.ships.length !== 4) {
      throw new Error('The 2v2 pilot requires exactly four historical ship records.');
    }
    const slots = {
      [SIDE_ROYAL_NAVY]: [{ x: 220, y: 260, heading: 90 }, { x: 220, y: 440, heading: 90 }],
      [SIDE_REAL_ARMADA]: [{ x: 780, y: 260, heading: 270 }, { x: 780, y: 440, heading: 270 }]
    };
    const counters = { [SIDE_ROYAL_NAVY]: 0, [SIDE_REAL_ARMADA]: 0 };
    const expBySide = options.crewExperienceBySide || {};
    const ships = data.ships.map(h => {
      if (!slots[h.side]) throw new Error('Unsupported side: ' + h.side);
      const slot = slots[h.side][counters[h.side]++];
      if (!slot) throw new Error('Each side must contain exactly two ships.');
      return newShipState(h, slot, expBySide[h.side] || 'NORMAL');
    });
    for (const ship of ships) {
      const enemy = ships.find(s => s.side !== ship.side);
      ship.order = defaultOrder(ship, enemy && enemy.id);
    }
    return {
      scenario: clone(data.scenario || {}),
      turn: 1,
      gameStarted: options.gameStarted !== false,
      paused: false,
      turnDurationSeconds: Number(options.turnDurationSeconds) || 60,
      windFromDeg: options.windFromDeg == null ? 0 : normalizeAngle(options.windFromDeg),
      windStrength: options.windStrength || 'MEDIA',
      windHasChanged: false,
      ships,
      log: ['Piloto 2v2 listo. Mecánicas heredadas del prototipo estable; datos de buque históricos y trazables.'],
      result: null
    };
  }

  function startBattle(state, options) {
    options = options || {};
    state.gameStarted = true;
    state.paused = false;
    state.turn = 1;
    state.result = null;
    state.windHasChanged = false;
    state.turnDurationSeconds = Math.max(10, Number(options.turnDurationSeconds || state.turnDurationSeconds || 60));
    if (options.windStrength) state.windStrength = options.windStrength;
    if (options.windFromDeg != null) state.windFromDeg = normalizeAngle(options.windFromDeg);
    const expBySide = options.crewExperienceBySide || {};
    for (const ship of state.ships) {
      ship.x = ship.startX; ship.y = ship.startY; ship.heading = ship.startHeading;
      ship.sail = 'MV'; ship.previousSail = 'MV'; ship.effectiveSail = 'MV';
      ship.rudder = 0; ship.previousRudder = 0;
      ship.hull = ship.maxHull;
      for (const mast of Object.values(ship.masts)) { mast.health = mast.max; mast.fallen = false; }
      syncRig(ship);
      ship.crew = ship.initialCrew;
      ship.fatigue = 0;
      ship.crewExperience = expBySide[ship.side] || ship.crewExperience || 'NORMAL';
      ship.portGuns = ship.gunsPerSide; ship.starboardGuns = ship.gunsPerSide;
      ship.rudderDamaged = false; ship.speedEfficiency = 1;
      ship.loadedAmmo = 'ROUND_SHOT'; ship.nextAmmo = 'ROUND_SHOT';
      ship.sunk = false; ship.disabled = false; ship.confirmed = false;
      ship.collidedThisTurn = false; ship.forceTurnOnly = false; ship.lastTargetId = null;
      const target = state.ships.find(s => s.side !== ship.side);
      ship.order = defaultOrder(ship, target && target.id);
    }
    state.log = ['--- INICIO PARTIDA ---', `Configuración aplicada. Turno: ${state.turnDurationSeconds}s. Viento: ${state.windStrength}.`, '--- INICIO TURNO 1 ---'];
    return state;
  }

  function livingShips(state, side) { return state.ships.filter(s => !s.sunk && (!side || s.side === side)); }
  function nearestEnemy(state, ship) {
    let best = null, bestD = Infinity;
    for (const other of state.ships) {
      if (other.side === ship.side || other.sunk) continue;
      const d = distance(ship, other);
      if (d < bestD) { best = other; bestD = d; }
    }
    return best;
  }

  function windSpeedModifier(ship, windFromDeg, windStrength) {
    const toward = normalizeAngle(windFromDeg + 180);
    const rel = Math.abs(angleDiff(ship.heading, toward));
    if (windStrength === 'CALMA') return rel <= 45 ? 0.75 : rel >= 135 ? 0.45 : 0.60;
    if (windStrength === 'FUERTE') return rel <= 45 ? 1.35 : rel <= 110 ? 1.15 : rel <= 135 ? 0.80 : 0.35;
    return rel <= 45 ? 1.20 : rel >= 135 ? 0.50 : 1.00;
  }

  function updateSpeedEfficiency(ship) {
    const hullLostPct = ship.maxHull > 0 ? (1 - ship.hull / ship.maxHull) * 100 : 100;
    const hullPenalty = Math.floor(hullLostPct / 10) * 0.01;
    let mastPenalty = 0;
    for (const key of ['fore','main','mizzen']) {
      const mast = ship.masts[key];
      const weight = SPEED_MAST_PENALTY[key];
      if (mast.fallen) mastPenalty += weight;
      else if (mast.max > 0) mastPenalty += (1 - mast.health / mast.max) * weight * 0.5;
    }
    ship.speedEfficiency = Math.max(0.05, 1 - hullPenalty - mastPenalty);
    syncRig(ship);
    return ship.speedEfficiency;
  }

  function fatigueThreshold(ship) { return FATIGUE_THRESHOLD[ship.crewExperience] || FATIGUE_THRESHOLD.NORMAL; }
  function fatigueEfficiency(ship) {
    const threshold = fatigueThreshold(ship);
    if (ship.crewExperience === 'VETERANA' && ship.fatigue < 100) return 1;
    if (ship.fatigue <= threshold) return 1;
    return Math.max(0.1, 1 - ((ship.fatigue - threshold) / (100 - threshold)) * 0.5);
  }

  function effectiveSailForOrder(ship, orderedSail) {
    const currentIndex = SAIL_ORDER.indexOf(ship.sail);
    const targetIndex = SAIL_ORDER.indexOf(orderedSail);
    if (targetIndex < 0 || currentIndex < 0 || targetIndex === currentIndex) return ship.sail;
    return SAIL_ORDER[currentIndex + Math.sign(targetIndex - currentIndex)];
  }

  function validateRudderOrder(ship, newRudder, sailOverride) {
    const v = clamp(Number(newRudder) || 0, -MAX_RUDDER, MAX_RUDDER);
    if (ship.rudderDamaged && Math.abs(v) > 1) return { valid: false, reason: 'Timón dañado: sólo ±1.' };
    const sail = sailOverride || effectiveSailForOrder(ship, ship.order && ship.order.sail || ship.sail);
    const ampLimit = RUDDER_AMPLITUDE_LIMIT[sail] == null ? 4 : RUDDER_AMPLITUDE_LIMIT[sail];
    const changeLimit = RUDDER_CHANGE_LIMIT[sail] == null ? 4 : RUDDER_CHANGE_LIMIT[sail];
    if (Math.abs(v) > ampLimit) return { valid: false, reason: `Amplitud ${v} excede ${ampLimit} para ${sail}.` };
    if (Math.abs(v - ship.rudder) > changeLimit) return { valid: false, reason: `Cambio de timón excede ${changeLimit} para ${sail}.` };
    return { valid: true, value: v, sail };
  }

  function projectMovement(state, ship, order) {
    if (ship.sunk) return { x: ship.x, y: ship.y, heading: ship.heading, sail: ship.sail, rudder: ship.rudder, valid: true };
    order = order || defaultOrder(ship, null);
    const sail = effectiveSailForOrder(ship, order.sail || ship.sail);
    const rv = validateRudderOrder(ship, order.rudder, sail);
    const rudder = rv.valid ? rv.value : ship.rudder;
    const abs = Math.abs(rudder);
    const baseTurn = RUDDER_DEG_PV[abs] || 0;
    const turn = Math.sign(rudder) * baseTurn * (RUDDER_EFFECT[sail] || 1);
    const newHeading = normalizeAngle(ship.heading + turn);
    const avgHeading = normalizeAngle(ship.heading + turn / 2);
    const onlyTurn = ship.forceTurnOnly || ship.collidedThisTurn;
    const baseDistance = onlyTurn ? 0 : (SAIL_SPEED[sail] || 0);
    const speed = baseDistance * windSpeedModifier(ship, state.windFromDeg, state.windStrength) * ship.speedEfficiency;
    const rad = avgHeading * Math.PI / 180;
    return {
      x: clamp(ship.x + speed * Math.sin(rad), 20, WORLD.width - 20),
      y: clamp(ship.y - speed * Math.cos(rad), 20, WORLD.height - 20),
      heading: newHeading,
      sail,
      rudder,
      valid: rv.valid,
      reason: rv.reason || null
    };
  }

  function broadsideArcFactor(attacker, target) {
    const r = relativeBearing(attacker, target);
    if (r >= 70 && r <= 110) return { factor: 1, bearing: r, band: 'ESTRIBOR', section: 'COMPLETA' };
    if (r >= 45 && r < 70) return { factor: 0.5, bearing: r, band: 'ESTRIBOR', section: 'PROA' };
    if (r > 110 && r <= 135) return { factor: 0.5, bearing: r, band: 'ESTRIBOR', section: 'POPA' };
    if (r >= 250 && r <= 290) return { factor: 1, bearing: r, band: 'BABOR', section: 'COMPLETA' };
    if (r > 290 && r <= 315) return { factor: 0.5, bearing: r, band: 'BABOR', section: 'PROA' };
    if (r >= 225 && r < 250) return { factor: 0.5, bearing: r, band: 'BABOR', section: 'POPA' };
    return { factor: 0, bearing: r, band: null, section: null };
  }

  function rangeFactor(range) {
    if (range < 100) return 1.5;
    if (range < 250) return 1;
    if (range < 400) return 0.5;
    return 0;
  }

  function rudderTowardHeading(ship, desiredHeading) {
    const err = angleDiff(desiredHeading, ship.heading);
    let candidate = 0;
    if (Math.abs(err) > 70) candidate = err > 0 ? 4 : -4;
    else if (Math.abs(err) > 35) candidate = err > 0 ? 2 : -2;
    else if (Math.abs(err) > 10) candidate = err > 0 ? 1 : -1;
    const check = validateRudderOrder(ship, candidate);
    if (check.valid) return candidate;
    for (const fallback of [Math.sign(candidate) * 2, Math.sign(candidate), 0]) {
      if (validateRudderOrder(ship, fallback).valid) return fallback;
    }
    return 0;
  }

  function planAIOrder(state, ship) {
    if (ship.sunk) return defaultOrder(ship, null);
    const target = nearestEnemy(state, ship);
    if (!target) return defaultOrder(ship, null);
    const d = distance(ship, target);
    const bearing = angleTo(ship, target);
    const arc = broadsideArcFactor(ship, target);
    let desiredHeading = bearing;
    if (d <= 300) {
      const a = normalizeAngle(bearing - 90), b = normalizeAngle(bearing + 90);
      desiredHeading = Math.abs(angleDiff(a, ship.heading)) <= Math.abs(angleDiff(b, ship.heading)) ? a : b;
    }
    let sail = d > 330 ? 'TV' : d < 120 ? 'PV' : 'MV';
    let rudder = arc.factor > 0 && d <= 300 ? 0 : rudderTowardHeading(ship, desiredHeading);
    if (ship.x < 55 || ship.x > WORLD.width - 55 || ship.y < 55 || ship.y > WORLD.height - 55) {
      rudder = rudderTowardHeading(ship, angleTo(ship, { x: WORLD.width / 2, y: WORLD.height / 2 }));
      sail = 'MV';
    }
    const fireArc = broadsideArcFactor(ship, target);
    const fire = d < MAX_FIRE_RANGE && fireArc.factor > 0;
    const aim = target.rig > target.maxRig * 0.55 ? 'HULL' : 'RIGGING';
    return { sail, rudder, fire, fireBand: fireArc.band || 'AUTO', fireSection: 'AUTO', ammo: aim === 'RIGGING' ? 'DOUBLE_SHOT' : 'ROUND_SHOT', aim, targetId: target.id };
  }

  function mastDamage(ship, amount, rng, bonusDirect) {
    if (amount <= 0) return { fallen: [], applied: 0 };
    const weights = [['fore', 0.30], ['main', 0.45], ['mizzen', 0.25]];
    let remaining = amount;
    const fallen = [];
    for (let i = 0; i < weights.length; i++) {
      const [key, share] = weights[i];
      const mast = ship.masts[key];
      if (mast.fallen) continue;
      const damage = Math.max(0, Math.round((i === weights.length - 1 ? remaining : amount * share) + (bonusDirect && rngValue(rng) < MAST_DAMAGE_CHANCE_RAKE ? mast.max * MAST_DAMAGE_BONUS_PERCENT_RAKE : 0)));
      remaining -= Math.round(amount * share);
      const wasFallen = mast.fallen;
      mast.health = Math.max(0, mast.health - damage);
      if (mast.health <= 0) mast.fallen = true;
      if (!wasFallen && mast.fallen) {
        fallen.push(key);
        applyCasualties(ship, ship.initialCrew * CASUALTY_MAST_FALL_PERCENT);
      }
    }
    updateSpeedEfficiency(ship);
    return { fallen, applied: amount };
  }

  function impactedBand(defender, attacker) {
    const r = normalizeAngle(angleTo(defender, attacker) - defender.heading);
    return r > 0 && r < 180 ? 'ESTRIBOR' : 'BABOR';
  }

  function dismountGuns(ship, band, hullDamage, ammo, rng) {
    if (!band || hullDamage <= 0 || ship.maxHull <= 0) return 0;
    const pct = (hullDamage / ship.maxHull) * 100;
    if (pct < 1) return 0;
    let lost = Math.floor(pct / 2);
    if (Math.floor(pct) % 2 === 1 && rngValue(rng) < 0.5) lost++;
    if (ammo === 'DOUBLE_SHOT') lost = Math.round(lost * 1.5);
    const key = band === 'BABOR' ? 'portGuns' : 'starboardGuns';
    const actual = Math.min(ship[key], Math.max(0, lost));
    ship[key] -= actual;
    return actual;
  }

  function applyCasualties(ship, amount) {
    const n = Math.min(ship.crew, Math.max(0, Math.round(amount)));
    ship.crew -= n;
    return n;
  }

  function rakeType(attacker, defender) {
    const rel = normalizeAngle(angleTo(defender, attacker) - defender.heading);
    if (rel <= RAKE_ARC_DEGREES || rel >= 360 - RAKE_ARC_DEGREES) return 'BOW';
    if (rel >= 180 - RAKE_ARC_DEGREES && rel <= 180 + RAKE_ARC_DEGREES) return 'STERN';
    return null;
  }

  function operationalGunFactor(attacker, band) {
    if (!band || attacker.gunsPerSide <= 0) return 0;
    const current = band === 'BABOR' ? attacker.portGuns : attacker.starboardGuns;
    return clamp(current / attacker.gunsPerSide, 0, 1);
  }

  function resolveShot(state, attacker, rng) {
    const order = attacker.order || {};
    if (!order.fire || attacker.sunk) return null;
    const target = state.ships.find(s => s.id === order.targetId && !s.sunk && s.side !== attacker.side);
    if (!target) { state.log.push(`${attacker.name}: disparo cancelado; objetivo no disponible.`); return null; }
    const d = distance(attacker, target);
    const arc = broadsideArcFactor(attacker, target);
    const rf = rangeFactor(d);
    if (!arc.factor || !rf) { state.log.push(`${attacker.name}: sin solución de tiro sobre ${target.name} (${Math.round(d)} m).`); return null; }
    const requestedBand = order.fireBand || 'AUTO';
    if (requestedBand !== 'AUTO' && requestedBand !== arc.band) { state.log.push(`${attacker.name}: orden de ${requestedBand.toLowerCase()} sin arco sobre ${target.name}.`); return null; }
    const requestedSection = order.fireSection || 'AUTO';
    let sectionFactor = arc.factor;
    if (requestedSection === 'COMPLETA' && arc.section !== 'COMPLETA') { state.log.push(`${attacker.name}: batería completa sin solución sobre ${target.name}.`); return null; }
    if (requestedSection === 'PROA' || requestedSection === 'POPA') {
      if (arc.section === 'COMPLETA') sectionFactor = 0.5;
      else if (arc.section !== requestedSection) { state.log.push(`${attacker.name}: sección ${requestedSection.toLowerCase()} sin solución.`); return null; }
    }
    const gunFactor = operationalGunFactor(attacker, arc.band);
    if (gunFactor <= 0) { state.log.push(`${attacker.name}: batería de ${arc.band.toLowerCase()} sin cañones operativos.`); return null; }
    const spread = 0.86 + rngValue(rng) * 0.28;
    let raw = attacker.historical.armament.broadsideLongKg * 0.38 * sectionFactor * rf * spread * gunFactor * fatigueEfficiency(attacker);
    const ammo = attacker.loadedAmmo || 'ROUND_SHOT';
    const aim = order.aim || 'HULL';
    if (ammo === 'DOUBLE_SHOT') raw *= aim === 'HULL' ? 1.25 : 1.5;
    if (ammo === 'GRAPE' && aim === 'HULL') raw *= 0.5;
    if (ammo === 'GRAPE' && aim === 'RIGGING') raw *= 0.75;
    const rake = rakeType(attacker, target);
    if (rake === 'STERN') raw *= STERN_RAKE_MULTIPLIER;
    else if (rake === 'BOW') raw *= BOW_RAKE_MULTIPLIER;
    let hullDamage = 0, rigDamage = 0;
    if (aim === 'RIGGING') { rigDamage = Math.round(raw * 0.9); hullDamage = Math.round(raw * 0.12); }
    else { hullDamage = Math.round(raw); rigDamage = Math.round(raw * 0.08); }
    const prevHull = target.hull;
    target.hull = Math.max(0, target.hull - hullDamage);
    const realHullDamage = Math.max(0, prevHull - target.hull);
    let fallen = [];
    if (rigDamage > 0) fallen = mastDamage(target, rigDamage, rng, !!rake).fallen;
    else updateSpeedEfficiency(target);
    const bandHit = impactedBand(target, attacker);
    const gunsLost = aim === 'HULL' ? dismountGuns(target, bandHit, realHullDamage, ammo, rng) : 0;
    let casualties = 0;
    if (aim === 'HULL') {
      if (ammo === 'GRAPE') casualties = realHullDamage * CASUALTY_GRAPE_FACTOR;
      else casualties = realHullDamage * CASUALTY_ROUND_HULL_FACTOR;
      if (ammo === 'DOUBLE_SHOT') casualties *= 2;
      if (rake === 'BOW') casualties *= CASUALTY_BOW_RAKE_MULTIPLIER;
      if (rake === 'STERN') casualties *= CASUALTY_STERN_RAKE_MULTIPLIER;
    }
    casualties = applyCasualties(target, casualties);
    if (rake === 'STERN' && aim === 'HULL' && !target.rudderDamaged && rngValue(rng) < RUDDER_DAMAGE_CHANCE_RAKE) {
      target.rudderDamaged = true;
      state.log.push(`¡Timón del ${target.name} dañado por barrido de popa!`);
    }
    updateSpeedEfficiency(target);
    attacker.lastTargetId = target.id;
    attacker.nextAmmo = order.ammo || attacker.nextAmmo;
    const ammoLabel = ammo === 'DOUBLE_SHOT' ? 'doble bala' : ammo === 'GRAPE' ? 'metralla' : 'bala redonda';
    const rakeLabel = rake ? ` · barrido ${rake === 'STERN' ? 'de popa' : 'de proa'}` : '';
    state.log.push(`${attacker.name} dispara ${arc.band} (${arc.section}) con ${ammoLabel} sobre ${target.name} a ${Math.round(d)} m${rakeLabel}: casco -${realHullDamage}, aparejo -${rigDamage}, cañones ${bandHit.toLowerCase()} -${gunsLost}, bajas ${casualties}${fallen.length ? `, mástiles caídos ${fallen.join('/')}` : ''}.`);
    if (target.hull <= 0 && !target.sunk) {
      const extra = applyCasualties(target, target.crew * CASUALTY_HULL_DESTROYED_PERCENT);
      target.sunk = true;
      state.log.push(`¡${target.name} queda fuera de combate; bajas adicionales por destrucción del casco: ${extra}.`);
    }
    return { hullDamage: realHullDamage, rigDamage, casualties, gunsLost, rake, fallen };
  }

  function collisionPoints(ship) {
    const rad = ship.heading * Math.PI / 180;
    const half = ship.historical.visual.lengthM * 0.54;
    const radius = Math.max(7, ship.historical.visual.beamM * 0.55);
    return [
      { type: 'CENTER', x: ship.x, y: ship.y, radius },
      { type: 'BOW', x: ship.x + half * Math.sin(rad), y: ship.y - half * Math.cos(rad), radius },
      { type: 'STERN', x: ship.x - half * Math.sin(rad), y: ship.y + half * Math.cos(rad), radius }
    ];
  }

  function detectCollision(a, b) {
    for (const pa of collisionPoints(a)) for (const pb of collisionPoints(b)) {
      if (Math.hypot(pa.x - pb.x, pa.y - pb.y) < pa.radius + pb.radius) return { collides: true, a: pa.type, b: pb.type };
    }
    return { collides: false, a: null, b: null };
  }

  function sailIndex(sail) { return Math.max(0, SAIL_ORDER.indexOf(sail)); }

  function applyCollisionDamage(state, rng) {
    const alive = livingShips(state);
    for (let i = 0; i < alive.length; i++) for (let j = i + 1; j < alive.length; j++) {
      const a = alive[i], b = alive[j];
      const hit = detectCollision(a, b);
      if (!hit.collides) continue;
      const speedA = SAIL_SPEED[a.effectiveSail || a.sail] || 0;
      const speedB = SAIL_SPEED[b.effectiveSail || b.sail] || 0;
      const impact = BASE_COLLISION_DAMAGE + Math.round((speedA + speedB) * 0.35);
      for (const [ship, ownType, other] of [[a, hit.a, b], [b, hit.b, a]]) {
        const hullDamage = impact;
        ship.hull = Math.max(0, ship.hull - hullDamage);
        mastDamage(ship, Math.round(hullDamage * RIGGING_DAMAGE_COLLISION_FACTOR), rng, false);
        const casualties = applyCasualties(ship, hullDamage * CASUALTY_COLLISION_FACTOR);
        if (ownType === 'STERN' && !ship.rudderDamaged) {
          const diff = Math.abs(sailIndex(ship.effectiveSail) - sailIndex(other.effectiveSail));
          const chance = Math.min(MAX_RUDDER_DAMAGE_CHANCE_STERN_COLLISION, BASE_RUDDER_DAMAGE_CHANCE_STERN_COLLISION + diff * RUDDER_DAMAGE_BONUS_PER_SAIL_DIFFERENCE);
          if (rngValue(rng) < chance) ship.rudderDamaged = true;
        }
        ship.collidedThisTurn = true; ship.forceTurnOnly = true;
        updateSpeedEfficiency(ship);
        if (ship.hull <= 0) ship.sunk = true;
        state.log.push(`Colisión: ${ship.name} (${ownType}) sufre casco -${hullDamage}, bajas ${casualties}${ship.rudderDamaged ? ', timón comprometido' : ''}.`);
      }
    }
  }

  function movementFatigue(ship, projected) {
    if (ship.forceTurnOnly || ship.collidedThisTurn) return 0;
    if (projected.sail === ship.sail) return 0;
    const pair = new Set([projected.sail, ship.sail]);
    if (pair.has('NV') && pair.has('PV')) return FATIGUE_NV_PV;
    return FATIGUE_ACTION;
  }
  function fireFatigue(ship) {
    if (!ship.order || !ship.order.fire) return 0;
    return ship.order.fireSection === 'COMPLETA' || ship.order.fireSection === 'AUTO' ? FATIGUE_ACTION : Math.round(FATIGUE_ACTION / 2);
  }
  function applyFatigueEndTurn(ship, generated) {
    if (generated > 0) ship.fatigue = clamp(ship.fatigue + generated, 0, 100);
    else ship.fatigue = clamp(ship.fatigue - FATIGUE_RECOVERY, 0, 100);
  }

  function maybeChangeWind(state, rng) {
    if (state.windHasChanged) return false;
    const t = state.turn;
    let chance = 0;
    if (t >= 11 && t <= 20) chance = 1;
    else if (t >= 21 && t <= 25) chance = 2;
    else if (t >= 26 && t <= 30) chance = 3;
    else if (t >= 31) chance = Math.min(50, 3 + (t - 30));
    if (rngValue(rng) * 100 >= chance) return false;
    const type = 1 + Math.floor(rngValue(rng) * 3);
    if (type === 1 || type === 3) {
      const choices = ['CALMA','MEDIA','FUERTE'].filter(v => v !== state.windStrength);
      state.windStrength = choices[Math.floor(rngValue(rng) * choices.length)];
    }
    if (type === 2 || type === 3) state.windFromDeg = Math.floor(rngValue(rng) * 8) * 45;
    state.windHasChanged = true;
    state.log.push(`Cambio de viento: ${Math.round(state.windFromDeg)}° · ${state.windStrength}.`);
    return true;
  }

  function evaluateResult(state) {
    const rn = livingShips(state, SIDE_ROYAL_NAVY).length;
    const ra = livingShips(state, SIDE_REAL_ARMADA).length;
    if (rn === 0 && ra === 0) state.result = 'draw';
    else if (rn === 0) state.result = SIDE_REAL_ARMADA;
    else if (ra === 0) state.result = SIDE_ROYAL_NAVY;
    else state.result = null;
    return state.result;
  }

  function resolveTurn(state, options) {
    options = options || {};
    const rng = options.rng || Math.random;
    const autoSides = options.autoSides || [SIDE_REAL_ARMADA];
    if (state.result) return state;
    if (!state.gameStarted) state.gameStarted = true;
    state.log.push(`--- TURNO ${state.turn} ---`);
    for (const ship of state.ships) {
      if (ship.sunk) continue;
      if (autoSides.includes(ship.side)) ship.order = planAIOrder(state, ship);
      if (!ship.order) ship.order = defaultOrder(ship, nearestEnemy(state, ship)?.id || null);
      ship.nextAmmo = ship.order.ammo || ship.nextAmmo;
      ship.collidedThisTurn = false;
    }
    const projections = new Map();
    const fatigueGenerated = new Map();
    for (const ship of state.ships) {
      const p = projectMovement(state, ship, ship.order);
      projections.set(ship.id, p);
      fatigueGenerated.set(ship.id, movementFatigue(ship, p) + fireFatigue(ship));
    }
    for (const ship of state.ships) {
      const p = projections.get(ship.id);
      ship.previousSail = ship.sail; ship.previousRudder = ship.rudder;
      ship.x = p.x; ship.y = p.y; ship.heading = p.heading;
      ship.effectiveSail = p.sail; ship.sail = p.sail; ship.rudder = p.rudder;
    }
    applyCollisionDamage(state, rng);
    const shooters = state.ships.filter(s => !s.sunk).map(s => s.id);
    for (const id of shooters) {
      const attacker = state.ships.find(s => s.id === id);
      if (attacker && !attacker.sunk) resolveShot(state, attacker, rng);
    }
    for (const ship of state.ships) {
      applyFatigueEndTurn(ship, fatigueGenerated.get(ship.id) || 0);
      ship.loadedAmmo = ship.nextAmmo;
      ship.confirmed = false;
      ship.forceTurnOnly = false;
      updateSpeedEfficiency(ship);
    }
    evaluateResult(state);
    if (!state.result) maybeChangeWind(state, rng);
    state.turn += 1;
    if (!state.result) {
      state.log.push(`--- INICIO TURNO ${state.turn} ---`);
      for (const ship of state.ships) if (!ship.sunk && autoSides.includes(ship.side)) ship.order = planAIOrder(state, ship);
    }
    return state;
  }

  function autoOrderSide(state, side) {
    for (const ship of state.ships) if (ship.side === side && !ship.sunk) ship.order = planAIOrder(state, ship);
    return state;
  }

  function validateState(state) {
    const errors = [];
    if (!state || !Array.isArray(state.ships) || state.ships.length !== 4) errors.push('expected four ships');
    if (!state || !Array.isArray(state.ships)) return errors;
    for (const s of state.ships) {
      for (const key of ['x','y','heading','hull','rig','crew','fatigue','portGuns','starboardGuns','speedEfficiency']) if (!Number.isFinite(s[key])) errors.push(`${s.id}: non-finite ${key}`);
      if (!s.id || !s.side) errors.push('ship missing identity/side');
      if (!s.masts || !s.masts.fore || !s.masts.main || !s.masts.mizzen) errors.push(`${s.id}: missing mast state`);
      if (s.portGuns < 0 || s.starboardGuns < 0 || s.portGuns > s.gunsPerSide || s.starboardGuns > s.gunsPerSide) errors.push(`${s.id}: invalid gun state`);
      if (s.fatigue < 0 || s.fatigue > 100) errors.push(`${s.id}: invalid fatigue`);
    }
    if (state.ships.filter(s => s.side === SIDE_ROYAL_NAVY).length !== 2) errors.push('Royal Navy side must contain two ships');
    if (state.ships.filter(s => s.side === SIDE_REAL_ARMADA).length !== 2) errors.push('Real Armada side must contain two ships');
    return errors;
  }

  return {
    SIDE_ROYAL_NAVY, SIDE_REAL_ARMADA, WORLD, MAX_FIRE_RANGE, BASE_HULL, BASE_RIG, MAX_RUDDER,
    SAIL_SPEED, SAIL_ORDER, FATIGUE_ACTION, FATIGUE_NV_PV, FATIGUE_RECOVERY,
    buildInitialState, startBattle, livingShips, nearestEnemy, distance, angleTo, relativeBearing,
    broadsideArcFactor, validateRudderOrder, projectMovement, planAIOrder, autoOrderSide,
    resolveShot, resolveTurn, evaluateResult, updateSpeedEfficiency, fatigueEfficiency, maybeChangeWind,
    validateState, seededRng
  };
});