(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.Pilot2v2Core = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';

  const SIDE_ROYAL_NAVY = 'royal-navy';
  const SIDE_REAL_ARMADA = 'real-armada';
  const WORLD = { width: 1000, height: 700 };
  const MAX_FIRE_RANGE = 450;
  const BASE_HULL = 1200;
  const BASE_RIG = 800;
  const MAX_RUDDER = 4;
  const SAIL_SPEED = { NV: 0, PV: 14, MV: 25, TV: 34 };
  const RUDDER_DEG_PER_POINT = 8;
  const RUDDER_SAIL_FACTOR = { NV: 0.8, PV: 1.0, MV: 0.82, TV: 0.62 };

  function clone(v) { return JSON.parse(JSON.stringify(v)); }
  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function angleDiff(a, b) {
    let d = normalizeAngle(a - b);
    if (d > 180) d -= 360;
    return d;
  }
  function distance(a, b) {
    return Math.hypot(b.x - a.x, b.y - a.y);
  }
  function angleTo(a, b) {
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    return normalizeAngle(Math.atan2(dx, -dy) * 180 / Math.PI);
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

  function defaultOrder(ship, enemyId) {
    return {
      sail: ship.sail || 'MV',
      rudder: 0,
      fire: false,
      fireBand: 'AUTO',
      fireSection: 'AUTO',
      ammo: 'ROUND_SHOT',
      aim: 'HULL',
      targetId: enemyId || null
    };
  }

  function buildInitialState(data, options) {
    options = options || {};
    if (!data || !Array.isArray(data.ships) || data.ships.length !== 4) {
      throw new Error('The 2v2 pilot requires exactly four historical ship records.');
    }

    const slots = {
      [SIDE_ROYAL_NAVY]: [
        { x: 220, y: 260, heading: 90 },
        { x: 220, y: 440, heading: 90 }
      ],
      [SIDE_REAL_ARMADA]: [
        { x: 780, y: 260, heading: 270 },
        { x: 780, y: 440, heading: 270 }
      ]
    };
    const counters = { [SIDE_ROYAL_NAVY]: 0, [SIDE_REAL_ARMADA]: 0 };

    const ships = data.ships.map(historical => {
      if (!slots[historical.side]) throw new Error('Unsupported side: ' + historical.side);
      const slot = slots[historical.side][counters[historical.side]++];
      if (!slot) throw new Error('Each side must contain exactly two ships.');
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
        sail: 'MV',
        rudder: 0,
        hull: BASE_HULL,
        maxHull: BASE_HULL,
        rig: BASE_RIG,
        maxRig: BASE_RIG,
        crew: historical.crew.actionComplement,
        initialCrew: historical.crew.actionComplement,
        sunk: false,
        disabled: false,
        confirmed: false,
        lastTargetId: null,
        order: null
      };
    });

    for (const ship of ships) {
      const enemies = ships.filter(s => s.side !== ship.side);
      ship.order = defaultOrder(ship, enemies[0] ? enemies[0].id : null);
    }

    return {
      scenario: clone(data.scenario || {}),
      turn: 1,
      windFromDeg: options.windFromDeg == null ? 0 : normalizeAngle(options.windFromDeg),
      windStrength: options.windStrength || 'MEDIA',
      ships,
      log: ['Piloto 2v2 iniciado. Mecánicas de navegación/daño provisionales; datos de barco históricamente trazables.'],
      result: null
    };
  }

  function livingShips(state, side) {
    return state.ships.filter(s => !s.sunk && (!side || s.side === side));
  }

  function nearestEnemy(state, ship) {
    let best = null;
    let bestD = Infinity;
    for (const other of state.ships) {
      if (other.side === ship.side || other.sunk) continue;
      const d = distance(ship, other);
      if (d < bestD) { best = other; bestD = d; }
    }
    return best;
  }

  function windSpeedModifier(ship, windFromDeg, windStrength) {
    const windToward = normalizeAngle(windFromDeg + 180);
    const rel = Math.abs(angleDiff(ship.heading, windToward));
    let mod = 1;
    if (windStrength === 'CALMA') {
      mod = rel <= 45 ? 1.05 : rel >= 135 ? 0.8 : 0.95;
    } else if (windStrength === 'FUERTE') {
      mod = rel <= 45 ? 1.35 : rel <= 110 ? 1.15 : rel <= 135 ? 0.8 : 0.35;
    } else {
      mod = rel <= 45 ? 1.2 : rel >= 135 ? 0.5 : 1.0;
    }
    return mod;
  }

  function speedEfficiency(ship) {
    const rigRatio = ship.maxRig > 0 ? ship.rig / ship.maxRig : 1;
    if (rigRatio <= 0) return 0.35;
    if (rigRatio < 0.3) return 0.55;
    if (rigRatio < 0.6) return 0.75;
    return 1;
  }

  function projectMovement(state, ship, order) {
    if (ship.sunk) return { x: ship.x, y: ship.y, heading: ship.heading, sail: ship.sail, rudder: ship.rudder };
    order = order || defaultOrder(ship, null);
    const sail = order.sail || ship.sail;
    const rudder = clamp(Number(order.rudder) || 0, -MAX_RUDDER, MAX_RUDDER);
    const turn = rudder * RUDDER_DEG_PER_POINT * (RUDDER_SAIL_FACTOR[sail] || 1);
    const newHeading = normalizeAngle(ship.heading + turn);
    const avgHeading = normalizeAngle(ship.heading + turn / 2);
    const baseSpeed = SAIL_SPEED[sail] || 0;
    const speed = baseSpeed * windSpeedModifier(ship, state.windFromDeg, state.windStrength) * speedEfficiency(ship);
    const rad = avgHeading * Math.PI / 180;
    const x = clamp(ship.x + speed * Math.sin(rad), 20, WORLD.width - 20);
    const y = clamp(ship.y - speed * Math.cos(rad), 20, WORLD.height - 20);
    return { x, y, heading: newHeading, sail, rudder };
  }

  function broadsideArcFactor(attacker, target) {
    const r = relativeBearing(attacker, target);
    const fullStarboard = r >= 65 && r <= 115;
    const fullPort = r >= 245 && r <= 295;
    if (fullStarboard || fullPort) {
      return { factor: 1, bearing: r, band: r < 180 ? 'ESTRIBOR' : 'BABOR', section: 'COMPLETA' };
    }

    if (r >= 45 && r < 65) return { factor: 0.6, bearing: r, band: 'ESTRIBOR', section: 'PROA' };
    if (r > 115 && r <= 135) return { factor: 0.6, bearing: r, band: 'ESTRIBOR', section: 'POPA' };
    if (r >= 295 && r <= 315) return { factor: 0.6, bearing: r, band: 'BABOR', section: 'PROA' };
    if (r >= 225 && r < 245) return { factor: 0.6, bearing: r, band: 'BABOR', section: 'POPA' };
    return { factor: 0, bearing: r, band: null, section: null };
  }

  function rangeFactor(range) {
    if (range <= 100) return 1;
    if (range <= 225) return 0.8;
    if (range <= 350) return 0.5;
    if (range <= MAX_FIRE_RANGE) return 0.25;
    return 0;
  }

  function rudderTowardHeading(ship, desiredHeading) {
    const err = angleDiff(desiredHeading, ship.heading);
    if (Math.abs(err) > 70) return err > 0 ? 4 : -4;
    if (Math.abs(err) > 35) return err > 0 ? 2 : -2;
    if (Math.abs(err) > 10) return err > 0 ? 1 : -1;
    return 0;
  }

  function planAIOrder(state, ship) {
    if (ship.sunk) return defaultOrder(ship, null);
    const target = nearestEnemy(state, ship);
    if (!target) return defaultOrder(ship, null);

    const d = distance(ship, target);
    const bearing = angleTo(ship, target);
    const arc = broadsideArcFactor(ship, target);
    let desiredHeading;

    if (d > 320) {
      desiredHeading = bearing;
    } else {
      const candidateA = normalizeAngle(bearing - 90);
      const candidateB = normalizeAngle(bearing + 90);
      desiredHeading = Math.abs(angleDiff(candidateA, ship.heading)) <= Math.abs(angleDiff(candidateB, ship.heading))
        ? candidateA
        : candidateB;
    }

    let sail = 'MV';
    if (d > 390) sail = 'TV';
    else if (d < 120) sail = 'PV';

    let rudder = arc.factor > 0 && d <= 300 ? 0 : rudderTowardHeading(ship, desiredHeading);

    if (ship.x < 55 || ship.x > WORLD.width - 55 || ship.y < 55 || ship.y > WORLD.height - 55) {
      const centerHeading = angleTo(ship, { x: WORLD.width / 2, y: WORLD.height / 2 });
      rudder = rudderTowardHeading(ship, centerHeading);
      sail = 'MV';
    }

    const currentArc = broadsideArcFactor(ship, target);
    const fire = d <= MAX_FIRE_RANGE && currentArc.factor > 0;
    return {
      sail,
      rudder,
      fire,
      fireBand: currentArc.band || 'AUTO',
      fireSection: 'AUTO',
      ammo: 'ROUND_SHOT',
      aim: target.rig > target.maxRig * 0.55 ? 'HULL' : 'RIGGING',
      targetId: target.id
    };
  }

  function applyCollisionDamage(state) {
    const alive = livingShips(state);
    for (let i = 0; i < alive.length; i++) {
      for (let j = i + 1; j < alive.length; j++) {
        const a = alive[i], b = alive[j];
        const radiusA = Math.max(11, a.historical.visual.lengthM * 0.32);
        const radiusB = Math.max(11, b.historical.visual.lengthM * 0.32);
        if (distance(a, b) < radiusA + radiusB) {
          a.hull = Math.max(0, a.hull - 70);
          b.hull = Math.max(0, b.hull - 70);
          state.log.push(`Colisión: ${a.name} y ${b.name} sufren daños estructurales.`);
          if (a.hull <= 0) a.sunk = true;
          if (b.hull <= 0) b.sunk = true;
        }
      }
    }
  }

  function resolveShot(state, attacker, rng) {
    const order = attacker.order || {};
    if (!order.fire || attacker.sunk) return;
    const target = state.ships.find(s => s.id === order.targetId && !s.sunk && s.side !== attacker.side);
    if (!target) {
      state.log.push(`${attacker.name}: disparo cancelado; objetivo no disponible.`);
      return;
    }

    const d = distance(attacker, target);
    const arc = broadsideArcFactor(attacker, target);
    const rf = rangeFactor(d);
    if (arc.factor <= 0 || rf <= 0) {
      state.log.push(`${attacker.name}: sin solución de tiro sobre ${target.name} (${Math.round(d)} m).`);
      return;
    }

    const requestedBand = order.fireBand || 'AUTO';
    if (requestedBand !== 'AUTO' && requestedBand !== arc.band) {
      state.log.push(`${attacker.name}: orden de ${requestedBand.toLowerCase()} sin arco sobre ${target.name}.`);
      return;
    }

    const requestedSection = order.fireSection || 'AUTO';
    let sectionFactor = arc.factor;
    if (requestedSection === 'COMPLETA' && arc.section !== 'COMPLETA') {
      state.log.push(`${attacker.name}: batería completa sin solución; ${target.name} está en ${arc.section || 'ninguna sección'}.`);
      return;
    }
    if (requestedSection === 'PROA' || requestedSection === 'POPA') {
      if (arc.section === 'COMPLETA') sectionFactor = 0.6;
      else if (arc.section !== requestedSection) {
        state.log.push(`${attacker.name}: sección ${requestedSection.toLowerCase()} sin solución sobre ${target.name}.`);
        return;
      }
    }

    const longKg = attacker.historical.armament.broadsideLongKg;
    const spread = 0.86 + (rng ? rng() : Math.random()) * 0.28;
    let raw = longKg * 0.38 * rf * sectionFactor * spread;
    const ammo = order.ammo || 'ROUND_SHOT';
    const aim = order.aim || 'HULL';

    // These modifiers preserve the old prototype's provisional ammunition distinctions.
    // They remain legacy mechanics, not finalized historical ballistics.
    if (ammo === 'DOUBLE_SHOT' && aim === 'RIGGING') raw *= 1.5;
    if (ammo === 'GRAPE' && aim === 'HULL') raw *= 0.5;
    if (ammo === 'GRAPE' && aim === 'RIGGING') raw *= 0.75;

    let hullDamage = 0;
    let rigDamage = 0;
    if (aim === 'RIGGING') {
      rigDamage = Math.round(raw * 0.9);
      hullDamage = Math.round(raw * 0.12);
    } else {
      hullDamage = Math.round(raw);
      rigDamage = Math.round(raw * 0.08);
    }

    target.hull = Math.max(0, target.hull - hullDamage);
    target.rig = Math.max(0, target.rig - rigDamage);
    let casualtyRate = d < 150 ? 0.03 : 0.018;
    if (ammo === 'GRAPE') casualtyRate *= 2.25;
    const casualties = Math.min(target.crew, Math.max(0, Math.round((hullDamage + rigDamage * 0.4) * casualtyRate)));
    target.crew -= casualties;
    attacker.lastTargetId = target.id;

    const ammoLabel = ammo === 'DOUBLE_SHOT' ? 'doble bala' : ammo === 'GRAPE' ? 'metralla' : 'bala redonda';
    state.log.push(`${attacker.name} dispara ${arc.band} (${arc.section}) con ${ammoLabel} sobre ${target.name} a ${Math.round(d)} m: casco -${hullDamage}, aparejo -${rigDamage}, bajas ${casualties}.`);
    if (target.hull <= 0 && !target.sunk) {
      target.sunk = true;
      state.log.push(`¡${target.name} queda fuera de combate y se hunde en este modelo piloto!`);
    }
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

    state.log.push(`--- Turno ${state.turn} ---`);

    for (const ship of state.ships) {
      if (ship.sunk) continue;
      if (autoSides.includes(ship.side)) ship.order = planAIOrder(state, ship);
      if (!ship.order) ship.order = defaultOrder(ship, nearestEnemy(state, ship)?.id || null);
    }

    const projections = new Map();
    for (const ship of state.ships) projections.set(ship.id, projectMovement(state, ship, ship.order));
    for (const ship of state.ships) {
      const p = projections.get(ship.id);
      ship.x = p.x; ship.y = p.y; ship.heading = p.heading;
      ship.sail = p.sail || ship.sail;
      ship.rudder = p.rudder == null ? ship.rudder : p.rudder;
    }

    applyCollisionDamage(state);

    const firingSnapshot = state.ships.filter(s => !s.sunk).map(s => s.id);
    for (const id of firingSnapshot) {
      const attacker = state.ships.find(s => s.id === id);
      if (attacker && !attacker.sunk) resolveShot(state, attacker, rng);
    }

    evaluateResult(state);
    state.turn += 1;
    for (const ship of state.ships) ship.confirmed = false;
    if (!state.result) {
      for (const ship of state.ships) {
        if (!ship.sunk && autoSides.includes(ship.side)) ship.order = planAIOrder(state, ship);
      }
    }
    return state;
  }

  function autoOrderSide(state, side) {
    for (const ship of state.ships) {
      if (ship.side === side && !ship.sunk) ship.order = planAIOrder(state, ship);
    }
    return state;
  }

  function validateState(state) {
    const errors = [];
    if (!state || !Array.isArray(state.ships) || state.ships.length !== 4) errors.push('expected four ships');
    if (state && Array.isArray(state.ships)) {
      for (const s of state.ships) {
        for (const key of ['x', 'y', 'heading', 'hull', 'rig', 'crew']) {
          if (!Number.isFinite(s[key])) errors.push(`${s.id}: non-finite ${key}`);
        }
        if (!s.id || !s.side) errors.push('ship missing identity/side');
      }
      if (state.ships.filter(s => s.side === SIDE_ROYAL_NAVY).length !== 2) errors.push('Royal Navy side must contain two ships');
      if (state.ships.filter(s => s.side === SIDE_REAL_ARMADA).length !== 2) errors.push('Real Armada side must contain two ships');
    }
    return errors;
  }

  return {
    SIDE_ROYAL_NAVY,
    SIDE_REAL_ARMADA,
    WORLD,
    MAX_FIRE_RANGE,
    BASE_HULL,
    BASE_RIG,
    MAX_RUDDER,
    SAIL_SPEED,
    buildInitialState,
    defaultOrder,
    livingShips,
    nearestEnemy,
    distance,
    angleTo,
    relativeBearing,
    broadsideArcFactor,
    projectMovement,
    planAIOrder,
    autoOrderSide,
    resolveTurn,
    evaluateResult,
    validateState,
    seededRng
  };
});