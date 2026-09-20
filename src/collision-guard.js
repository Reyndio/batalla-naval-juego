(function (root, factory) {
  const Core = root && root.Pilot2v2Core ? root.Pilot2v2Core : (typeof require !== 'undefined' ? require('./pilot2v2-core.js') : null);
  const api = factory(Core);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.CollisionGuard = api;
  if (root && root.document && Core) api.install();
})(typeof window !== 'undefined' ? window : globalThis, function (Core) {
  'use strict';

  const SAMPLE_STEPS = 48;
  const BASE_COLLISION_DAMAGE = 30;
  const RIGGING_DAMAGE_COLLISION_FACTOR = 0.20;
  const CASUALTY_COLLISION_FACTOR = 0.08;

  // Owner-approved collision response by impacted section.
  const BOW_MOMENTUM_RETENTION = 0;
  const CENTER_MOMENTUM_RETENTION = 0.25;
  const STERN_MOMENTUM_RETENTION = 0.50;
  const EXACT_REAR_MOMENTUM_RETENTION = 1;
  const EXACT_REAR_TOLERANCE_DEG = 5;

  // Stern/rudder risk rises continuously as the collision aligns with the rudder axis.
  const BASE_RUDDER_DAMAGE_CHANCE_STERN_COLLISION = 0.25;
  const MAX_RUDDER_DAMAGE_CHANCE_STERN_COLLISION = 0.75;

  // Prototype used <=30% mast health as the critical visual band. For collision knock-down,
  // that threshold is now the project reconstruction for "very low health".
  const CRITICAL_MAST_HEALTH_RATIO = 0.30;
  const COLLISION_CRITICAL_MAST_FALL_CHANCE = 0.50;
  const COLLISION_ENTANGLE_CHANCE = 0.75;
  const CUT_PARTY_SUCCESS_CHANCE = 0.50;

  let installed = false;

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function angleDelta(from, to) { let d = normalizeAngle(to - from); if (d > 180) d -= 360; return d; }
  function absAngleDiff(a, b) { return Math.abs(angleDelta(a, b)); }
  function rngValue(rng) { return (rng || Math.random)(); }

  function interpolatePose(a, b, t) {
    return {
      x: a.x + (b.x - a.x) * t,
      y: a.y + (b.y - a.y) * t,
      heading: normalizeAngle(a.heading + angleDelta(a.heading, b.heading) * t)
    };
  }

  function collisionPointsAtPose(ship, pose) {
    const rad = pose.heading * Math.PI / 180;
    const half = ship.historical.visual.lengthM * 0.54;
    const radius = Math.max(7, ship.historical.visual.beamM * 0.55);
    return [
      { type: 'CENTER', x: pose.x, y: pose.y, radius },
      { type: 'BOW', x: pose.x + half * Math.sin(rad), y: pose.y - half * Math.cos(rad), radius },
      { type: 'STERN', x: pose.x - half * Math.sin(rad), y: pose.y + half * Math.cos(rad), radius }
    ];
  }

  function poseCollision(a, poseA, b, poseB) {
    for (const pa of collisionPointsAtPose(a, poseA)) {
      for (const pb of collisionPointsAtPose(b, poseB)) {
        if (Math.hypot(pa.x - pb.x, pa.y - pb.y) < pa.radius + pb.radius) {
          return { collides: true, a: pa.type, b: pb.type };
        }
      }
    }
    return { collides: false, a: null, b: null };
  }

  function detectSweptCollision(a, startA, endA, b, startB, endB, steps = SAMPLE_STEPS) {
    const count = Math.max(1, Number(steps) || SAMPLE_STEPS);
    for (let i = 0; i <= count; i++) {
      const t = i / count;
      const poseA = interpolatePose(startA, endA, t);
      const poseB = interpolatePose(startB, endB, t);
      const hit = poseCollision(a, poseA, b, poseB);
      if (hit.collides) return { ...hit, t, poseA, poseB };
    }
    return { collides: false, a: null, b: null, t: null, poseA: null, poseB: null };
  }

  function bearingFromTo(a, b) {
    return normalizeAngle(Math.atan2(b.x - a.x, -(b.y - a.y)) * 180 / Math.PI);
  }

  function sternAlignment(ship, other) {
    const bearing = bearingFromTo(ship, other);
    const astern = normalizeAngle(ship.heading + 180);
    const offAxis = absAngleDiff(astern, bearing);
    return { offAxis, alignment: clamp(1 - offAxis / 90, 0, 1) };
  }

  function collisionMomentumRetention(ownType, ship, other) {
    if (ownType === 'BOW') return BOW_MOMENTUM_RETENTION;
    if (ownType === 'CENTER') return CENTER_MOMENTUM_RETENTION;
    if (ownType === 'STERN') {
      const { offAxis } = sternAlignment(ship, other);
      if (offAxis <= EXACT_REAR_TOLERANCE_DEG) return EXACT_REAR_MOMENTUM_RETENTION;
      return STERN_MOMENTUM_RETENTION;
    }
    return CENTER_MOMENTUM_RETENTION;
  }

  function sternRudderDamageChance(ship, other) {
    const { alignment } = sternAlignment(ship, other);
    return BASE_RUDDER_DAMAGE_CHANCE_STERN_COLLISION +
      (MAX_RUDDER_DAMAGE_CHANCE_STERN_COLLISION - BASE_RUDDER_DAMAGE_CHANCE_STERN_COLLISION) * alignment;
  }

  function mastForSection(type) {
    if (type === 'BOW') return 'fore';
    if (type === 'STERN') return 'mizzen';
    return 'main';
  }

  function syncRig(ship) {
    if (!ship || !ship.masts) return;
    ship.rig = Math.max(0, Object.values(ship.masts).reduce((sum, mast) => sum + Math.max(0, mast.health || 0), 0));
    ship.maxRig = Object.values(ship.masts).reduce((sum, mast) => sum + Math.max(0, mast.max || 0), 0);
  }

  function clearMotion(ship) {
    ship.motionVx = 0;
    ship.motionVy = 0;
    ship.motionSpeed = 0;
    ship.lastInertialDisplacement = 0;
  }

  function linkEntanglement(state, fallenShip, other, mastKey) {
    fallenShip.entangledWith = other.id;
    fallenShip.entangledMastKey = mastKey;
    fallenShip.draggingMast = true;
    fallenShip.fallenMastTowardShipId = other.id;
    other.entangledWith = fallenShip.id;
    other.entangledByMastOf = fallenShip.id;
    clearMotion(fallenShip);
    clearMotion(other);
    fallenShip.collisionMomentumRetention = 0;
    other.collisionMomentumRetention = 0;
    if (state && state.log) state.log.push(`¡${fallenShip.name} y ${other.name} quedan AFERRADOS por la caída del ${mastKey === 'fore' ? 'trinquete' : mastKey === 'main' ? 'palo mayor' : 'mesana'}! Se requiere una partida de carpinteros para cortarlo.`);
  }

  function clearEntanglementPair(state, ship) {
    if (!ship || !ship.entangledWith) return false;
    const other = state && state.ships ? state.ships.find(s => s.id === ship.entangledWith) : null;
    const mastOwner = ship.entangledMastKey ? ship : (other && other.entangledMastKey ? other : null);
    if (mastOwner) {
      mastOwner.draggingMast = false;
      mastOwner.cutAwayMastKey = mastOwner.entangledMastKey || mastOwner.cutAwayMastKey;
      mastOwner.entangledMastKey = null;
      mastOwner.fallenMastTowardShipId = null;
    }
    const clear = s => {
      if (!s) return;
      s.entangledWith = null;
      s.entangledByMastOf = null;
      s.forceTurnOnly = false;
    };
    clear(ship);
    clear(other);
    return true;
  }

  function resolveCutParty(state, ship, requested, rng) {
    if (!requested || !ship || !ship.entangledWith) return { attempted: false, success: false };
    const success = rngValue(rng) < CUT_PARTY_SUCCESS_CHANCE;
    if (success) {
      const otherName = state.ships.find(s => s.id === ship.entangledWith)?.name || 'el otro buque';
      clearEntanglementPair(state, ship);
      state.log.push(`${ship.name}: los carpinteros cortan el palo aferrado y separan al buque de ${otherName}.`);
    } else {
      state.log.push(`${ship.name}: los carpinteros no consiguen liberar el palo aferrado este turno.`);
    }
    return { attempted: true, success };
  }

  function damageCollisionMast(state, ship, ownType, other, amount, rng) {
    const key = mastForSection(ownType);
    const mast = ship.masts && ship.masts[key];
    if (!mast || mast.fallen) return { key, damage: 0, fallen: false, entangled: false };
    const damage = Math.max(0, Math.round(amount));
    const wasStanding = !mast.fallen;
    mast.health = Math.max(0, mast.health - damage);
    let fallen = false;

    if (mast.health <= 0) {
      mast.fallen = true;
      fallen = wasStanding;
    } else if (mast.max > 0 && mast.health / mast.max <= CRITICAL_MAST_HEALTH_RATIO && rngValue(rng) < COLLISION_CRITICAL_MAST_FALL_CHANCE) {
      mast.health = 0;
      mast.fallen = true;
      fallen = true;
    }

    let entangled = false;
    if (fallen) {
      ship.fallenMastTowardShipId = other.id;
      state.log.push(`¡Colisión! El ${key === 'fore' ? 'trinquete' : key === 'main' ? 'palo mayor' : 'mesana'} de ${ship.name} cae hacia ${other.name}.`);
      if (rngValue(rng) < COLLISION_ENTANGLE_CHANCE) {
        linkEntanglement(state, ship, other, key);
        entangled = true;
      }
    }
    syncRig(ship);
    if (Core && Core.updateSpeedEfficiency) Core.updateSpeedEfficiency(ship);
    return { key, damage, fallen, entangled };
  }

  function applyCollisionConsequences(state, ship, ownType, other, rng, preTurnFatigue) {
    const speedA = Core && Core.SAIL_SPEED ? (Core.SAIL_SPEED[ship.effectiveSail || ship.sail] || 0) : 0;
    const speedB = Core && Core.SAIL_SPEED ? (Core.SAIL_SPEED[other.effectiveSail || other.sail] || 0) : 0;
    const impact = BASE_COLLISION_DAMAGE + Math.round((speedA + speedB) * 0.35);
    const hullBefore = ship.hull;
    ship.hull = Math.max(0, ship.hull - impact);
    const casualties = Math.min(ship.crew, Math.max(0, Math.round(impact * CASUALTY_COLLISION_FACTOR)));
    ship.crew -= casualties;

    const retention = collisionMomentumRetention(ownType, ship, other);
    ship.collisionMomentumRetention = retention;

    let rudderChance = 0;
    if (ownType === 'STERN' && !ship.rudderDamaged) {
      rudderChance = sternRudderDamageChance(ship, other);
      if (rngValue(rng) < rudderChance) ship.rudderDamaged = true;
    }

    const rigging = damageCollisionMast(state, ship, ownType, other, Math.round(impact * RIGGING_DAMAGE_COLLISION_FACTOR), rng);

    ship.collidedThisTurn = true;
    const fatigue = Core && Core.collisionFatigueCost ? Core.collisionFatigueCost(ship.effectiveSail || ship.sail) : 0;
    const fatigueBase = Number.isFinite(preTurnFatigue) ? Math.max(ship.fatigue, preTurnFatigue) : ship.fatigue;
    ship.fatigue = Math.max(0, fatigueBase + fatigue);
    if (Core && Core.updateSpeedEfficiency) Core.updateSpeedEfficiency(ship);

    if (state && state.log) {
      const reduction = Math.round((1 - retention) * 100);
      const motionText = ownType === 'STERN' && retention === 1
        ? 'impacto exactamente por popa: conserva su velocidad'
        : ownType === 'BOW'
          ? 'impacto en proa: queda detenido'
          : `velocidad reducida ${reduction}%`;
      const rudderText = ownType === 'STERN' ? `, riesgo de timón ${Math.round(rudderChance * 100)}%${ship.rudderDamaged ? ' — TIMÓN DAÑADO' : ''}` : '';
      state.log.push(`Colisión durante el movimiento: ${ship.name} (${ownType}) casco -${hullBefore - ship.hull}, ${motionText}, fatiga +${fatigue}%, bajas ${casualties}${rudderText}.`);
    }
    return { impact, casualties, fatigue, retention, rudderChance, rigging };
  }

  function capturePoses(state) {
    return new Map(state.ships.map(s => [s.id, { x: s.x, y: s.y, heading: s.heading, fatigue: s.fatigue }]));
  }

  function enforceSweptCollisions(state, before, rng) {
    const ships = state.ships.filter(s => s && !s.sunk && !s.sinking && !s.disabled);
    const handled = new Set();
    for (let i = 0; i < ships.length; i++) {
      for (let j = i + 1; j < ships.length; j++) {
        const a = ships[i], b = ships[j];
        const key = [a.id, b.id].sort().join('|');
        if (handled.has(key)) continue;
        if (a.collidedThisTurn && b.collidedThisTurn) continue;
        const startA = before.get(a.id), startB = before.get(b.id);
        if (!startA || !startB) continue;
        const endA = { x: a.x, y: a.y, heading: a.heading };
        const endB = { x: b.x, y: b.y, heading: b.heading };
        const hit = detectSweptCollision(a, startA, endA, b, startB, endB);
        if (!hit.collides || hit.t <= 0 || hit.t >= 1) continue;

        a.x = hit.poseA.x; a.y = hit.poseA.y; a.heading = hit.poseA.heading;
        b.x = hit.poseB.x; b.y = hit.poseB.y; b.heading = hit.poseB.heading;
        applyCollisionConsequences(state, a, hit.a, b, rng, startA.fatigue);
        applyCollisionConsequences(state, b, hit.b, a, rng, startB.fatigue);
        handled.add(key);
      }
    }
    return handled.size;
  }

  function install() {
    if (installed || !Core || typeof Core.resolveTurn !== 'function') return false;
    const baseResolveTurn = Core.resolveTurn;
    Core.resolveTurn = function (state, options) {
      options = options || {};
      const before = capturePoses(state);
      const cutOrders = new Map(state.ships.map(s => [s.id, !!(s.order && s.order.cutMast)]));
      for (const ship of state.ships) if (ship.entangledWith) ship.forceTurnOnly = true;
      const result = baseResolveTurn.call(Core, state, options);
      for (const ship of state.ships) resolveCutParty(state, ship, cutOrders.get(ship.id), options.rng);
      enforceSweptCollisions(state, before, options.rng);
      for (const ship of state.ships) if (ship.entangledWith) ship.forceTurnOnly = true;
      return result;
    };
    Core.collisionGuard = api;
    Core.__collisionGuardInstalled = true;
    installed = true;
    return true;
  }

  const api = {
    SAMPLE_STEPS,
    BOW_MOMENTUM_RETENTION,
    CENTER_MOMENTUM_RETENTION,
    STERN_MOMENTUM_RETENTION,
    EXACT_REAR_MOMENTUM_RETENTION,
    EXACT_REAR_TOLERANCE_DEG,
    BASE_RUDDER_DAMAGE_CHANCE_STERN_COLLISION,
    MAX_RUDDER_DAMAGE_CHANCE_STERN_COLLISION,
    CRITICAL_MAST_HEALTH_RATIO,
    COLLISION_CRITICAL_MAST_FALL_CHANCE,
    COLLISION_ENTANGLE_CHANCE,
    CUT_PARTY_SUCCESS_CHANCE,
    interpolatePose,
    collisionPointsAtPose,
    poseCollision,
    detectSweptCollision,
    sternAlignment,
    collisionMomentumRetention,
    sternRudderDamageChance,
    mastForSection,
    damageCollisionMast,
    linkEntanglement,
    clearEntanglementPair,
    resolveCutParty,
    applyCollisionConsequences,
    enforceSweptCollisions,
    install
  };

  return api;
});