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
  const BASE_RUDDER_DAMAGE_CHANCE_STERN_COLLISION = 0.25;
  const RUDDER_DAMAGE_BONUS_PER_SAIL_DIFFERENCE = 0.25;
  const MAX_RUDDER_DAMAGE_CHANCE_STERN_COLLISION = 0.75;
  const SAIL_ORDER = ['NV', 'PV', 'MV', 'TV'];

  let installed = false;

  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function angleDelta(from, to) { let d = normalizeAngle(to - from); if (d > 180) d -= 360; return d; }
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

  function sailIndex(sail) { return Math.max(0, SAIL_ORDER.indexOf(sail)); }

  function damageRig(ship, amount) {
    if (!amount || !ship.masts) return;
    const standing = ['fore', 'main', 'mizzen'].filter(k => ship.masts[k] && !ship.masts[k].fallen && ship.masts[k].health > 0);
    if (!standing.length) return;
    let remaining = Math.max(0, Math.round(amount));
    for (let i = 0; i < standing.length; i++) {
      const key = standing[i];
      const mast = ship.masts[key];
      const share = i === standing.length - 1 ? remaining : Math.max(1, Math.round(amount / standing.length));
      remaining = Math.max(0, remaining - share);
      mast.health = Math.max(0, mast.health - share);
      if (mast.health <= 0) mast.fallen = true;
    }
  }

  function applyCollisionConsequences(state, ship, ownType, other, rng) {
    const speedA = Core && Core.SAIL_SPEED ? (Core.SAIL_SPEED[ship.effectiveSail || ship.sail] || 0) : 0;
    const speedB = Core && Core.SAIL_SPEED ? (Core.SAIL_SPEED[other.effectiveSail || other.sail] || 0) : 0;
    const impact = BASE_COLLISION_DAMAGE + Math.round((speedA + speedB) * 0.35);
    const hullBefore = ship.hull;
    ship.hull = Math.max(0, ship.hull - impact);
    damageRig(ship, Math.round(impact * RIGGING_DAMAGE_COLLISION_FACTOR));
    const casualties = Math.min(ship.crew, Math.max(0, Math.round(impact * CASUALTY_COLLISION_FACTOR)));
    ship.crew -= casualties;

    if (ownType === 'STERN' && !ship.rudderDamaged) {
      const diff = Math.abs(sailIndex(ship.effectiveSail || ship.sail) - sailIndex(other.effectiveSail || other.sail));
      const chance = Math.min(MAX_RUDDER_DAMAGE_CHANCE_STERN_COLLISION, BASE_RUDDER_DAMAGE_CHANCE_STERN_COLLISION + diff * RUDDER_DAMAGE_BONUS_PER_SAIL_DIFFERENCE);
      const roll = (rng || Math.random)();
      if (roll < chance) ship.rudderDamaged = true;
    }

    ship.collidedThisTurn = true;
    const fatigue = Core && Core.collisionFatigueCost ? Core.collisionFatigueCost(ship.effectiveSail || ship.sail) : 0;
    ship.fatigue = Math.max(0, ship.fatigue + fatigue);
    if (Core && Core.updateSpeedEfficiency) Core.updateSpeedEfficiency(ship);
    if (state && state.log) {
      state.log.push(`Colisión durante el movimiento: ${ship.name} (${ownType}) casco -${hullBefore - ship.hull}, fatiga +${fatigue}%, bajas ${casualties}${ship.rudderDamaged ? ', timón comprometido' : ''}.`);
    }
    return { impact, casualties, fatigue };
  }

  function capturePoses(state) {
    return new Map(state.ships.map(s => [s.id, { x: s.x, y: s.y, heading: s.heading }]));
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
        applyCollisionConsequences(state, a, hit.a, b, rng);
        applyCollisionConsequences(state, b, hit.b, a, rng);
        handled.add(key);
      }
    }
    return handled.size;
  }

  function install() {
    if (installed || !Core || typeof Core.resolveTurn !== 'function') return false;
    const baseResolveTurn = Core.resolveTurn;
    Core.resolveTurn = function (state, options) {
      const before = capturePoses(state);
      const result = baseResolveTurn.call(Core, state, options);
      enforceSweptCollisions(state, before, options && options.rng);
      return result;
    };
    installed = true;
    return true;
  }

  return {
    SAMPLE_STEPS,
    interpolatePose,
    collisionPointsAtPose,
    poseCollision,
    detectSweptCollision,
    damageRig,
    applyCollisionConsequences,
    enforceSweptCollisions,
    install
  };
});
