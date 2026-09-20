(function (root, factory) {
  const Core = root && root.Pilot2v2Core
    ? root.Pilot2v2Core
    : (typeof require !== 'undefined' ? require('./pilot2v2-core.js') : null);
  const api = factory(Core);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.InertiaModel = api;
  if (Core) api.install();
})(typeof window !== 'undefined' ? window : globalThis, function (Core) {
  'use strict';

  if (!Core) throw new Error('InertiaModel requires Pilot2v2Core.');

  // Project reconstruction. Lower values mean that the ship retains more of its previous way.
  // Large ships answer changes in driving force more slowly than small craft.
  const RESPONSE_BY_CLASS = {
    1: 0.30,
    2: 0.35,
    3: 0.40,
    4: 0.48,
    5: 0.56,
    6: 0.64
  };
  const COLLISION_MOMENTUM_RETAINED = 0.25;
  const BASE_COLLISION_LENGTH_M = 0;
  const BASE_COLLISION_BEAM_M = 0;

  let installed = false;
  let baseBuildInitialState = null;
  let baseStartBattle = null;
  let baseProjectMovement = null;
  let baseResolveTurn = null;

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function magnitude(v) { return Math.hypot(v.x, v.y); }
  function finiteVector(x, y) {
    return Number.isFinite(x) && Number.isFinite(y) ? { x, y } : null;
  }

  function responseFor(ship) {
    const cls = Core.velmadClassOf ? Core.velmadClassOf(ship) : 3;
    return RESPONSE_BY_CLASS[cls] == null ? RESPONSE_BY_CLASS[3] : RESPONSE_BY_CLASS[cls];
  }

  function retainedMotion(ship, fallback) {
    let old = finiteVector(ship.motionVx, ship.motionVy) || fallback || { x: 0, y: 0 };
    if (ship.collidedThisTurn) {
      old = {
        x: old.x * COLLISION_MOMENTUM_RETAINED,
        y: old.y * COLLISION_MOMENTUM_RETAINED
      };
    }
    return old;
  }

  function blendVelocity(ship, oldVelocity, commandedVelocity) {
    const response = responseFor(ship);
    const next = {
      x: oldVelocity.x + (commandedVelocity.x - oldVelocity.x) * response,
      y: oldVelocity.y + (commandedVelocity.y - oldVelocity.y) * response
    };
    // Linear acceleration/deceleration across the movement phase: travelled distance uses mean velocity.
    const displacement = {
      x: (oldVelocity.x + next.x) * 0.5,
      y: (oldVelocity.y + next.y) * 0.5
    };
    return {
      response,
      oldVelocity,
      commandedVelocity,
      nextVelocity: next,
      displacement,
      oldSpeed: magnitude(oldVelocity),
      commandedSpeed: magnitude(commandedVelocity),
      nextSpeed: magnitude(next),
      movementSpeed: magnitude(displacement)
    };
  }

  function seedShipMotion(state, ship) {
    if (!ship || !baseProjectMovement) return;
    const neutralOrder = {
      ...(ship.order || {}),
      sail: ship.sail,
      rudder: 0,
      fire: false,
      reloadDoubleShot: false,
      fireFighting: false,
      cutMast: false
    };
    const p = baseProjectMovement(state, ship, neutralOrder, { resolveChance: false });
    ship.motionVx = p.x - ship.x;
    ship.motionVy = p.y - ship.y;
    ship.motionSpeed = Math.hypot(ship.motionVx, ship.motionVy);
    ship.motionSeeded = true;
  }

  function seedStateMotion(state) {
    if (!state || !Array.isArray(state.ships)) return state;
    for (const ship of state.ships) seedShipMotion(state, ship);
    return state;
  }

  function inertialProjection(state, ship, order, options) {
    const commanded = baseProjectMovement(state, ship, order, options);
    if (!ship || ship.sunk || ship.sinking || ship.disabled) return commanded;
    const commandVelocity = { x: commanded.x - ship.x, y: commanded.y - ship.y };
    const oldVelocity = retainedMotion(ship, commandVelocity);
    const motion = blendVelocity(ship, oldVelocity, commandVelocity);
    return {
      ...commanded,
      x: clamp(ship.x + motion.displacement.x, 20, Core.WORLD.width - 20),
      y: clamp(ship.y + motion.displacement.y, 20, Core.WORLD.height - 20),
      inertia: motion,
      commandedX: commanded.x,
      commandedY: commanded.y
    };
  }

  function suppressBaseEndpointCollisions(state, fn) {
    const saved = [];
    for (const ship of state.ships || []) {
      const visual = ship && ship.historical && ship.historical.visual;
      if (!visual) continue;
      saved.push([visual, visual.lengthM, visual.beamM]);
      visual.lengthM = BASE_COLLISION_LENGTH_M;
      visual.beamM = BASE_COLLISION_BEAM_M;
    }
    try {
      return fn();
    } finally {
      for (const [visual, lengthM, beamM] of saved) {
        visual.lengthM = lengthM;
        visual.beamM = beamM;
      }
    }
  }

  function resolveTurnWithInertia(state, options) {
    const starts = new Map();
    for (const ship of state.ships || []) {
      const fallback = { x: 0, y: 0 };
      starts.set(ship.id, {
        x: ship.x,
        y: ship.y,
        oldVelocity: retainedMotion(ship, fallback),
        wasActive: !ship.sunk && !ship.sinking && !ship.disabled
      });
    }

    // Endpoint-only collision checks in the inherited resolver are reduced to a near-point check.
    // The swept collision guard, loaded outside this layer, evaluates the real inertial trajectory.
    const result = suppressBaseEndpointCollisions(state, () => baseResolveTurn(state, options));

    for (const ship of state.ships || []) {
      const start = starts.get(ship.id);
      if (!start) continue;
      if (!start.wasActive || ship.sunk || ship.sinking || ship.disabled) {
        ship.motionVx = 0;
        ship.motionVy = 0;
        ship.motionSpeed = 0;
        continue;
      }

      const commandVelocity = { x: ship.x - start.x, y: ship.y - start.y };
      const motion = blendVelocity(ship, start.oldVelocity, commandVelocity);
      ship.x = clamp(start.x + motion.displacement.x, 20, Core.WORLD.width - 20);
      ship.y = clamp(start.y + motion.displacement.y, 20, Core.WORLD.height - 20);
      ship.motionVx = motion.nextVelocity.x;
      ship.motionVy = motion.nextVelocity.y;
      ship.motionSpeed = motion.nextSpeed;
      ship.lastCommandedSpeed = motion.commandedSpeed;
      ship.lastInertialDisplacement = motion.movementSpeed;
    }
    return result;
  }

  function install() {
    if (installed || Core.__inertiaModelInstalled) return false;
    baseBuildInitialState = Core.buildInitialState;
    baseStartBattle = Core.startBattle;
    baseProjectMovement = Core.projectMovement;
    baseResolveTurn = Core.resolveTurn;

    Core.buildInitialState = function (...args) {
      return seedStateMotion(baseBuildInitialState.apply(Core, args));
    };
    Core.startBattle = function (state, ...args) {
      return seedStateMotion(baseStartBattle.call(Core, state, ...args));
    };
    Core.projectMovement = inertialProjection;
    Core.resolveTurn = resolveTurnWithInertia;
    Core.inertiaModel = api;
    Core.__inertiaModelInstalled = true;
    installed = true;
    return true;
  }

  const api = {
    RESPONSE_BY_CLASS,
    COLLISION_MOMENTUM_RETAINED,
    responseFor,
    blendVelocity,
    seedShipMotion,
    seedStateMotion,
    inertialProjection,
    resolveTurnWithInertia,
    install
  };

  return api;
});