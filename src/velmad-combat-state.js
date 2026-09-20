(function (root, factory) {
  const Core = root && root.Pilot2v2Core ? root.Pilot2v2Core : (typeof require !== 'undefined' ? require('./pilot2v2-core.js') : null);
  if (typeof require !== 'undefined' && Core && !Core.__velmadGunneryInstalled) require('./velmad-gunnery.js');
  const api = factory(root, Core);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.VelmadCombatState = api;
})(typeof window !== 'undefined' ? window : globalThis, function (root, Core) {
  'use strict';

  if (!Core) throw new Error('VelmadCombatState requires Pilot2v2Core.');
  if (Core.__velmadCombatStateInstalled) return Core.velmadCombatState;

  const baseBuildInitialState = Core.buildInitialState;
  const baseStartBattle = Core.startBattle;
  const baseResolveTurn = Core.resolveTurn;

  const STABLE_PROTOTYPE_HULL = 2400;
  const DEFAULT_INITIAL_MORALE = 11; // Minimum integer consistent with intact initial morale > recovery ceiling 10. Project reconstruction.
  const MORALE_RECOVERY_CEILING = 10;
  const BOARDING_DISTANCE_M = 75; // One Velmad rules ship-length. Project reconstruction of the manual's undefined "close enough".
  const WHITE_FLAG_TURNS = 1;
  const SURRENDER_HULL = 1000;
  const CAPTAIN_HIT_SURRENDER_HULL = 1500;
  const RECAPTURE_DISTANCE_M = 525;
  const CRITICAL_RANGE_M = 300;
  const CRITICAL_BASE_CHANCE = 0.01;
  const CRITICAL_HULL_ZERO_ONE_MULTIPLIER = 10;
  const FULL_SAIL_FIRE_CHANCE = 0.20;
  const SHIP_LENGTH_M = 75;
  const RAKE_RANGE_M = 2 * SHIP_LENGTH_M;
  const QUALITY_ORDER = ['NOVATA', 'NORMAL', 'VETERANA', 'ELITE'];
  const PRIZE_CREW = { 1: 50, 2: 40, 3: 30, 4: 20, 5: 10, 6: 10 };

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function rngValue(rng) { return (rng || Math.random)(); }
  function d10(rng) { return 1 + Math.floor(clamp(rngValue(rng), 0, 0.999999999) * 10); }
  function activeForCombat(ship) { return !!ship && !ship.sunk && !ship.sinking && !ship.disabled && !ship.surrendered && !ship.captured; }
  function standingMasts(ship) { return Object.entries(ship.masts || {}).filter(([, m]) => m && !m.fallen); }
  function fallenMasts(ship) { return Object.entries(ship.masts || {}).filter(([, m]) => m && m.fallen).map(([k]) => k); }
  function log(state, text) { if (state && Array.isArray(state.log)) state.log.push(text); }

  function ensureCombatState(ship) {
    if (ship.maxHull < STABLE_PROTOTYPE_HULL && ship.hull === ship.maxHull) ship.hull = STABLE_PROTOTYPE_HULL;
    if (ship.maxHull < STABLE_PROTOTYPE_HULL) ship.maxHull = STABLE_PROTOTYPE_HULL;
    if (!Number.isFinite(ship.initialMorale)) ship.initialMorale = DEFAULT_INITIAL_MORALE;
    if (!Number.isFinite(ship.morale)) ship.morale = ship.initialMorale;
    if (!Number.isFinite(ship.lowestMorale)) ship.lowestMorale = ship.morale;
    if (!Number.isFinite(ship.fireLevel)) ship.fireLevel = 0;
    if (!Number.isFinite(ship.whiteFlagTurns)) ship.whiteFlagTurns = 0;
    if (!Number.isFinite(ship.prizeCrew)) ship.prizeCrew = 0;
    if (!Number.isFinite(ship.battleCasualties)) ship.battleCasualties = Math.max(0, (ship.initialCrew || ship.crew) - ship.crew);
    if (ship.surrendered == null) ship.surrendered = false;
    if (ship.exploded == null) ship.exploded = false;
    if (ship.originalSide == null) ship.originalSide = ship.side;
    if (ship.capturedBySide == null) ship.capturedBySide = null;
    if (ship.controllerSide == null) ship.controllerSide = ship.side;
    if (ship.captainHit == null) ship.captainHit = false;
    if (ship.captainKilled == null) ship.captainKilled = false;
    if (ship.order) {
      if (ship.order.boardTargetId == null) ship.order.boardTargetId = null;
      if (ship.order.fireFighting == null) ship.order.fireFighting = false;
    }
    return ship;
  }

  function ensureState(state) {
    for (const ship of state.ships || []) ensureCombatState(ship);
    if (!Array.isArray(state.velmadEvents)) state.velmadEvents = [];
    if (!Number.isFinite(state.velmadTurnMinutes)) state.velmadTurnMinutes = 5;
    if (!Number.isFinite(state.velmadRulesShipLengthM)) state.velmadRulesShipLengthM = SHIP_LENGTH_M;
    return state;
  }

  function resetCombatState(state) {
    ensureState(state);
    for (const ship of state.ships) {
      ship.maxHull = STABLE_PROTOTYPE_HULL;
      ship.hull = STABLE_PROTOTYPE_HULL;
      ship.initialMorale = DEFAULT_INITIAL_MORALE;
      ship.morale = DEFAULT_INITIAL_MORALE;
      ship.lowestMorale = DEFAULT_INITIAL_MORALE;
      ship.fireLevel = 0;
      ship.whiteFlagTurns = 0;
      ship.prizeCrew = 0;
      ship.battleCasualties = 0;
      ship.surrendered = false;
      ship.exploded = false;
      ship.originalSide = ship.side;
      ship.controllerSide = ship.side;
      ship.capturedBySide = null;
      ship.captainHit = false;
      ship.captainKilled = false;
      ship.captured = false;
      if (ship.order) {
        ship.order.boardTargetId = null;
        ship.order.fireFighting = false;
      }
      Core.updateSpeedEfficiency(ship);
    }
    state.velmadEvents = [];
    return state;
  }

  function applyMoraleLoss(ship, points, reason, state) {
    if (!points || points <= 0 || ship.sunk) return 0;
    const before = ship.morale;
    ship.morale = Math.max(0, ship.morale - points);
    ship.lowestMorale = Math.min(ship.lowestMorale, ship.morale);
    const actual = before - ship.morale;
    if (actual > 0) {
      log(state, `${ship.name}: moral -${actual} (${reason}); queda en ${ship.morale}.`);
      state.velmadEvents.push({ type: 'morale-loss', shipId: ship.id, points: actual, reason });
    }
    return actual;
  }

  function canRecoverMorale(ship) {
    return ship.initialMorale - ship.lowestMorale >= 3 && ship.morale < MORALE_RECOVERY_CEILING;
  }

  function recoverMorale(ship, reason, state) {
    if (!canRecoverMorale(ship)) return false;
    ship.morale = Math.min(MORALE_RECOVERY_CEILING, ship.morale + 1);
    log(state, `${ship.name}: moral +1 (${reason}); queda en ${ship.morale}.`);
    state.velmadEvents.push({ type: 'morale-recovery', shipId: ship.id, points: 1, reason });
    return true;
  }

  function parseShotLog(line, state, snapshots) {
    if (typeof line !== 'string' || !line.includes(' dispara ') || !line.includes(': casco -')) return null;
    const attacker = state.ships.find(s => line.startsWith(`${s.name} dispara `));
    if (!attacker) return null;
    const snap = snapshots.get(attacker.id);
    if (!snap || !snap.order || !snap.order.targetId) return null;
    const target = state.ships.find(s => s.id === snap.order.targetId);
    if (!target) return null;
    const bandMatch = line.match(/ dispara (BABOR|ESTRIBOR) /);
    const dmgMatch = line.match(/: casco -(\d+), aparejo -(\d+), cañones .*? -(\d+), bajas (\d+)/);
    if (!bandMatch || !dmgMatch) return null;
    const band = bandMatch[1];
    const ammo = snap.loadedAmmoByBand && snap.loadedAmmoByBand[band] || snap.loadedAmmo || 'ROUND_SHOT';
    const range = Core.distance(attacker, target);
    const effectiveAim = range <= 112 ? 'HULL' : (snap.order.aim || 'HULL');
    const rake = rakeType(attacker, target);
    const fallenNow = fallenMasts(target);
    const fallenBefore = snap.targetFallenById && snap.targetFallenById[target.id] || [];
    const newFallen = fallenNow.filter(k => !fallenBefore.includes(k));
    return {
      attackerId: attacker.id,
      targetId: target.id,
      band,
      ammo,
      range,
      effectiveAim,
      rake,
      hullDamage: Number(dmgMatch[1]),
      rigDamage: Number(dmgMatch[2]),
      gunsLost: Number(dmgMatch[3]),
      casualties: Number(dmgMatch[4]),
      newFallen,
      totalDamage: Number(dmgMatch[1]) + Number(dmgMatch[2])
    };
  }

  function rakeType(attacker, defender) {
    const rel = ((Core.angleTo(defender, attacker) - defender.heading) % 360 + 360) % 360;
    if (rel <= 15 || rel >= 345) return 'BOW';
    if (rel >= 165 && rel <= 195) return 'STERN';
    return null;
  }

  function applyShotMorale(state, shot) {
    const attacker = state.ships.find(s => s.id === shot.attackerId);
    const target = state.ships.find(s => s.id === shot.targetId);
    if (!attacker || !target) return;
    let recovered = false;

    if (shot.range < RAKE_RANGE_M && shot.rake && shot.totalDamage >= 75) {
      const full = shot.rake === 'STERN' ? 4 : 2;
      const loss = shot.totalDamage >= 150 ? full : full / 2;
      applyMoraleLoss(target, loss, `${shot.rake === 'STERN' ? 'barrido de popa' : 'barrido de proa'} a <150 m`, state);
      if (shot.rake === 'STERN') recovered = recoverMorale(attacker, 'barrido de popa a <150 m', state) || recovered;
    }
    for (let i = 0; i < shot.newFallen.length; i++) {
      applyMoraleLoss(target, 3, 'pérdida de mástil', state);
      if (!recovered) recovered = recoverMorale(attacker, 'derribo de mástil enemigo', state) || recovered;
    }
    if (shot.ammo === 'GRAPE' && shot.effectiveAim === 'HULL' && shot.range < RAKE_RANGE_M && shot.hullDamage >= 100) {
      applyMoraleLoss(target, 1, '100+ daños de metralla al casco a <150 m', state);
    }
    if (shot.effectiveAim === 'HULL' && shot.totalDamage >= 500) {
      applyMoraleLoss(target, 1, '500+ daños totales en una andanada al casco', state);
    }
  }

  function heavyMagazineRiskPercent(ship) {
    const fit = ship.historical && ship.historical.armament && ship.historical.armament.fit || [];
    const weighted = fit.reduce((sum, p) => {
      if (p.type !== 'long-gun') return sum;
      if (p.calibreLb > 24) return sum + p.count * 2;
      if (p.calibreLb === 24) return sum + p.count;
      return sum;
    }, 0);
    return clamp(weighted + 1, 0, 100);
  }

  function startFire(ship, state, reason) {
    if (ship.sunk || ship.exploded) return false;
    ship.fireLevel = clamp((ship.fireLevel || 0) + 1, 0, 5);
    log(state, `¡Incendio en ${ship.name}! Nivel ${ship.fireLevel} (${reason}).`);
    state.velmadEvents.push({ type: 'fire-start-or-rise', shipId: ship.id, level: ship.fireLevel, reason });
    if (ship.fireLevel >= 5) abandonInFlames(ship, state);
    return true;
  }

  function explodeShip(ship, state, reason) {
    if (ship.exploded) return;
    ship.exploded = true;
    ship.sunk = true;
    ship.disabled = true;
    ship.sinking = false;
    ship.hull = 0;
    log(state, `¡${ship.name} EXPLOTA! ${reason}`);
    state.velmadEvents.push({ type: 'explosion', shipId: ship.id, reason });
  }

  function abandonInFlames(ship, state) {
    ship.fireLevel = 5;
    ship.disabled = true;
    log(state, `¡${ship.name} está envuelto en llamas! La tripulación abandona el buque; queda fuera de combate.`);
    state.velmadEvents.push({ type: 'ship-in-flames', shipId: ship.id });
  }

  function resolveCritical(state, shot, rng) {
    if (shot.ammo !== 'ROUND_SHOT' || shot.range >= CRITICAL_RANGE_M) return null;
    const target = state.ships.find(s => s.id === shot.targetId);
    if (!target || target.sunk) return null;
    let chance = CRITICAL_BASE_CHANCE;
    if (target.hull <= 1) chance *= CRITICAL_HULL_ZERO_ONE_MULTIPLIER;
    // The v1.2 '<2000 hull ... damage/100' modifier is source-ambiguous and deliberately not guessed here.
    if (rngValue(rng) >= chance) return null;
    const magazinePct = heavyMagazineRiskPercent(target);
    state.velmadEvents.push({ type: 'critical', shipId: target.id, chance, magazinePct });
    log(state, `¡Impacto crítico en ${target.name}! Riesgo de santabárbara: ${magazinePct}%.`);
    if (rngValue(rng) < magazinePct / 100) {
      explodeShip(target, state, 'Impacto crítico en la santabárbara.');
      return { critical: true, magazineExplosion: true, magazinePct };
    }
    startFire(target, state, 'impacto crítico sin explosión de santabárbara');
    return { critical: true, magazineExplosion: false, magazinePct };
  }

  function damageRandomMast(ship, amount, rng, state) {
    const standing = standingMasts(ship);
    if (!standing.length) {
      ship.hull = Math.max(0, ship.hull - amount);
      return { hull: amount, mast: null, fallen: false };
    }
    const [key, mast] = standing[Math.floor(rngValue(rng) * standing.length) % standing.length];
    const wasFallen = mast.fallen;
    mast.health = Math.max(0, mast.health - amount);
    if (mast.health <= 0) mast.fallen = true;
    const fell = !wasFallen && mast.fallen;
    if (fell) applyMoraleLoss(ship, 3, 'pérdida de mástil por incendio', state);
    ship.rig = Math.max(0, Object.values(ship.masts).reduce((sum, m) => sum + m.health, 0));
    Core.updateSpeedEfficiency(ship);
    return { hull: 0, mast: key, fallen: fell };
  }

  function applyFireDamage(ship, state, rng) {
    if (ship.fireLevel === 3) {
      if (rngValue(rng) < 0.5) {
        ship.hull = Math.max(0, ship.hull - 50);
        log(state, `${ship.name}: incendio serio causa 50 puntos al casco.`);
      } else {
        const hit = damageRandomMast(ship, 50, rng, state);
        log(state, `${ship.name}: incendio serio causa 50 puntos ${hit.mast ? `al mástil ${hit.mast}` : 'al casco (sin mástiles restantes)'}.`);
      }
      if (rngValue(rng) < 0.33) explodeShip(ship, state, 'Explosión por incendio serio (33%).');
    } else if (ship.fireLevel === 4) {
      ship.hull = Math.max(0, ship.hull - 100);
      const hit = damageRandomMast(ship, 100, rng, state);
      log(state, `${ship.name}: incendio general causa 100 al casco y 100 ${hit.mast ? `al mástil ${hit.mast}` : 'adicionales al casco por no quedar mástiles'}.`);
      if (!hit.mast) ship.hull = Math.max(0, ship.hull - 100);
      if (rngValue(rng) < 0.66) explodeShip(ship, state, 'Explosión por incendio general (66%).');
    }
    if (ship.hull === 0 && !ship.sunk) Core.updateSpeedEfficiency(ship);
  }

  function processExistingFire(ship, startLevel, order, state, rng) {
    if (!startLevel || ship.sunk || ship.exploded) return;
    ship.fireLevel = startLevel;
    if (order && order.fireFighting) {
      const controlChance = Math.max(0, 0.50 - (startLevel - 1) * 0.10);
      if (rngValue(rng) < controlChance) {
        const busy = !!order.fire || (order.sail && order.sail !== ship.previousSail);
        ship.fireLevel = Math.max(0, startLevel - (busy ? 1 : 2));
        log(state, `${ship.name}: equipo contraincendios controla el fuego; nivel ${startLevel}→${ship.fireLevel}.`);
      } else if (rngValue(rng) < 0.5) {
        ship.fireLevel = Math.min(5, startLevel + 1);
        log(state, `${ship.name}: fracasa el control y el incendio crece a nivel ${ship.fireLevel}.`);
      } else {
        log(state, `${ship.name}: fracasa el control; incendio permanece en nivel ${ship.fireLevel}.`);
      }
    } else {
      ship.fireLevel = Math.min(5, startLevel + 1);
      log(state, `${ship.name}: sin equipo contraincendios, el fuego crece a nivel ${ship.fireLevel}.`);
    }
    if (ship.fireLevel >= 5) { abandonInFlames(ship, state); return; }
    applyFireDamage(ship, state, rng);
  }

  function surrenderShip(ship, captor, state, reason) {
    if (ship.surrendered || ship.sunk || ship.exploded) return false;
    ship.surrendered = true;
    ship.captured = true;
    ship.capturedBySide = captor ? captor.side : null;
    ship.controllerSide = captor ? captor.side : null;
    ship.whiteFlagTurns = WHITE_FLAG_TURNS;
    ship.disabled = true;
    const required = PRIZE_CREW[Core.velmadClassOf(ship)] || 10;
    ship.prizeCrew = required;
    if (captor && captor.crew >= required) {
      captor.crew -= required;
      captor.battleCasualties = Math.max(0, captor.initialCrew - captor.crew);
    }
    log(state, `¡${ship.name} se rinde y larga bandera blanca! ${reason}${captor ? ` · presa de ${captor.name}` : ''}.`);
    state.velmadEvents.push({ type: 'surrender', shipId: ship.id, captorId: captor && captor.id, reason, prizeCrew: required });
    return true;
  }

  function checkSurrenderAfterShot(state, shot, rng) {
    const target = state.ships.find(s => s.id === shot.targetId);
    const attacker = state.ships.find(s => s.id === shot.attackerId);
    if (!target || target.surrendered || target.sunk) return false;
    if (target.morale <= 0) return surrenderShip(target, attacker, state, 'moral 0 al recibir una nueva andanada');
    const threshold = target.captainHit ? CAPTAIN_HIT_SURRENDER_HULL : SURRENDER_HULL;
    if (target.hull <= threshold && shot.range < 300) {
      const roll = d10(rng);
      log(state, `${target.name}: chequeo de rendición d10=${roll} contra moral ${target.morale}.`);
      if (roll > target.morale) return surrenderShip(target, attacker, state, `chequeo de rendición ${roll}>${target.morale}`);
    }
    return false;
  }

  function qualityIndex(ship) {
    const q = String(ship.crewExperience || 'NORMAL').toUpperCase();
    const normalized = q === 'BEGINNER' ? 'NOVATA' : q === 'VETERAN' ? 'VETERANA' : q;
    return Math.max(0, QUALITY_ORDER.indexOf(normalized));
  }

  function deckCount(ship) {
    const rate = String(ship.historical && ship.historical.rate || '').toLowerCase();
    if (rate.includes('four-decker')) return 4;
    if (rate.includes('three-decker')) return 3;
    if (rate.includes('two-decker')) return 2;
    return 1;
  }

  function boardingCasualtyThreshold(ship) {
    const rate = String(ship.historical && ship.historical.rate || '').toLowerCase();
    const cls = Core.velmadClassOf(ship);
    if (cls === 1) return 100;
    if (cls === 2) return 80;
    if (rate.includes('74-gun')) return 60;
    if (rate.includes('two-decker')) return 40;
    if (cls === 5) return 20;
    return 0;
  }

  function boardingEligibility(attacker, defender) {
    if (!activeForCombat(attacker) || !activeForCombat(defender) || attacker.side === defender.side) return { ok: false, reason: 'combatientes no disponibles' };
    if (Core.distance(attacker, defender) > BOARDING_DISTANCE_M) return { ok: false, reason: `más de ${BOARDING_DISTANCE_M} m` };
    const stoppedOrPunished = defender.sail === 'NV' || defender.collidedThisTurn || fallenMasts(defender).length > 0;
    if (!stoppedOrPunished) return { ok: false, reason: 'objetivo no está detenido/recogido ni tiene mástil caído' };
    if (defender.morale >= 10) return { ok: false, reason: 'objetivo aún tiene moral 10 o superior' };
    return { ok: true };
  }

  function resolveBoarding(state, attacker, defender, rng, snapshots) {
    const eligible = boardingEligibility(attacker, defender);
    if (!eligible.ok) {
      log(state, `${attacker.name}: abordaje sobre ${defender.name} cancelado (${eligible.reason}).`);
      return { resolved: false, reason: eligible.reason };
    }
    const aSnap = snapshots.get(attacker.id), dSnap = snapshots.get(defender.id);
    if ((aSnap && aSnap.order && aSnap.order.fire) || (dSnap && dSnap.order && dSnap.order.fire)) {
      const reason = 'el manual no aporta el algoritmo de sirvientes de cañón necesario para calcular hombres libres tras disparar';
      log(state, `${attacker.name}: abordaje no resuelto este turno: ${reason}.`);
      return { resolved: false, sourceOmitted: true, reason };
    }
    const attackerForce = attacker.crew * 2 / 3;
    const defenderForce = Math.max(1, defender.crew * 2 / 3);
    let ratio = attackerForce / defenderForce;
    ratio += (attacker.morale - defender.morale) * 0.075;
    if (attacker.fatigue < defender.fatigue) ratio += 0.075;
    else if (attacker.fatigue > defender.fatigue) ratio -= 0.075;
    ratio += (qualityIndex(attacker) - qualityIndex(defender)) * 0.10;
    const deckDisadvantage = Math.max(0, deckCount(defender) - deckCount(attacker));
    ratio -= deckDisadvantage * 0.10;
    const defenderPreCasualties = Math.max(0, defender.initialCrew - defender.crew);
    const threshold = boardingCasualtyThreshold(defender);
    const tenacious = defenderPreCasualties < threshold;
    if (tenacious) ratio -= 0.075;
    const luck = rngValue(rng) * 0.40 - 0.20;
    ratio += luck;
    const success = ratio > 1;
    state.velmadEvents.push({ type: 'boarding', attackerId: attacker.id, defenderId: defender.id, ratio, luck, success, tenacious, casualtyFormulaOmitted: true });
    log(state, `${attacker.name} aborda ${defender.name}: relación final ${ratio.toFixed(3)} (${success ? 'éxito' : 'rechazado'}). Las bajas de abordaje quedan sin cuantificar porque v1.2 no publica su fórmula base.`);
    if (success) surrenderShip(defender, attacker, state, 'captura por abordaje');
    return { resolved: true, success, ratio, luck, tenacious, casualtyFormulaOmitted: true };
  }

  function processBoardingOrders(state, snapshots, rng) {
    const handled = new Set();
    for (const attacker of state.ships) {
      const snap = snapshots.get(attacker.id);
      const targetId = snap && snap.order && snap.order.boardTargetId;
      if (!targetId || handled.has(attacker.id)) continue;
      const defender = state.ships.find(s => s.id === targetId);
      if (!defender) continue;
      const reverse = snapshots.get(defender.id) && snapshots.get(defender.id).order && snapshots.get(defender.id).order.boardTargetId === attacker.id;
      let boarder = attacker, boarded = defender;
      if (reverse) {
        if (defender.morale > attacker.morale || (defender.morale === attacker.morale && defender.crew > attacker.crew)) {
          boarder = defender; boarded = attacker;
        }
        handled.add(defender.id);
      }
      resolveBoarding(state, boarder, boarded, rng, snapshots);
      handled.add(attacker.id);
    }
  }

  function processRecapture(state) {
    for (const ship of state.ships) {
      if (!ship.captured || !ship.capturedBySide || ship.sunk) continue;
      const captorFriends = state.ships.filter(s => s.id !== ship.id && s.side === ship.capturedBySide && !s.sunk && !s.sinking);
      const nearest = captorFriends.reduce((best, s) => Math.min(best, Core.distance(ship, s)), Infinity);
      if (nearest <= RECAPTURE_DISTANCE_M) continue;
      ship.captured = false;
      ship.surrendered = false;
      ship.capturedBySide = null;
      ship.controllerSide = ship.originalSide;
      ship.fatigue = 120;
      ship.whiteFlagTurns = WHITE_FLAG_TURNS;
      ship.disabled = true;
      ship.prizeCrew = 0;
      log(state, `¡${ship.name} es retomado por su tripulación! Fatiga 120% y bandera blanca durante un turno.`);
      state.velmadEvents.push({ type: 'recapture', shipId: ship.id });
    }
  }

  function processWhiteFlags(state) {
    for (const ship of state.ships) {
      if (ship.whiteFlagTurns > 0) {
        ship.whiteFlagTurns -= 1;
        if (ship.whiteFlagTurns <= 0 && !ship.captured && !ship.surrendered && !ship.sunk) ship.disabled = false;
      }
    }
  }

  function snapshotTurn(state) {
    const allFallen = Object.fromEntries(state.ships.map(s => [s.id, fallenMasts(s)]));
    return new Map(state.ships.map(ship => {
      if (Core.ensureAmmoState) Core.ensureAmmoState(ship);
      return [ship.id, {
        hull: ship.hull,
        crew: ship.crew,
        morale: ship.morale,
        fireLevel: ship.fireLevel,
        order: ship.order ? JSON.parse(JSON.stringify(ship.order)) : null,
        loadedAmmo: ship.loadedAmmo,
        loadedAmmoByBand: ship.loadedAmmoByBand ? { ...ship.loadedAmmoByBand } : null,
        fallen: fallenMasts(ship),
        targetFallenById: allFallen
      }];
    }));
  }

  function resolveTurnCombat(state, options) {
    options = options || {};
    const rng = options.rng || Math.random;
    ensureState(state);
    const snapshots = snapshotTurn(state);
    const priorLogLength = state.log.length;

    // White-flag/captured ships stay disabled before movement/fire.
    for (const ship of state.ships) {
      if (ship.whiteFlagTurns > 0 || ship.captured || ship.surrendered || ship.fireLevel >= 5) ship.disabled = true;
    }

    const result = baseResolveTurn(state, { ...options, rng });
    ensureState(state);

    const newLines = state.log.slice(priorLogLength);
    const shots = [];
    for (const line of newLines) {
      const shot = parseShotLog(line, state, snapshots);
      if (shot) shots.push(shot);
    }
    state.lastVelmadShots = shots;

    for (const shot of shots) {
      applyShotMorale(state, shot);
      resolveCritical(state, shot, rng);
      const attacker = state.ships.find(s => s.id === shot.attackerId);
      if (attacker && attacker.sail === 'TV' && rngValue(rng) < FULL_SAIL_FIRE_CHANCE) startFire(attacker, state, 'disparo a toda vela: riesgo 20%');
      checkSurrenderAfterShot(state, shot, rng);
    }

    for (const ship of state.ships) {
      const snap = snapshots.get(ship.id);
      if (!snap) continue;
      processExistingFire(ship, snap.fireLevel, snap.order, state, rng);
      ship.battleCasualties = Math.max(0, ship.initialCrew - ship.crew);
    }

    processBoardingOrders(state, snapshots, rng);
    processRecapture(state);
    processWhiteFlags(state);

    for (const ship of state.ships) {
      if (ship.order) {
        ship.order.boardTargetId = null;
        ship.order.fireFighting = false;
      }
    }
    Core.evaluateResult(state);
    return result;
  }

  function installCombatUi() {
    if (!root || !root.document) return;
    const doc = root.document;
    const panel = doc.getElementById('leftPanel');
    if (!panel || doc.getElementById('velmadCombatActions')) return;
    const box = doc.createElement('section');
    box.id = 'velmadCombatActions';
    box.innerHTML = '<h3>Moral, fuego y abordaje</h3><div id="velmadCombatStatus" class="small">Moral/fuego: —</div><div class="two-col" style="margin-top:6px"><button id="fireFightingAction">Equipo contraincendios (+10%)</button><button id="boardingAction">Abordar objetivo</button></div><div class="small" style="margin-top:4px">Moral inicial 11 y distancia de abordaje 75 m son reconstrucciones explícitas; las bajas base de abordaje no se inventan porque v1.2 no publica esa fórmula.</div>';
    panel.appendChild(box);
    const status = box.querySelector('#velmadCombatStatus');
    const fireButton = box.querySelector('#fireFightingAction');
    const boardButton = box.querySelector('#boardingAction');

    function stateAndShip() {
      const state = root.__pilot2v2State;
      const select = doc.getElementById('shipSelect');
      const ship = state && select ? state.ships.find(s => s.id === select.value) : null;
      return { state, ship };
    }
    function refresh() {
      const { ship } = stateAndShip();
      if (!ship) { status.textContent = 'Moral/fuego: —'; fireButton.disabled = true; boardButton.disabled = true; return; }
      status.textContent = `Moral ${ship.morale}/${ship.initialMorale} · Fuego ${ship.fireLevel}/5${ship.whiteFlagTurns ? ' · BANDERA BLANCA' : ''}${ship.captured ? ' · CAPTURADO' : ''}`;
      fireButton.disabled = !ship.fireLevel || ship.confirmed || ship.sunk || ship.captured;
      boardButton.disabled = ship.confirmed || ship.sunk || ship.captured;
    }
    fireButton.addEventListener('click', () => {
      const { ship } = stateAndShip();
      if (!ship || !ship.fireLevel || !ship.order) return;
      ship.order.fireFighting = true;
      ship.confirmed = false;
      refresh();
    });
    boardButton.addEventListener('click', () => {
      const { state, ship } = stateAndShip();
      const targetSelect = doc.getElementById('targetSelect');
      if (!state || !ship || !ship.order || !targetSelect || !targetSelect.value) return;
      ship.order.boardTargetId = targetSelect.value;
      ship.confirmed = false;
      refresh();
    });
    doc.getElementById('shipSelect')?.addEventListener('change', () => setTimeout(refresh, 0));
    setInterval(refresh, 800);
    refresh();
  }

  Core.buildInitialState = function (...args) {
    const state = baseBuildInitialState.apply(Core, args);
    return resetCombatState(state);
  };
  Core.startBattle = function (state, ...args) {
    const result = baseStartBattle.call(Core, state, ...args);
    return resetCombatState(result);
  };
  Core.resolveTurn = resolveTurnCombat;
  Core.BASE_HULL = STABLE_PROTOTYPE_HULL;

  const api = {
    STABLE_PROTOTYPE_HULL, DEFAULT_INITIAL_MORALE, MORALE_RECOVERY_CEILING, BOARDING_DISTANCE_M, WHITE_FLAG_TURNS,
    SURRENDER_HULL, CAPTAIN_HIT_SURRENDER_HULL, RECAPTURE_DISTANCE_M, CRITICAL_RANGE_M, CRITICAL_BASE_CHANCE,
    FULL_SAIL_FIRE_CHANCE, SHIP_LENGTH_M, PRIZE_CREW,
    ensureCombatState, ensureState, resetCombatState, applyMoraleLoss, canRecoverMorale, recoverMorale,
    parseShotLog, applyShotMorale, heavyMagazineRiskPercent, startFire, explodeShip, processExistingFire,
    surrenderShip, checkSurrenderAfterShot, boardingEligibility, resolveBoarding, boardingCasualtyThreshold,
    processRecapture, resolveCritical, resolveTurnCombat
  };

  Core.velmadCombatState = api;
  Core.__velmadCombatStateInstalled = true;
  if (root && root.document) setTimeout(installCombatUi, 0);
  return api;
});
