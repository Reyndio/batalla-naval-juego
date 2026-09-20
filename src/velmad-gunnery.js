(function (root, factory) {
  const Core = root && root.Pilot2v2Core ? root.Pilot2v2Core : (typeof require !== 'undefined' ? require('./pilot2v2-core.js') : null);
  const api = factory(root, Core);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.VelmadGunnery = api;
})(typeof window !== 'undefined' ? window : globalThis, function (root, Core) {
  'use strict';

  if (!Core) throw new Error('VelmadGunnery requires Pilot2v2Core.');
  if (Core.__velmadGunneryInstalled) return Core.velmadGunnery;

  const baseResolveTurn = Core.resolveTurn;
  const LB_TO_KG = 0.45359237;
  const SHIP_LENGTH_M = 75;
  const DOUBLE_SHOT_RANGE_M = 112;
  const BAR_CHAIN_LONG_RANGE_M = 7 * SHIP_LENGTH_M;
  const HULL_LONG_RANGE_M = 6 * SHIP_LENGTH_M;
  const WIND_ARC_HALF_DEG = 15;
  const RAKE_ARC_DEGREES = 15;
  const STERN_RAKE_MULTIPLIER = 3;
  const BOW_RAKE_MULTIPLIER = 2.5;
  const RUDDER_DAMAGE_CHANCE_RAKE = 0.20;
  const MAST_DAMAGE_CHANCE_RAKE = 0.35;
  const MAST_DAMAGE_BONUS_PERCENT_RAKE = 0.25;
  const CASUALTY_ROUND_HULL_FACTOR = 0.18;
  const CASUALTY_GRAPE_MULTIPLIER = 3;
  const CASUALTY_BOW_RAKE_MULTIPLIER = 1.5;
  const CASUALTY_STERN_RAKE_MULTIPLIER = 2;
  const CASUALTY_MAST_FALL_PERCENT = 0.05;
  const MAST_WEIGHTS = { fore: 0.30, main: 0.45, mizzen: 0.25 };
  const STANDARD_AMMO = ['ROUND_SHOT', 'BAR_CHAIN', 'GRAPE'];
  const ALL_AMMO = [...STANDARD_AMMO, 'DOUBLE_SHOT'];

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function angleDiff(a, b) { let d = normalizeAngle(a - b); if (d > 180) d -= 360; return d; }
  function rngValue(rng) { return (rng || Math.random)(); }
  function activeShip(ship) { return !!ship && !ship.sunk && !ship.sinking && !ship.disabled; }
  function syncRig(ship) {
    ship.rig = Math.max(0, ship.masts.fore.health + ship.masts.main.health + ship.masts.mizzen.health);
    ship.maxRig = ship.masts.fore.max + ship.masts.main.max + ship.masts.mizzen.max;
  }
  function applyCasualties(ship, amount) {
    const n = Math.min(ship.crew, Math.max(0, Math.round(amount)));
    ship.crew -= n;
    return n;
  }
  function mastDamage(ship, amount, rng, bonusDirect) {
    if (amount <= 0) return { fallen: [], applied: 0 };
    const weights = [['fore',0.30],['main',0.45],['mizzen',0.25]];
    let remaining = amount;
    const fallen = [];
    for (let i = 0; i < weights.length; i++) {
      const [key, share] = weights[i];
      const mast = ship.masts[key];
      if (mast.fallen) continue;
      const damage = Math.max(0, Math.round((i === weights.length - 1 ? remaining : amount * share) + (bonusDirect && rngValue(rng) < MAST_DAMAGE_CHANCE_RAKE ? mast.max * MAST_DAMAGE_BONUS_PERCENT_RAKE : 0)));
      remaining -= Math.round(amount * share);
      const was = mast.fallen;
      mast.health = Math.max(0, mast.health - damage);
      if (mast.health <= 0) mast.fallen = true;
      if (!was && mast.fallen) {
        fallen.push(key);
        applyCasualties(ship, ship.initialCrew * CASUALTY_MAST_FALL_PERCENT);
      }
    }
    syncRig(ship);
    Core.updateSpeedEfficiency(ship);
    return { fallen, applied: amount };
  }
  function impactedBand(defender, attacker) {
    const r = normalizeAngle(Core.angleTo(defender, attacker) - defender.heading);
    return r > 0 && r < 180 ? 'ESTRIBOR' : 'BABOR';
  }
  function dismountGuns(ship, band, hullDamage, ammo, rng) {
    if (!band || hullDamage <= 0 || ship.maxHull <= 0) return 0;
    const pct = hullDamage / ship.maxHull * 100;
    if (pct < 1) return 0;
    let lost = Math.floor(pct / 2);
    if (Math.floor(pct) % 2 === 1 && rngValue(rng) < 0.5) lost++;
    if (ammo === 'DOUBLE_SHOT') lost = Math.round(lost * 1.5);
    const key = band === 'BABOR' ? 'portGuns' : 'starboardGuns';
    const actual = Math.min(ship[key], Math.max(0, lost));
    ship[key] -= actual;
    return actual;
  }
  function rakeType(attacker, defender) {
    const rel = normalizeAngle(Core.angleTo(defender, attacker) - defender.heading);
    if (rel <= RAKE_ARC_DEGREES || rel >= 360 - RAKE_ARC_DEGREES) return 'BOW';
    if (rel >= 180 - RAKE_ARC_DEGREES && rel <= 180 + RAKE_ARC_DEGREES) return 'STERN';
    return null;
  }
  function operationalGunFactor(attacker, band) {
    if (!band || attacker.gunsPerSide <= 0) return 0;
    const current = band === 'BABOR' ? attacker.portGuns : attacker.starboardGuns;
    return clamp(current / attacker.gunsPerSide, 0, 1);
  }
  function stableRangeFactor(range) {
    if (range < 100) return 1.5;
    if (range < 250) return 1;
    if (range < 400) return 0.5;
    return 0;
  }

  function ensureAmmoState(ship) {
    if (!ship.loadedAmmoByBand) {
      const seed = ALL_AMMO.includes(ship.loadedAmmo) ? ship.loadedAmmo : 'ROUND_SHOT';
      ship.loadedAmmoByBand = { BABOR: seed, ESTRIBOR: seed };
    }
    if (!ship.nextAmmoByBand) {
      ship.nextAmmoByBand = { BABOR: ship.loadedAmmoByBand.BABOR, ESTRIBOR: ship.loadedAmmoByBand.ESTRIBOR };
    }
    return ship.loadedAmmoByBand;
  }

  function broadsideKgFromFit(ship, predicate) {
    const fit = ship.historical && ship.historical.armament && ship.historical.armament.fit || [];
    return fit.filter(predicate).reduce((sum, p) => sum + (p.count / 2) * p.calibreLb * LB_TO_KG, 0);
  }

  function longGunBroadsideKg(ship) {
    return broadsideKgFromFit(ship, p => {
      if (p.type !== 'long-gun') return false;
      if (ship.hull === 0 && p.deck === 'lower') return false;
      if (ship.sail === 'TV' && p.deck === 'upperworks') return false;
      return true;
    });
  }

  function carronadeBroadsideKg(ship) {
    if (ship.sail === 'TV') return 0;
    return broadsideKgFromFit(ship, p => p.type === 'carronade');
  }

  function carronadeRangeFactor(range) {
    if (range <= 150) return 1;
    if (range <= 225) return 0.5;
    if (range <= 300) return 1 / 3;
    return 0;
  }

  function availableBroadsideKg(ship, range) {
    return longGunBroadsideKg(ship) + carronadeBroadsideKg(ship) * carronadeRangeFactor(range);
  }

  function targetSailRiggingFactor(sail) {
    if (sail === 'TV') return 1.5;
    if (sail === 'PV') return 0.9;
    if (sail === 'NV') return 0.5;
    return 1;
  }

  function windShotPosition(state, attacker, target, windFromDeg) {
    const bearing = Core.angleTo(attacker, target);
    const windFrom = normalizeAngle(windFromDeg == null ? state.windFromDeg : windFromDeg);
    if (Math.abs(angleDiff(bearing, windFrom)) <= WIND_ARC_HALF_DEG) return 'TARGET_WINDWARD';
    if (Math.abs(angleDiff(bearing, windFrom + 180)) <= WIND_ARC_HALF_DEG) return 'TARGET_LEEWARD';
    return 'CROSSWIND';
  }

  function distributeDamage(raw, aim, position) {
    if (position === 'TARGET_WINDWARD') {
      return aim === 'RIGGING'
        ? { hull: 0, rig: raw * 0.90, lost: raw * 0.10 }
        : { hull: raw * 0.60, rig: raw * 0.30, lost: raw * 0.10 };
    }
    if (position === 'TARGET_LEEWARD') {
      return aim === 'RIGGING'
        ? { hull: raw * 0.40, rig: raw * 0.60, lost: 0 }
        : { hull: raw, rig: 0, lost: 0 };
    }
    return aim === 'RIGGING'
      ? { hull: raw * 0.10, rig: raw * 0.90, lost: 0 }
      : { hull: raw * 0.90, rig: raw * 0.10, lost: 0 };
  }

  function ammoPowerModifier(ammo, aim, range) {
    if (ammo === 'ROUND_SHOT') return aim === 'RIGGING' ? 0.5 : 1;
    if (ammo === 'BAR_CHAIN') {
      const base = aim === 'HULL' ? 0.5 : 1;
      return range > BAR_CHAIN_LONG_RANGE_M ? base / 3 : base;
    }
    if (ammo === 'GRAPE') return aim === 'RIGGING' ? 1 / 3 : 0.5;
    if (ammo === 'DOUBLE_SHOT') {
      if (aim === 'RIGGING') return range <= DOUBLE_SHOT_RANGE_M ? 1 / 3 : 1 / 5;
      return 1.25 * (range > DOUBLE_SHOT_RANGE_M ? 1 / 5 : 1);
    }
    return 1;
  }

  function firingEfficiencyAt(ship, fatigueAtFire) {
    const profile = Core.crewQualityProfile(ship);
    let effectiveFatigue = Math.max(0, fatigueAtFire);
    if (ship.sail === 'NV') effectiveFatigue = Math.max(0, effectiveFatigue - 10);
    if (ship.sail === 'TV') effectiveFatigue += 10;
    const steps = Math.floor(effectiveFatigue / 10);
    return Math.max(0, 1 - steps * profile.firingPenaltyPer10);
  }

  function canReloadDoubleShot(ship, band) {
    ensureAmmoState(ship);
    return (band === 'BABOR' || band === 'ESTRIBOR') && ship.loadedAmmoByBand[band] === 'ROUND_SHOT';
  }

  function standardNextAmmo(order) {
    return STANDARD_AMMO.includes(order && order.ammo) ? order.ammo : 'ROUND_SHOT';
  }

  function resolveShotVelmad(state, attacker, rng, context) {
    context = context || {};
    const order = context.order || attacker.order || {};
    if (!order.fire || !activeShip(attacker)) return null;
    ensureAmmoState(attacker);

    if (context.canFireAtStart === false) {
      state.log.push(`${attacker.name}: no puede disparar con ${Math.round(context.fatigueAtFire == null ? attacker.fatigue : context.fatigueAtFire)}% de fatiga (${Core.crewQualityProfile(attacker).label}).`);
      return { fired: false, blockedByFatigue: true };
    }

    const target = state.ships.find(s => s.id === order.targetId && activeShip(s) && s.side !== attacker.side);
    if (!target) {
      state.log.push(`${attacker.name}: disparo cancelado; objetivo no disponible.`);
      return { fired: false };
    }
    const d = Core.distance(attacker, target);
    const arc = Core.broadsideArcFactor(attacker, target);
    const rf = stableRangeFactor(d);
    if (!arc.factor || !rf) {
      state.log.push(`${attacker.name}: sin solución de tiro sobre ${target.name} (${Math.round(d)} m).`);
      return { fired: false };
    }
    const requestedBand = order.fireBand || 'AUTO';
    if (requestedBand !== 'AUTO' && requestedBand !== arc.band) {
      state.log.push(`${attacker.name}: orden de ${requestedBand.toLowerCase()} sin arco sobre ${target.name}.`);
      return { fired: false };
    }
    const band = arc.band;
    if (context.doubleReloadBand === band) {
      state.log.push(`${attacker.name}: ${band.toLowerCase()} no dispara mientras recarga doble bala.`);
      return { fired: false, blockedByDoubleReload: true };
    }

    const requestedSection = order.fireSection || 'AUTO';
    let sectionFactor = arc.factor;
    if (requestedSection === 'COMPLETA' && arc.section !== 'COMPLETA') return { fired: false };
    if (requestedSection === 'PROA' || requestedSection === 'POPA') {
      if (arc.section === 'COMPLETA') sectionFactor = 0.5;
      else if (arc.section !== requestedSection) return { fired: false };
    }
    const gunFactor = operationalGunFactor(attacker, band);
    if (gunFactor <= 0) return { fired: false };

    const ammo = attacker.loadedAmmoByBand[band] || 'ROUND_SHOT';
    const orderedAim = order.aim || 'HULL';
    const effectiveAim = d <= DOUBLE_SHOT_RANGE_M ? 'HULL' : orderedAim;
    const position = windShotPosition(state, attacker, target, context.windFromDeg);
    const spread = 0.86 + rngValue(rng) * 0.28;
    const fatigueAtFire = context.fatigueAtFire == null ? attacker.fatigue : context.fatigueAtFire;
    const powerKg = availableBroadsideKg(attacker, d);
    let raw = powerKg * 0.38 * sectionFactor * rf * spread * gunFactor * firingEfficiencyAt(attacker, fatigueAtFire);
    raw *= ammoPowerModifier(ammo, effectiveAim, d);

    if (effectiveAim === 'HULL' && d > HULL_LONG_RANGE_M) raw *= 0.5;

    const rake = rakeType(attacker, target);
    if (rake === 'STERN') raw *= STERN_RAKE_MULTIPLIER;
    else if (rake === 'BOW') raw *= BOW_RAKE_MULTIPLIER;

    const allocation = distributeDamage(raw, effectiveAim, position);
    let hullDamage = Math.round(allocation.hull);
    let rigDamage = Math.round(allocation.rig * targetSailRiggingFactor(target.sail));

    const prevHull = target.hull;
    target.hull = Math.max(0, target.hull - hullDamage);
    const realHullDamage = Math.max(0, prevHull - target.hull);
    let fallen = [];
    if (rigDamage > 0) fallen = mastDamage(target, rigDamage, rng, !!rake).fallen;
    else Core.updateSpeedEfficiency(target);

    const bandHit = impactedBand(target, attacker);
    const gunsLost = dismountGuns(target, bandHit, realHullDamage, ammo, rng);

    let casualties = realHullDamage * CASUALTY_ROUND_HULL_FACTOR;
    if (ammo === 'GRAPE') casualties *= CASUALTY_GRAPE_MULTIPLIER;
    if (ammo === 'DOUBLE_SHOT') casualties *= 2;
    if (rake === 'BOW') casualties *= CASUALTY_BOW_RAKE_MULTIPLIER;
    if (rake === 'STERN') casualties *= CASUALTY_STERN_RAKE_MULTIPLIER;
    casualties = applyCasualties(target, casualties);

    if (rake === 'STERN' && effectiveAim === 'HULL' && !target.rudderDamaged && rngValue(rng) < RUDDER_DAMAGE_CHANCE_RAKE) {
      target.rudderDamaged = true;
      state.log.push(`¡Timón del ${target.name} dañado por barrido de popa!`);
    }
    Core.updateSpeedEfficiency(target);
    attacker.lastTargetId = target.id;

    const nextAmmo = standardNextAmmo(order);
    attacker.nextAmmoByBand[band] = nextAmmo;
    attacker.loadedAmmoByBand[band] = nextAmmo;
    attacker.nextAmmo = nextAmmo;
    attacker.loadedAmmo = nextAmmo;

    const ammoLabel = ammo === 'DOUBLE_SHOT' ? 'doble bala' : ammo === 'GRAPE' ? 'metralla' : ammo === 'BAR_CHAIN' ? 'palanqueta/cadena' : 'bala redonda';
    const rakeLabel = rake ? ` · barrido ${rake === 'STERN' ? 'de popa' : 'de proa'}` : '';
    const windLabel = position === 'TARGET_WINDWARD' ? ' · objetivo a barlovento' : position === 'TARGET_LEEWARD' ? ' · objetivo a sotavento' : '';
    const forcedAimLabel = orderedAim !== effectiveAim ? ' · ≤112 m: tiro forzado al casco' : '';
    state.log.push(`${attacker.name} dispara ${band} (${arc.section}) con ${ammoLabel} sobre ${target.name} a ${Math.round(d)} m${rakeLabel}${windLabel}${forcedAimLabel}: casco -${realHullDamage}, aparejo -${rigDamage}, cañones ${bandHit.toLowerCase()} -${gunsLost}, bajas ${casualties}${fallen.length ? `, mástiles caídos ${fallen.join('/')}` : ''}.`);
    if (target.hull === 0) state.log.push(`${target.name} queda en CASCO 0: continúa operativo con restricciones Velmad.`);

    return {
      fired: true, band, ammo, orderedAim, effectiveAim, position, range: d,
      hullDamage: realHullDamage, rigDamage, casualties, gunsLost, rake, fallen,
      powerKg, carronadeFactor: carronadeRangeFactor(d), nextAmmo
    };
  }

  function snapshotOrdersAndPrepareAI(state, autoSides) {
    for (const ship of state.ships) {
      ensureAmmoState(ship);
      if (activeShip(ship) && autoSides.includes(ship.side)) ship.order = Core.planAIOrder(state, ship);
    }
    return new Map(state.ships.map(ship => [ship.id, {
      order: ship.order ? JSON.parse(JSON.stringify(ship.order)) : null,
      fatigueAtFire: ship.fatigue,
      canFireAtStart: Core.canShipFire(ship),
      loadedAmmo: ship.loadedAmmo,
      nextAmmo: ship.nextAmmo,
      loadedAmmoByBand: { ...ship.loadedAmmoByBand },
      nextAmmoByBand: { ...ship.nextAmmoByBand }
    }]));
  }

  function prepareDoubleReloads(state, snapshots) {
    const valid = new Map();
    for (const ship of state.ships) {
      const snap = snapshots.get(ship.id);
      const order = snap && snap.order || {};
      const band = order.reloadDoubleShotBand || (order.reloadDoubleShot ? order.fireBand : null);
      const ok = !!band && canReloadDoubleShot(ship, band);
      valid.set(ship.id, ok ? band : null);
      if (ship.order) {
        ship.order.reloadDoubleShot = !!ok;
        ship.order.reloadDoubleShotBand = ok ? band : null;
        ship.order.fire = false;
      }
      if ((order.reloadDoubleShot || order.reloadDoubleShotBand) && !ok) {
        state.log.push(`${ship.name}: no puede recargar doble bala; la banda debe tener bala redonda ya cargada.`);
      }
    }
    return valid;
  }

  function restoreAmmoAfterBase(state, snapshots) {
    for (const ship of state.ships) {
      const snap = snapshots.get(ship.id);
      if (!snap) continue;
      ship.loadedAmmo = snap.loadedAmmo;
      ship.nextAmmo = snap.nextAmmo;
      ship.loadedAmmoByBand = { ...snap.loadedAmmoByBand };
      ship.nextAmmoByBand = { ...snap.nextAmmoByBand };
    }
  }

  function chargeBroadsideFatigue(ship, preFatigue, cost) {
    if (!cost) return;
    if (ship.fatigue < preFatigue) ship.fatigue = preFatigue + cost;
    else ship.fatigue += cost;
  }

  function resolveTurnVelmad(state, options) {
    options = options || {};
    const rng = options.rng || Math.random;
    const autoSides = options.autoSides || [Core.SIDE_REAL_ARMADA];
    if (state.result) return state;

    const windAtFire = state.windFromDeg;
    const snapshots = snapshotOrdersAndPrepareAI(state, autoSides);
    const doubleReloadBands = prepareDoubleReloads(state, snapshots);

    const nextTurnMarker = `--- INICIO TURNO ${state.turn + 1} ---`;
    const result = baseResolveTurn(state, { ...options, rng, autoSides: [] });
    restoreAmmoAfterBase(state, snapshots);

    if (state.log[state.log.length - 1] === nextTurnMarker) state.log.pop();

    for (const ship of state.ships) {
      const snap = snapshots.get(ship.id);
      if (!snap || !snap.order || !activeShip(ship)) continue;
      const shot = resolveShotVelmad(state, ship, rng, {
        order: snap.order,
        fatigueAtFire: snap.fatigueAtFire,
        canFireAtStart: snap.canFireAtStart,
        doubleReloadBand: doubleReloadBands.get(ship.id),
        windFromDeg: windAtFire
      });
      if (shot && shot.fired) chargeBroadsideFatigue(ship, snap.fatigueAtFire, Core.FATIGUE_ONE_BROADSIDE);
    }

    for (const ship of state.ships) {
      const snap = snapshots.get(ship.id);
      const band = doubleReloadBands.get(ship.id);
      if (!snap || !band || !activeShip(ship)) continue;
      ship.loadedAmmoByBand[band] = 'DOUBLE_SHOT';
      ship.nextAmmoByBand[band] = 'DOUBLE_SHOT';
      ship.loadedAmmo = 'DOUBLE_SHOT';
      ship.nextAmmo = 'DOUBLE_SHOT';
      state.log.push(`${ship.name}: ${band.toLowerCase()} queda cargada con doble bala; no disparó esa banda durante la recarga.`);
    }

    Core.evaluateResult(state);
    if (!state.result) {
      state.log.push(nextTurnMarker);
      for (const ship of state.ships) if (activeShip(ship) && autoSides.includes(ship.side)) ship.order = Core.planAIOrder(state, ship);
    }

    for (const ship of state.ships) {
      const snap = snapshots.get(ship.id);
      if (!snap || !snap.order) continue;
      if (!autoSides.includes(ship.side)) {
        ship.order = { ...snap.order, fire: false, reloadDoubleShot: false, reloadDoubleShotBand: null };
      }
      ship.confirmed = false;
    }
    return result;
  }

  function installGunneryUi() {
    if (!root || !root.document) return;
    const doc = root.document;
    const ammo = doc.getElementById('ammoSelect');
    if (ammo) {
      let bar = Array.from(ammo.options).find(o => o.value === 'BAR_CHAIN');
      if (!bar) {
        bar = doc.createElement('option');
        bar.value = 'BAR_CHAIN';
        bar.textContent = 'Palanqueta / cadena';
        const grape = Array.from(ammo.options).find(o => o.value === 'GRAPE');
        ammo.insertBefore(bar, grape || null);
      }
      Array.from(ammo.options).filter(o => o.value === 'DOUBLE_SHOT').forEach(o => o.remove());
      if (ammo.previousElementSibling) ammo.previousElementSibling.textContent = 'Munición a cargar tras disparar esta banda';
    }

    const panel = doc.getElementById('leftPanel');
    if (!panel || doc.getElementById('velmadGunneryActions')) return;
    const box = doc.createElement('section');
    box.id = 'velmadGunneryActions';
    box.innerHTML = '<h3>Artillería Velmad</h3><div id="ammoBandStatus" class="small">Cargas: —</div><label for="doubleReloadBand">Recargar doble bala (+10% fatiga)</label><div class="two-col"><select id="doubleReloadBand"><option value="BABOR">Babor</option><option value="ESTRIBOR">Estribor</option></select><button id="doubleReloadAction">Recargar</button></div><div class="small" style="margin-top:4px">Requiere bala redonda ya cargada. Esa banda no puede disparar durante la recarga.</div>';
    panel.appendChild(box);
    const status = box.querySelector('#ammoBandStatus');
    const button = box.querySelector('#doubleReloadAction');
    const bandSelect = box.querySelector('#doubleReloadBand');

    function selected() {
      const select = doc.getElementById('shipSelect');
      return root.Pilot2v2Core && root.Pilot2v2Core.__browserStateRef && select ? root.Pilot2v2Core.__browserStateRef.ships.find(s => s.id === select.value) : null;
    }

    function currentStateShip() {
      const select = doc.getElementById('shipSelect');
      const state = root.__pilot2v2State || null;
      if (state && select) return state.ships.find(s => s.id === select.value);
      return selected();
    }

    function refresh() {
      const ship = currentStateShip();
      if (!ship) { status.textContent = 'Cargas: —'; button.disabled = true; return; }
      ensureAmmoState(ship);
      status.textContent = `Babor: ${ammoLabel(ship.loadedAmmoByBand.BABOR)} · Estribor: ${ammoLabel(ship.loadedAmmoByBand.ESTRIBOR)}`;
      button.disabled = !canReloadDoubleShot(ship, bandSelect.value) || !!ship.confirmed;
    }

    function ammoLabel(v) {
      return v === 'DOUBLE_SHOT' ? 'doble bala' : v === 'GRAPE' ? 'metralla' : v === 'BAR_CHAIN' ? 'palanqueta/cadena' : 'bala redonda';
    }

    button.addEventListener('click', () => {
      const select = doc.getElementById('shipSelect');
      const ship = currentStateShip();
      if (!ship || !canReloadDoubleShot(ship, bandSelect.value)) return;
      ship.order.reloadDoubleShot = true;
      ship.order.reloadDoubleShotBand = bandSelect.value;
      if (ship.order.fire && ship.order.fireBand === bandSelect.value) ship.order.fire = false;
      ship.confirmed = false;
      if (select) select.dispatchEvent(new Event('change', { bubbles: true }));
      refresh();
    });
    bandSelect.addEventListener('change', refresh);
    doc.getElementById('shipSelect')?.addEventListener('change', () => setTimeout(refresh, 0));
    setInterval(refresh, 800);
    refresh();
  }

  const api = {
    SHIP_LENGTH_M, DOUBLE_SHOT_RANGE_M, BAR_CHAIN_LONG_RANGE_M, HULL_LONG_RANGE_M, WIND_ARC_HALF_DEG,
    STANDARD_AMMO, ALL_AMMO, ensureAmmoState, longGunBroadsideKg, carronadeBroadsideKg, carronadeRangeFactor,
    availableBroadsideKg, targetSailRiggingFactor, windShotPosition, distributeDamage, ammoPowerModifier,
    firingEfficiencyAt, canReloadDoubleShot, resolveShotVelmad, resolveTurnVelmad
  };

  Core.resolveShot = resolveShotVelmad;
  Core.resolveTurn = resolveTurnVelmad;
  Core.ensureAmmoState = ensureAmmoState;
  Core.carronadeBroadsideKg = carronadeBroadsideKg;
  Core.carronadeRangeFactor = carronadeRangeFactor;
  Core.availableBroadsideKg = availableBroadsideKg;
  Core.targetSailRiggingFactor = targetSailRiggingFactor;
  Core.windShotPosition = windShotPosition;
  Core.ammoPowerModifier = ammoPowerModifier;
  Core.canReloadDoubleShot = canReloadDoubleShot;
  Core.velmadGunnery = api;
  Core.__velmadGunneryInstalled = true;

  if (root && root.document) setTimeout(installGunneryUi, 0);
  return api;
});
