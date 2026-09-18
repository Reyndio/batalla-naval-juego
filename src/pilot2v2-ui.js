(async function () {
  'use strict';
  const Core = window.Pilot2v2Core;
  const canvas = document.getElementById('battleCanvas');
  const ctx = canvas.getContext('2d');
  const SAILS = ['NV','PV','MV','TV'];
  const $ = id => document.getElementById(id);
  const deg = v => v * Math.PI / 180;
  const clamp = (v,min,max) => Math.max(min,Math.min(max,v));

  let data;
  let state;
  let selectedShipId = null;
  let rng = Core.seededRng(Date.now() & 0xffffffff);
  let viewW = 1000;
  let viewH = 700;
  const camera = { x: Core.WORLD.width / 2, y: Core.WORLD.height / 2, zoom: 1 };
  let isPanning = false;
  let lastPanX = 0;
  let lastPanY = 0;
  let timerId = null;
  let secondsRemaining = 0;
  let animation = null;
  let isAnimating = false;

  async function loadData() {
    const res = await fetch('data/historical_ships_1805.json');
    if (!res.ok) throw new Error('No se pudo cargar data/historical_ships_1805.json');
    return res.json();
  }

  function shipById(id) { return state.ships.find(s => s.id === id); }
  function selectedShip() { return shipById(selectedShipId); }
  function playerShips() { return state.ships.filter(s => s.side === Core.SIDE_ROYAL_NAVY); }
  function enemyShips() { return state.ships.filter(s => s.side === Core.SIDE_REAL_ARMADA); }
  function livingPlayerShips() { return playerShips().filter(s => !s.sunk); }
  function controlsLocked(s) { return !state.gameStarted || state.paused || isAnimating || !s || s.sunk || s.confirmed; }

  function buildPreparationState() {
    state = Core.buildInitialState(data, { gameStarted: false, windFromDeg: 0, windStrength: 'MEDIA' });
    selectedShipId = playerShips()[0].id;
    for (const s of playerShips()) { s.order.fire = false; s.confirmed = false; }
    secondsRemaining = 0;
    stopTimer();
    fitFleetView();
    syncControlsFromShip();
    renderAll();
  }

  function startBattleFromConfig() {
    const duration = Math.max(10, Number($('turnDurationInput').value) || 60);
    const windStrength = $('windStrengthSetting').value;
    const exp = {
      [Core.SIDE_ROYAL_NAVY]: $('rnCrewExperience').value,
      [Core.SIDE_REAL_ARMADA]: $('raCrewExperience').value
    };
    Core.startBattle(state, { turnDurationSeconds: duration, windStrength, crewExperienceBySide: exp });
    selectedShipId = livingPlayerShips()[0]?.id || selectedShipId;
    fitFleetView();
    syncControlsFromShip();
    renderAll();
    startTurnTimer();
  }

  function stopTimer() {
    if (timerId) clearInterval(timerId);
    timerId = null;
  }

  function startTurnTimer() {
    stopTimer();
    if (!state.gameStarted || state.result) { updateClock(); return; }
    secondsRemaining = state.turnDurationSeconds;
    updateClock();
    timerId = setInterval(() => {
      if (!state.gameStarted || state.result || state.paused || isAnimating) return;
      secondsRemaining = Math.max(0, secondsRemaining - 1);
      updateClock();
      if (secondsRemaining <= 0) resolveTurn('timeout');
    }, 1000);
  }

  function updateClock() {
    if (!state?.gameStarted) { $('turnClock').textContent = 'Tiempo: --:--'; return; }
    const m = Math.floor(secondsRemaining / 60);
    const s = secondsRemaining % 60;
    $('turnClock').textContent = `Tiempo: ${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
  }

  function togglePause() {
    if (!state.gameStarted || state.result || isAnimating) return;
    state.paused = !state.paused;
    state.log.push(state.paused ? 'Juego pausado.' : 'Juego reanudado.');
    renderAll();
  }

  function markOrderChanged() {
    const s = selectedShip();
    if (s) s.confirmed = false;
  }

  function populateSelectors() {
    const shipSelect = $('shipSelect');
    const targetSelect = $('targetSelect');
    shipSelect.innerHTML = '';
    for (const s of playerShips()) {
      const opt = document.createElement('option');
      opt.value = s.id; opt.textContent = s.name + (s.sunk ? ' — fuera de combate' : ''); opt.disabled = s.sunk;
      shipSelect.appendChild(opt);
    }
    shipSelect.value = selectedShipId;
    targetSelect.innerHTML = '';
    for (const s of enemyShips()) {
      const opt = document.createElement('option');
      opt.value = s.id; opt.textContent = s.name + (s.sunk ? ' — fuera de combate' : ''); opt.disabled = s.sunk;
      targetSelect.appendChild(opt);
    }
    const ship = selectedShip();
    const target = ship && ship.order ? shipById(ship.order.targetId) : null;
    if (target && !target.sunk) targetSelect.value = target.id;
    else {
      const fallback = enemyShips().find(s => !s.sunk);
      if (fallback && ship) { ship.order.targetId = fallback.id; targetSelect.value = fallback.id; }
    }
  }

  function syncControlsFromShip() {
    populateSelectors();
    const s = selectedShip(); if (!s) return;
    $('sailSelect').value = s.order.sail;
    $('aimSelect').value = s.order.aim || 'HULL';
    $('fireSectionSelect').value = s.order.fireSection || 'AUTO';
    $('ammoSelect').value = s.order.ammo || s.nextAmmo || 'ROUND_SHOT';
    $('fireSelect').value = s.order.fire ? 'yes' : 'no';
    $('rudderHint').textContent = '';
    updateControlButtonStates();
    updateHistoricalCard();
  }

  function updateControlButtonStates() {
    const s = selectedShip();
    if (!s) return;
    const locked = controlsLocked(s);
    document.querySelectorAll('[data-sail]').forEach(btn => {
      btn.classList.toggle('current', btn.dataset.sail === s.sail);
      btn.classList.toggle('ordered', btn.dataset.sail === s.order.sail);
      const extremeJump = (s.sail === 'NV' && btn.dataset.sail === 'TV') || (s.sail === 'TV' && btn.dataset.sail === 'NV');
      btn.disabled = locked || extremeJump;
    });
    document.querySelectorAll('[data-rudder]').forEach(btn => {
      const v = Number(btn.dataset.rudder);
      btn.classList.toggle('current', v === Number(s.rudder));
      btn.classList.toggle('ordered', v === Number(s.order.rudder));
      btn.disabled = locked || !Core.validateRudderOrder(s, v).valid;
    });
    $('firePort').classList.toggle('fire-active', !!s.order.fire && s.order.fireBand === 'BABOR');
    $('fireStarboard').classList.toggle('fire-active', !!s.order.fire && s.order.fireBand === 'ESTRIBOR');
    for (const id of ['firePort','fireStarboard','cancelFire','targetSelect','aimSelect','fireSectionSelect','ammoSelect']) $(id).disabled = locked;
    $('shipSelect').disabled = !state.gameStarted || state.paused || isAnimating;
    $('confirmOrder').disabled = !state.gameStarted || state.paused || isAnimating || s.sunk;
    $('confirmOrder').classList.toggle('is-confirmed', !!s.confirmed);
    $('confirmOrder').textContent = s.confirmed ? 'Órdenes confirmadas (Q)' : 'Confirmar órdenes (Q)';
    $('resolveTurn').disabled = !canResolveTurn() || state.paused || isAnimating;
    $('pauseBattle').disabled = !state.gameStarted || !!state.result || isAnimating;
    $('pauseBattle').textContent = state.paused ? 'Reanudar (P)' : 'Pausar (P)';
    for (const id of ['turnDurationInput','windStrengthSetting','rnCrewExperience','raCrewExperience','startBattle']) $(id).disabled = state.gameStarted;
    $('prebattleConfig').classList.toggle('locked', state.gameStarted);
  }

  function setSail(value) {
    const s = selectedShip(); if (!s || controlsLocked(s)) return;
    if ((s.sail === 'NV' && value === 'TV') || (s.sail === 'TV' && value === 'NV')) {
      $('mainMessage').textContent = 'No se puede pasar directamente entre NV y TV; el cambio de velamen es progresivo.';
      return;
    }
    s.order.sail = value;
    $('sailSelect').value = value;
    markOrderChanged(); renderAll();
  }

  function setRudder(value) {
    const s = selectedShip(); if (!s || controlsLocked(s)) return;
    const check = Core.validateRudderOrder(s, Number(value));
    if (!check.valid) { $('rudderHint').textContent = check.reason; $('mainMessage').textContent = check.reason; return; }
    s.order.rudder = check.value;
    $('rudderHint').textContent = '';
    markOrderChanged(); renderAll();
  }

  function setFireBand(band) {
    const s = selectedShip(); if (!s || controlsLocked(s)) return;
    if (!band) { s.order.fire = false; s.order.fireBand = 'AUTO'; }
    else { s.order.fire = true; s.order.fireBand = band; }
    $('fireSelect').value = s.order.fire ? 'yes' : 'no';
    markOrderChanged(); renderAll();
  }

  function saveSelectControls() {
    const s = selectedShip(); if (!s || controlsLocked(s)) return;
    s.order.targetId = $('targetSelect').value;
    s.order.aim = $('aimSelect').value;
    s.order.fireSection = $('fireSectionSelect').value;
    s.order.ammo = $('ammoSelect').value;
    s.nextAmmo = s.order.ammo;
    markOrderChanged(); renderAll();
  }

  function canResolveTurn() {
    const ships = livingPlayerShips();
    return state.gameStarted && !state.result && ships.length > 0 && ships.every(s => s.confirmed);
  }

  function toggleConfirm() {
    const s = selectedShip(); if (!s || !state.gameStarted || state.paused || isAnimating || s.sunk) return;
    s.confirmed = !s.confirmed;
    renderAll();
  }

  function capturePose() { return new Map(state.ships.map(s => [s.id, { x:s.x, y:s.y, heading:s.heading }])); }

  function resolveTurn(reason='manual') {
    if (!state.gameStarted || state.result || state.paused || isAnimating) return;
    if (reason !== 'timeout' && !canResolveTurn()) {
      $('mainMessage').textContent = 'Confirma primero las órdenes de los dos navíos británicos.';
      return;
    }
    stopTimer();
    const before = capturePose();
    Core.resolveTurn(state, { rng, autoSides: [Core.SIDE_REAL_ARMADA] });
    const after = capturePose();
    const selected = selectedShip();
    if (!selected || selected.sunk) selectedShipId = livingPlayerShips()[0]?.id || selectedShipId;
    animation = { before, after, start: performance.now(), duration: 800 };
    isAnimating = true;
    syncControlsFromShip();
    renderAll();
    requestAnimationFrame(animateTurn);
  }

  function animateTurn(now) {
    if (!animation) { isAnimating = false; return; }
    const t = clamp((now - animation.start) / animation.duration, 0, 1);
    animation.progress = t;
    renderCanvas();
    if (t < 1) requestAnimationFrame(animateTurn);
    else {
      animation = null; isAnimating = false;
      renderAll();
      if (!state.result) startTurnTimer();
      else stopTimer();
    }
  }

  function visualPose(s) {
    if (!animation) return s;
    const a = animation.before.get(s.id), b = animation.after.get(s.id);
    if (!a || !b) return s;
    const diff = ((b.heading - a.heading + 540) % 360) - 180;
    return { x: a.x + (b.x - a.x) * animation.progress, y: a.y + (b.y - a.y) * animation.progress, heading: (a.heading + diff * animation.progress + 360) % 360 };
  }

  function worldToScreen(x,y) { return { x:(x-camera.x)*camera.zoom + viewW/2, y:(y-camera.y)*camera.zoom + viewH/2 }; }
  function screenToWorld(x,y) { return { x:(x-viewW/2)/camera.zoom + camera.x, y:(y-viewH/2)/camera.zoom + camera.y }; }

  function resizeCanvas() {
    const rect = canvas.getBoundingClientRect();
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    viewW = Math.max(1, rect.width); viewH = Math.max(1, rect.height);
    canvas.width = Math.round(viewW * dpr); canvas.height = Math.round(viewH * dpr);
    ctx.setTransform(dpr,0,0,dpr,0,0);
    renderCanvas();
  }

  function fitFleetView() {
    camera.x = Core.WORLD.width/2; camera.y = Core.WORLD.height/2;
    if (viewW && viewH) camera.zoom = clamp(Math.min(viewW/Core.WORLD.width, viewH/Core.WORLD.height) * 0.94, 0.55, 1.25);
    renderCanvas();
  }

  function centerSelected() {
    const s = selectedShip(); if (!s) return;
    camera.x = s.x; camera.y = s.y; camera.zoom = Math.max(camera.zoom, 1.05); renderCanvas();
  }

  function drawGrid() {
    const step = 50;
    ctx.save(); ctx.strokeStyle = 'rgba(99,179,237,.17)'; ctx.lineWidth = 1;
    for (let x=0; x<=Core.WORLD.width; x+=step) { const a=worldToScreen(x,0), b=worldToScreen(x,Core.WORLD.height); ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); }
    for (let y=0; y<=Core.WORLD.height; y+=step) { const a=worldToScreen(0,y), b=worldToScreen(Core.WORLD.width,y); ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); }
    const tl=worldToScreen(0,0), br=worldToScreen(Core.WORLD.width,Core.WORLD.height);
    ctx.strokeStyle='rgba(255,255,255,.3)'; ctx.strokeRect(tl.x,tl.y,br.x-tl.x,br.y-tl.y); ctx.restore();
  }

  function drawWindRose() {
    const x=viewW-55, y=70, r=30;
    ctx.save(); ctx.translate(x,y); ctx.strokeStyle='rgba(255,255,255,.6)'; ctx.fillStyle='white'; ctx.lineWidth=1;
    ctx.beginPath(); ctx.arc(0,0,r,0,Math.PI*2); ctx.stroke();
    ctx.font='10px Segoe UI'; ctx.textAlign='center'; ctx.textBaseline='middle'; ctx.fillText('N',0,-r*.75); ctx.fillText('E',r*.75,0); ctx.fillText('S',0,r*.75); ctx.fillText('O',-r*.75,0);
    ctx.rotate(deg(state.windFromDeg+180)); ctx.beginPath(); ctx.moveTo(0,-r*.62); ctx.lineTo(6,4); ctx.lineTo(2,4); ctx.lineTo(2,r*.42); ctx.lineTo(-2,r*.42); ctx.lineTo(-2,4); ctx.lineTo(-6,4); ctx.closePath(); ctx.fill(); ctx.restore();
  }

  function drawFireArcs(s) {
    if (!state.gameStarted || !s || s.sunk || isAnimating) return;
    const pose=visualPose(s), p=worldToScreen(pose.x,pose.y), radius=Core.MAX_FIRE_RANGE*camera.zoom;
    ctx.save(); ctx.translate(p.x,p.y); ctx.rotate(deg(pose.heading));
    for (const sec of [{start:45,end:135},{start:225,end:315}]) {
      ctx.beginPath(); ctx.moveTo(0,0); ctx.arc(0,0,radius,deg(sec.start-90),deg(sec.end-90)); ctx.closePath(); ctx.fillStyle='rgba(72,187,255,.09)'; ctx.fill(); ctx.strokeStyle='rgba(99,179,237,.42)'; ctx.lineWidth=1; ctx.stroke();
    }
    ctx.restore();
  }

  function drawHullShape(L,W,colors,ghost) {
    ctx.fillStyle=colors.hull; ctx.beginPath(); ctx.moveTo(0,-L/2); ctx.bezierCurveTo(W*.40,-L*.40,W*.60,-L*.10,W*.60,0); ctx.lineTo(W*.50,L*.40); ctx.quadraticCurveTo(W*.40,L*.50,0,L*.55); ctx.quadraticCurveTo(-W*.40,L*.50,-W*.50,L*.40); ctx.lineTo(-W*.60,0); ctx.bezierCurveTo(-W*.60,-L*.10,-W*.40,-L*.40,0,-L/2); ctx.closePath(); ctx.fill();
    ctx.strokeStyle=colors.stroke; ctx.lineWidth=ghost?1.3:1; ctx.stroke();
    if (!ghost) { ctx.fillStyle=colors.deck; ctx.beginPath(); ctx.moveTo(0,-L*.40); ctx.bezierCurveTo(W*.30,-L*.34,W*.48,-L*.05,W*.48,0); ctx.lineTo(W*.38,L*.34); ctx.quadraticCurveTo(W*.28,L*.40,0,L*.43); ctx.quadraticCurveTo(-W*.28,L*.40,-W*.38,L*.34); ctx.lineTo(-W*.48,0); ctx.bezierCurveTo(-W*.48,-L*.05,-W*.30,-L*.34,0,-L*.40); ctx.closePath(); ctx.fill(); }
  }

  function drawMastsAndSails(L,W,s,sail,colors,ghost) {
    const masts=[['fore',-L*.25],['main',0],['mizzen',L*.27]];
    ctx.strokeStyle=colors.mast; ctx.fillStyle=colors.mast;
    for (const [key,my] of masts) {
      if (s.masts?.[key]?.fallen) continue;
      ctx.lineWidth=Math.max(1.4,W*.08); ctx.beginPath(); ctx.moveTo(0,my-L*.18); ctx.lineTo(0,my+L*.18); ctx.stroke();
      ctx.lineWidth=Math.max(1,W*.035); ctx.beginPath(); ctx.moveTo(-W*.72,my-L*.06); ctx.lineTo(W*.72,my-L*.06); ctx.stroke();
    }
    if (sail==='NV') return;
    const scale=sail==='PV'?.52:sail==='MV'?.76:1;
    const alpha=ghost?.18:(sail==='PV'?.70:sail==='MV'?.82:.94);
    ctx.fillStyle=`rgba(245,245,235,${alpha})`; ctx.strokeStyle=ghost?'rgba(210,220,235,.28)':'rgba(180,180,170,.9)'; ctx.lineWidth=.7;
    const drawSail=(my,widthFactor,heightFactor,yOffset)=>{ const sw=W*widthFactor*scale, sh=L*heightFactor*scale, cy=my+yOffset; ctx.beginPath(); ctx.moveTo(-sw/2,cy-sh*.12); ctx.lineTo(sw/2,cy-sh*.12); ctx.lineTo(sw*.43,cy+sh*.72); ctx.lineTo(-sw*.43,cy+sh*.72); ctx.closePath(); ctx.fill(); ctx.stroke(); };
    for (const [key,my] of masts) {
      if (s.masts?.[key]?.fallen) continue;
      if (sail==='PV') drawSail(my,1.35,.11,-L*.13);
      else { drawSail(my,1.65,.15,-L*.05); drawSail(my,1.35,.12,-L*.17); if (sail==='TV') drawSail(my,1.05,.09,-L*.27); }
    }
  }

  function drawShip(s, ghost=false, projection=null) {
    const pose=projection || visualPose(s); const p=worldToScreen(pose.x,pose.y);
    const L=clamp(s.historical.visual.lengthM*1.08*camera.zoom,34*camera.zoom,76*camera.zoom);
    const W=clamp(s.historical.visual.beamM*1.15*camera.zoom,12*camera.zoom,24*camera.zoom);
    const selected=s.id===selectedShipId, friendly=s.side===Core.SIDE_ROYAL_NAVY;
    const colors=ghost ? { hull:'rgba(160,174,192,.22)',deck:'rgba(190,205,220,.15)',mast:'rgba(160,174,192,.34)',stroke:'rgba(220,230,240,.55)' } : friendly ? { hull:'#8B5A2B',deck:'#D2B48C',mast:'#704214',stroke:'#e2e8f0' } : { hull:'#7f1d1d',deck:'#BC8F8F',mast:'#704214',stroke:'#fca5a5' };
    ctx.save(); ctx.translate(p.x,p.y); ctx.rotate(deg(pose.heading)); ctx.globalAlpha=s.sunk?.45:1;
    if (ghost) ctx.setLineDash([5,4]);
    drawHullShape(L,W,colors,ghost); drawMastsAndSails(L,W,s,projection?.sail||s.sail,colors,ghost);
    if (selected && !ghost) { ctx.setLineDash([]); ctx.strokeStyle='#ffd166'; ctx.lineWidth=2.4; ctx.beginPath(); ctx.ellipse(0,0,W*.95,L*.63,0,0,Math.PI*2); ctx.stroke(); }
    ctx.restore();
    if (!ghost) { ctx.save(); ctx.fillStyle=s.sunk?'#94a3b8':'#fff'; ctx.font='12px Segoe UI'; ctx.textAlign='center'; ctx.fillText(`${s.name}${s.sunk?' — FUERA':''}`,p.x,p.y+L*.72+12); ctx.fillStyle='#cbd5e1'; ctx.font='10px Segoe UI'; ctx.fillText(`${s.sail} · ${Math.round(s.heading)}°`,p.x,p.y+L*.72+25); ctx.restore(); }
  }

  function drawMovementPreview() {
    const s=selectedShip(); if (!state.gameStarted || state.paused || isAnimating || !s || s.sunk || s.confirmed) return;
    const projection=Core.projectMovement(state,s,s.order); const a=worldToScreen(s.x,s.y), b=worldToScreen(projection.x,projection.y);
    ctx.save(); ctx.strokeStyle=projection.valid?'rgba(226,232,240,.65)':'rgba(248,113,113,.8)'; ctx.lineWidth=1.3; ctx.setLineDash([6,5]); ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); ctx.restore(); drawShip(s,true,projection);
  }

  function renderCanvas() {
    if (!state || !ctx) return;
    ctx.clearRect(0,0,viewW,viewH); drawGrid(); drawFireArcs(selectedShip()); drawMovementPreview(); for (const s of state.ships) drawShip(s,false,null); drawWindRose();
  }

  function hitTestShip(clientX,clientY) {
    const rect=canvas.getBoundingClientRect(), mx=clientX-rect.left, my=clientY-rect.top;
    let best=null,bestD=Infinity;
    for (const s of state.ships) { const pose=visualPose(s), p=worldToScreen(pose.x,pose.y), radius=clamp(s.historical.visual.lengthM*.55*camera.zoom,18,42), d=Math.hypot(mx-p.x,my-p.y); if (d<radius && d<bestD) { best=s; bestD=d; } }
    return best;
  }

  function updateTacticalHover(ship) {
    const overlay=$('tacticalOverlay'), me=selectedShip();
    if (!state.gameStarted) { overlay.textContent='Configure la partida y pulse Iniciar partida.'; return; }
    if (!ship || !me) { overlay.textContent='Mueve el cursor sobre un buque para información táctica.'; return; }
    if (ship.id===me.id) { const p=Core.projectMovement(state,me,me.order); overlay.textContent=`${me.name}: rumbo ${Math.round(me.heading)}° → ${Math.round(p.heading)}°, velamen ${me.sail} → ${p.sail}, timón ${me.rudder} → ${p.rudder}${p.valid?'':` · ${p.reason}`}.`; return; }
    const d=Core.distance(me,ship), rel=Math.round(Core.relativeBearing(me,ship)), arc=Core.broadsideArcFactor(me,ship);
    overlay.textContent=`${ship.name}: ${Math.round(d)} m · marcación relativa ${rel}° · ${arc.factor>0?`${arc.band}, ${arc.section}`:'fuera de arco'}.`;
  }

  function pct(v,m) { return Math.round(clamp(m? v/m*100:0,0,100)); }
  function ammoLabel(v) { return v==='DOUBLE_SHOT'?'Doble bala':v==='GRAPE'?'Metralla':'Bala redonda'; }
  function mastLabel(m) { return m.fallen ? 'CAÍDO' : `${pct(m.health,m.max)}%`; }

  function shipCard(s) {
    return `<div class="ship-card${s.id===selectedShipId?' selected':''}${s.sunk?' sunk':''}" data-card="${s.id}">
      <div class="ship-title"><span>${s.name}</span><span>${s.sunk?'FUERA':Math.round(s.hull)+' HP'}</span></div>
      <div class="info-line"><span>Casco</span><span>${pct(s.hull,s.maxHull)}%</span></div><div class="bar"><span style="width:${pct(s.hull,s.maxHull)}%"></span></div>
      <div class="info-line"><span>Trinquete / Mayor / Mesana</span><span>${mastLabel(s.masts.fore)} · ${mastLabel(s.masts.main)} · ${mastLabel(s.masts.mizzen)}</span></div>
      <div class="info-line"><span>Cañones B/E</span><span>${s.portGuns}/${s.gunsPerSide} · ${s.starboardGuns}/${s.gunsPerSide}</span></div>
      <div class="info-line"><span>Tripulación</span><span>${s.crew}/${s.initialCrew}</span></div>
      <div class="info-line"><span>Fatiga / experiencia</span><span>${Math.round(s.fatigue)}% · ${s.crewExperience}</span></div>
      <div class="info-line"><span>Timón</span><span>${s.rudderDamaged?'DAÑADO':'operativo'} · ${s.rudder}</span></div>
      <div class="info-line"><span>Eficiencia velocidad</span><span>${Math.round(s.speedEfficiency*100)}%</span></div>
      <div class="info-line"><span>Munición cargada / próxima</span><span>${ammoLabel(s.loadedAmmo)} / ${ammoLabel(s.nextAmmo)}</span></div>
      <div class="info-line"><span>Velamen / rumbo</span><span>${s.sail} · ${Math.round(s.heading)}°</span></div>
    </div>`;
  }

  function renderForceStatus() {
    $('forceStatus').innerHTML=`<h3>Royal Navy</h3>${playerShips().map(shipCard).join('')}<h3>Real Armada</h3>${enemyShips().map(shipCard).join('')}`;
    document.querySelectorAll('[data-card]').forEach(el=>el.addEventListener('click',()=>{
      const s=shipById(el.dataset.card); if (!s) return;
      if (s.side===Core.SIDE_ROYAL_NAVY && !s.sunk) { selectedShipId=s.id; syncControlsFromShip(); renderAll(); }
      else if (s.side===Core.SIDE_REAL_ARMADA && !s.sunk) { const me=selectedShip(); if(me&&!controlsLocked(me)){me.order.targetId=s.id; markOrderChanged(); syncControlsFromShip(); renderAll();} }
    }));
  }

  function updateHistoricalCard() {
    const s=selectedShip(); if(!s) return; const h=s.historical;
    const shortLabel=h.armament.shortArmType==='obus'?'obuses':'carronadas';
    $('historicalCard').innerHTML=`<strong>${h.name}</strong><br>${h.rate}<br>Configuración: ${h.configurationDate}<br>
      Eslora: ${h.dimensions.lengthSource} (${h.dimensions.lengthM.toFixed(2)} m derivados)<br>Manga: ${h.dimensions.beamSource} (${h.dimensions.beamM.toFixed(2)} m derivados)<br>
      Dotación histórica de trabajo: ${h.crew.actionComplement}<br>Piezas principales: ${h.armament.principalPieces}; por banda: ${h.armament.gunsPerBroadside}<br>
      Andanada cañones largos: ${h.armament.broadsideLongKg.toFixed(1)} kg derivados<br>Armamento corto registrado: ${h.armament.broadsideShortKg.toFixed(1)} kg nominales (${shortLabel}).<br><br>
      <strong>Estado mecánico:</strong> cañones B/E ${s.portGuns}/${s.starboardGuns}; fatiga ${Math.round(s.fatigue)}%; experiencia ${s.crewExperience}; munición cargada ${ammoLabel(s.loadedAmmo)}.<br><br>
      <strong>Evidencia marinera:</strong> ${h.sailingEvidence}`;
  }

  function renderOrdersSummary() {
    $('ordersSummary').innerHTML=playerShips().map(s=>{
      const fire=s.order.fire?`${s.order.fireBand} a ${shipById(s.order.targetId)?.name||'—'} (${s.order.aim==='HULL'?'casco':'aparejo'})`:'sin disparo';
      return `<div><strong>${s.name}:</strong> ${s.order.sail}, timón ${s.order.rudder}, ${fire}, próxima ${ammoLabel(s.order.ammo)}. <span class="${s.confirmed?'status-good':'status-warn'}">${s.confirmed?'CONFIRMADO':'pendiente'}</span></div>`;
    }).join('');
  }

  function renderLog() { const log=$('log'); log.textContent=state.log.slice(-100).join('\n'); log.scrollTop=log.scrollHeight; }

  function renderStatusHeader() {
    $('turnPill').textContent=state.gameStarted?`Turno ${state.turn}`:'Preparación';
    $('windPill').textContent=`Viento ${Math.round(state.windFromDeg)}° · ${state.windStrength}`;
    $('selectedPill').textContent=`Seleccionado: ${selectedShip()?.name||'—'}`;
    if (!state.gameStarted) $('resultPill').textContent='Sin iniciar';
    else if (!state.result) $('resultPill').textContent=state.paused?'Pausado':'En combate';
    else if (state.result==='draw') $('resultPill').textContent='Empate';
    else $('resultPill').textContent=state.result===Core.SIDE_ROYAL_NAVY?'Victoria Royal Navy':'Victoria Real Armada';
    if (!state.gameStarted) $('mainMessage').textContent='Configure la partida y pulse Iniciar partida.';
    else if (state.result) $('mainMessage').textContent=$('resultPill').textContent;
    else if (state.paused) $('mainMessage').textContent='Juego pausado.';
    else if (canResolveTurn()) $('mainMessage').textContent='Órdenes confirmadas. Puedes resolver el turno.';
    else $('mainMessage').textContent='Da órdenes a ambos navíos británicos y confírmalas. El reloj resolverá automáticamente al llegar a 00:00.';
    updateClock();
  }

  function renderAll() {
    if (!state) return;
    populateSelectors(); updateControlButtonStates(); renderCanvas(); renderForceStatus(); renderOrdersSummary(); renderLog(); updateHistoricalCard(); renderStatusHeader();
  }

  document.querySelectorAll('[data-sail]').forEach(btn=>btn.addEventListener('click',()=>setSail(btn.dataset.sail)));
  document.querySelectorAll('[data-rudder]').forEach(btn=>btn.addEventListener('click',()=>setRudder(btn.dataset.rudder)));
  $('firePort').addEventListener('click',()=>setFireBand('BABOR'));
  $('fireStarboard').addEventListener('click',()=>setFireBand('ESTRIBOR'));
  $('cancelFire').addEventListener('click',()=>setFireBand(null));
  for (const id of ['targetSelect','aimSelect','fireSectionSelect','ammoSelect']) $(id).addEventListener('change',saveSelectControls);
  $('shipSelect').addEventListener('change',e=>{ selectedShipId=e.target.value; syncControlsFromShip(); renderAll(); });
  $('confirmOrder').addEventListener('click',toggleConfirm);
  $('resolveTurn').addEventListener('click',()=>resolveTurn('manual'));
  $('startBattle').addEventListener('click',startBattleFromConfig);
  $('resetBattle').addEventListener('click',buildPreparationState);
  $('pauseBattle').addEventListener('click',togglePause);
  $('centerSelected').addEventListener('click',centerSelected);
  $('resetCamera').addEventListener('click',centerSelected);
  $('fitFleet').addEventListener('click',fitFleetView);
  $('zoomIn').addEventListener('click',()=>{ camera.zoom=clamp(camera.zoom*1.18,.45,2.5); renderCanvas(); });
  $('zoomOut').addEventListener('click',()=>{ camera.zoom=clamp(camera.zoom/1.18,.45,2.5); renderCanvas(); });

  canvas.addEventListener('contextmenu',e=>e.preventDefault());
  canvas.addEventListener('mousedown',e=>{ if (e.button===2 || e.button===1) { isPanning=true; lastPanX=e.clientX; lastPanY=e.clientY; canvas.classList.add('panning'); e.preventDefault(); } });
  window.addEventListener('mousemove',e=>{
    if (isPanning) { camera.x-=(e.clientX-lastPanX)/camera.zoom; camera.y-=(e.clientY-lastPanY)/camera.zoom; lastPanX=e.clientX; lastPanY=e.clientY; renderCanvas(); return; }
    if (!state) return; updateTacticalHover(hitTestShip(e.clientX,e.clientY));
  });
  window.addEventListener('mouseup',e=>{ if ((e.button===2||e.button===1)&&isPanning) { isPanning=false; canvas.classList.remove('panning'); } });
  canvas.addEventListener('wheel',e=>{
    e.preventDefault(); const rect=canvas.getBoundingClientRect(), sx=e.clientX-rect.left, sy=e.clientY-rect.top, before=screenToWorld(sx,sy);
    camera.zoom=clamp(camera.zoom*(e.deltaY<0?1.12:1/1.12),.45,2.5); const after=screenToWorld(sx,sy); camera.x+=before.x-after.x; camera.y+=before.y-after.y; renderCanvas();
  },{passive:false});
  canvas.addEventListener('click',e=>{
    if (!state.gameStarted || isAnimating) return; const hit=hitTestShip(e.clientX,e.clientY); if(!hit) return;
    if (hit.side===Core.SIDE_ROYAL_NAVY && !hit.sunk) { selectedShipId=hit.id; syncControlsFromShip(); renderAll(); }
    else if (hit.side===Core.SIDE_REAL_ARMADA && !hit.sunk) { const me=selectedShip(); if(me&&!controlsLocked(me)){me.order.targetId=hit.id; markOrderChanged(); syncControlsFromShip(); renderAll();} }
  });

  window.addEventListener('keydown',e=>{
    if (!state || ['INPUT','SELECT','TEXTAREA'].includes(e.target.tagName)) return;
    const key=e.key.toLowerCase(), s=selectedShip(); if(!s) return;
    if (key==='p') togglePause();
    else if (!state.gameStarted || state.paused || isAnimating) return;
    else if (key==='w'&&!s.confirmed) { const i=SAILS.indexOf(s.order.sail); setSail(SAILS[Math.min(SAILS.length-1,i+1)]); }
    else if (key==='s'&&!s.confirmed) { const i=SAILS.indexOf(s.order.sail); setSail(SAILS[Math.max(0,i-1)]); }
    else if (key==='a'&&!s.confirmed) setRudder(Number(s.order.rudder)-1);
    else if (key==='d'&&!s.confirmed) setRudder(Number(s.order.rudder)+1);
    else if (key==='q') toggleConfirm();
    else if (key==='e') resolveTurn('manual');
    else if (key==='c') centerSelected();
    else if (key==='tab') { const alive=livingPlayerShips(); if(alive.length){ const i=alive.findIndex(x=>x.id===selectedShipId); selectedShipId=alive[(i+1+alive.length)%alive.length].id; syncControlsFromShip(); renderAll(); } }
    else return;
    e.preventDefault();
  });

  try {
    data=await loadData(); buildPreparationState();
    const ro=new ResizeObserver(resizeCanvas); ro.observe($('canvasWrap')); resizeCanvas();
  } catch (err) {
    console.error(err); $('mainMessage').textContent='Error al iniciar el piloto: '+err.message;
  }
})();