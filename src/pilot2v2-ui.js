(async function () {
  'use strict';
  const Core = window.Pilot2v2Core;
  const canvas = document.getElementById('battleCanvas');
  const ctx = canvas.getContext('2d');
  const SAILS = ['NV','PV','MV','TV'];
  let data;
  let state;
  let selectedShipId = null;
  let hoveredShipId = null;
  let rng = Core.seededRng(Date.now() & 0xffffffff);
  let viewW = 1000;
  let viewH = 700;
  const camera = { x: Core.WORLD.width / 2, y: Core.WORLD.height / 2, zoom: 1 };
  let isPanning = false;
  let lastPanX = 0;
  let lastPanY = 0;

  const $ = id => document.getElementById(id);
  const deg = v => v * Math.PI / 180;
  const clamp = (v,min,max) => Math.max(min,Math.min(max,v));

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

  function initBattle() {
    state = Core.buildInitialState(data, { windFromDeg: 0, windStrength: 'MEDIA' });
    selectedShipId = playerShips()[0].id;
    for (const s of playerShips()) {
      s.order.fire = false;
      s.order.fireBand = 'AUTO';
      s.confirmed = false;
    }
    fitFleetView();
    syncControlsFromShip();
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
    const s = selectedShip();
    if (!s) return;
    $('sailSelect').value = s.order.sail;
    $('aimSelect').value = s.order.aim || 'HULL';
    $('fireSectionSelect').value = s.order.fireSection || 'AUTO';
    $('ammoSelect').value = s.order.ammo || 'ROUND_SHOT';
    $('fireSelect').value = s.order.fire ? 'yes' : 'no';
    updateControlButtonStates();
    updateHistoricalCard();
  }

  function updateControlButtonStates() {
    const s = selectedShip();
    if (!s) return;
    document.querySelectorAll('[data-sail]').forEach(btn => {
      btn.classList.toggle('current', btn.dataset.sail === s.sail);
      btn.classList.toggle('ordered', btn.dataset.sail === s.order.sail);
      btn.disabled = s.sunk || s.confirmed;
    });
    document.querySelectorAll('[data-rudder]').forEach(btn => {
      const v = Number(btn.dataset.rudder);
      btn.classList.toggle('current', v === Number(s.rudder));
      btn.classList.toggle('ordered', v === Number(s.order.rudder));
      btn.disabled = s.sunk || s.confirmed;
    });
    $('firePort').classList.toggle('fire-active', !!s.order.fire && s.order.fireBand === 'BABOR');
    $('fireStarboard').classList.toggle('fire-active', !!s.order.fire && s.order.fireBand === 'ESTRIBOR');
    for (const id of ['firePort','fireStarboard','cancelFire','targetSelect','aimSelect','fireSectionSelect','ammoSelect']) $(id).disabled = s.sunk || s.confirmed;
    $('confirmOrder').disabled = s.sunk;
    $('confirmOrder').classList.toggle('is-confirmed', !!s.confirmed);
    $('confirmOrder').textContent = s.confirmed ? 'Órdenes confirmadas (Q)' : 'Confirmar órdenes (Q)';
    $('resolveTurn').disabled = !canResolveTurn();
  }

  function setSail(value) {
    const s = selectedShip(); if (!s || s.sunk || s.confirmed) return;
    s.order.sail = value;
    $('sailSelect').value = value;
    markOrderChanged(); renderAll();
  }

  function setRudder(value) {
    const s = selectedShip(); if (!s || s.sunk || s.confirmed) return;
    s.order.rudder = clamp(Number(value), -Core.MAX_RUDDER, Core.MAX_RUDDER);
    markOrderChanged(); renderAll();
  }

  function setFireBand(band) {
    const s = selectedShip(); if (!s || s.sunk || s.confirmed) return;
    if (!band) { s.order.fire = false; s.order.fireBand = 'AUTO'; }
    else { s.order.fire = true; s.order.fireBand = band; }
    $('fireSelect').value = s.order.fire ? 'yes' : 'no';
    markOrderChanged(); renderAll();
  }

  function saveSelectControls() {
    const s = selectedShip(); if (!s || s.sunk || s.confirmed) return;
    s.order.targetId = $('targetSelect').value;
    s.order.aim = $('aimSelect').value;
    s.order.fireSection = $('fireSectionSelect').value;
    s.order.ammo = $('ammoSelect').value;
    markOrderChanged(); renderAll();
  }

  function canResolveTurn() {
    const ships = livingPlayerShips();
    return ships.length > 0 && ships.every(s => s.confirmed) && !state.result;
  }

  function toggleConfirm() {
    const s = selectedShip(); if (!s || s.sunk) return;
    s.confirmed = !s.confirmed;
    renderAll();
  }

  function resolveTurn() {
    if (!canResolveTurn()) {
      $('mainMessage').textContent = 'Confirma primero las órdenes de los dos navíos británicos.';
      return;
    }
    Core.resolveTurn(state, { rng, autoSides: [Core.SIDE_REAL_ARMADA] });
    const selected = selectedShip();
    if (!selected || selected.sunk) {
      const fallback = livingPlayerShips()[0];
      if (fallback) selectedShipId = fallback.id;
    }
    syncControlsFromShip();
    renderAll();
  }

  function worldToScreen(x,y) {
    return { x:(x-camera.x)*camera.zoom + viewW/2, y:(y-camera.y)*camera.zoom + viewH/2 };
  }
  function screenToWorld(x,y) {
    return { x:(x-viewW/2)/camera.zoom + camera.x, y:(y-viewH/2)/camera.zoom + camera.y };
  }

  function resizeCanvas() {
    const rect = canvas.getBoundingClientRect();
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    viewW = Math.max(1, rect.width);
    viewH = Math.max(1, rect.height);
    canvas.width = Math.round(viewW * dpr);
    canvas.height = Math.round(viewH * dpr);
    ctx.setTransform(dpr,0,0,dpr,0,0);
    renderCanvas();
  }

  function fitFleetView() {
    camera.x = Core.WORLD.width/2;
    camera.y = Core.WORLD.height/2;
    if (viewW && viewH) camera.zoom = clamp(Math.min(viewW/Core.WORLD.width, viewH/Core.WORLD.height) * 0.94, 0.55, 1.25);
    renderCanvas();
  }

  function centerSelected() {
    const s = selectedShip(); if (!s) return;
    camera.x = s.x; camera.y = s.y; camera.zoom = Math.max(camera.zoom, 1.05);
    renderCanvas();
  }

  function drawGrid() {
    const step = 50;
    ctx.save();
    ctx.strokeStyle = 'rgba(99,179,237,.17)';
    ctx.lineWidth = 1;
    for (let x=0; x<=Core.WORLD.width; x+=step) {
      const a=worldToScreen(x,0), b=worldToScreen(x,Core.WORLD.height);
      ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
    }
    for (let y=0; y<=Core.WORLD.height; y+=step) {
      const a=worldToScreen(0,y), b=worldToScreen(Core.WORLD.width,y);
      ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
    }
    const tl=worldToScreen(0,0), br=worldToScreen(Core.WORLD.width,Core.WORLD.height);
    ctx.strokeStyle='rgba(255,255,255,.3)'; ctx.strokeRect(tl.x,tl.y,br.x-tl.x,br.y-tl.y);
    ctx.restore();
  }

  function drawWindRose() {
    const x=viewW-55, y=70, r=30;
    ctx.save(); ctx.translate(x,y);
    ctx.strokeStyle='rgba(255,255,255,.6)'; ctx.fillStyle='white'; ctx.lineWidth=1;
    ctx.beginPath(); ctx.arc(0,0,r,0,Math.PI*2); ctx.stroke();
    ctx.font='10px Segoe UI'; ctx.textAlign='center'; ctx.textBaseline='middle';
    ctx.fillText('N',0,-r*.75); ctx.fillText('E',r*.75,0); ctx.fillText('S',0,r*.75); ctx.fillText('O',-r*.75,0);
    ctx.rotate(deg(state.windFromDeg+180));
    ctx.beginPath(); ctx.moveTo(0,-r*.62); ctx.lineTo(6,4); ctx.lineTo(2,4); ctx.lineTo(2,r*.42); ctx.lineTo(-2,r*.42); ctx.lineTo(-2,4); ctx.lineTo(-6,4); ctx.closePath(); ctx.fill();
    ctx.restore();
  }

  function drawFireArcs(s) {
    if (!s || s.sunk) return;
    const p=worldToScreen(s.x,s.y);
    const radius=Core.MAX_FIRE_RANGE*camera.zoom;
    ctx.save(); ctx.translate(p.x,p.y); ctx.rotate(deg(s.heading));
    const sectors=[
      {start:45,end:135, fill:'rgba(72,187,255,.09)', stroke:'rgba(99,179,237,.42)'},
      {start:225,end:315, fill:'rgba(72,187,255,.09)', stroke:'rgba(99,179,237,.42)'}
    ];
    for (const sec of sectors) {
      ctx.beginPath(); ctx.moveTo(0,0); ctx.arc(0,0,radius,deg(sec.start-90),deg(sec.end-90)); ctx.closePath();
      ctx.fillStyle=sec.fill; ctx.fill(); ctx.strokeStyle=sec.stroke; ctx.lineWidth=1; ctx.stroke();
    }
    ctx.restore();
  }

  function drawHullShape(ctx,L,W,colors,ghost) {
    ctx.fillStyle=colors.hull;
    ctx.beginPath();
    ctx.moveTo(0,-L/2);
    ctx.bezierCurveTo(W*.40,-L*.40,W*.60,-L*.10,W*.60,0);
    ctx.lineTo(W*.50,L*.40);
    ctx.quadraticCurveTo(W*.40,L*.50,0,L*.55);
    ctx.quadraticCurveTo(-W*.40,L*.50,-W*.50,L*.40);
    ctx.lineTo(-W*.60,0);
    ctx.bezierCurveTo(-W*.60,-L*.10,-W*.40,-L*.40,0,-L/2);
    ctx.closePath(); ctx.fill();
    ctx.strokeStyle=colors.stroke; ctx.lineWidth=ghost?1.3:1; ctx.stroke();
    if (!ghost) {
      ctx.fillStyle=colors.deck;
      ctx.beginPath();
      ctx.moveTo(0,-L*.40);
      ctx.bezierCurveTo(W*.30,-L*.34,W*.48,-L*.05,W*.48,0);
      ctx.lineTo(W*.38,L*.34);
      ctx.quadraticCurveTo(W*.28,L*.40,0,L*.43);
      ctx.quadraticCurveTo(-W*.28,L*.40,-W*.38,L*.34);
      ctx.lineTo(-W*.48,0);
      ctx.bezierCurveTo(-W*.48,-L*.05,-W*.30,-L*.34,0,-L*.40);
      ctx.closePath(); ctx.fill();
    }
  }

  function drawMastsAndSails(L,W,sail,colors,ghost) {
    const mastYs=[-L*.25,0,L*.27];
    ctx.strokeStyle=colors.mast; ctx.fillStyle=colors.mast; ctx.lineWidth=Math.max(1.4,W*.08);
    for (const my of mastYs) {
      ctx.beginPath(); ctx.moveTo(0,my-L*.18); ctx.lineTo(0,my+L*.18); ctx.stroke();
      ctx.lineWidth=Math.max(1,W*.035);
      ctx.beginPath(); ctx.moveTo(-W*.72,my-L*.06); ctx.lineTo(W*.72,my-L*.06); ctx.stroke();
      ctx.lineWidth=Math.max(1.4,W*.08);
    }
    if (sail==='NV') return;
    const scale=sail==='PV'?.52:sail==='MV'?.76:1;
    const sailAlpha=ghost?.18:(sail==='PV'?.70:sail==='MV'?.82:.94);
    ctx.fillStyle=`rgba(245,245,235,${sailAlpha})`;
    ctx.strokeStyle=ghost?'rgba(210,220,235,.28)':'rgba(180,180,170,.9)';
    ctx.lineWidth=.7;
    const drawSail=(my,widthFactor,heightFactor,yOffset)=>{
      const sw=W*widthFactor*scale, sh=L*heightFactor*scale, cy=my+yOffset;
      ctx.beginPath();
      ctx.moveTo(-sw/2,cy-sh*.12); ctx.lineTo(sw/2,cy-sh*.12);
      ctx.lineTo(sw*.43,cy+sh*.72); ctx.lineTo(-sw*.43,cy+sh*.72); ctx.closePath();
      ctx.fill(); ctx.stroke();
    };
    for (const my of mastYs) {
      if (sail==='PV') drawSail(my,1.35,.11,-L*.13);
      else {
        drawSail(my,1.65,.15,-L*.05);
        drawSail(my,1.35,.12,-L*.17);
        if (sail==='TV') drawSail(my,1.05,.09,-L*.27);
      }
    }
  }

  function drawShip(s, ghost=false, projection=null) {
    const pos=projection||s;
    const p=worldToScreen(pos.x,pos.y);
    const L=clamp(s.historical.visual.lengthM*1.08*camera.zoom, 34*camera.zoom, 76*camera.zoom);
    const W=clamp(s.historical.visual.beamM*1.15*camera.zoom, 12*camera.zoom, 24*camera.zoom);
    const selected=s.id===selectedShipId;
    const isSpanish=s.side===Core.SIDE_REAL_ARMADA;
    const colors=ghost
      ? {hull:'#a0aec0',deck:'#b0c4de',mast:'#778899',stroke:'#cbd5e1'}
      : isSpanish
        ? {hull:'#7f1d1d',deck:'#c08484',mast:'#6b3f22',stroke:'#f7dada'}
        : {hull:'#a0522d',deck:'#d2b48c',mast:'#8b4513',stroke:selected?'#f6e05e':'#5c4033'};
    ctx.save(); ctx.translate(p.x,p.y); ctx.rotate(deg(pos.heading));
    ctx.globalAlpha=s.sunk?.4:(ghost?.42:1);
    if (ghost) ctx.setLineDash([5,4]);
    drawHullShape(ctx,L,W,colors,ghost);
    drawMastsAndSails(L,W,projection?.sail||s.sail,colors,ghost);
    if (selected && !ghost) {
      ctx.setLineDash([]); ctx.strokeStyle='#ffd166'; ctx.lineWidth=2.4;
      ctx.beginPath(); ctx.ellipse(0,0,W*.95,L*.63,0,0,Math.PI*2); ctx.stroke();
    }
    ctx.restore();
    if (!ghost) {
      ctx.save(); ctx.fillStyle=s.sunk?'#94a3b8':'#fff'; ctx.font='12px Segoe UI'; ctx.textAlign='center';
      ctx.fillText(`${s.name}${s.sunk?' — FUERA':''}`,p.x,p.y+L*.72+12);
      ctx.fillStyle='#cbd5e1'; ctx.font='10px Segoe UI'; ctx.fillText(`${s.sail} · ${Math.round(s.heading)}°`,p.x,p.y+L*.72+25); ctx.restore();
    }
  }

  function drawMovementPreview() {
    const s=selectedShip(); if (!s || s.sunk) return;
    const projection=Core.projectMovement(state,s,s.order);
    const a=worldToScreen(s.x,s.y), b=worldToScreen(projection.x,projection.y);
    ctx.save(); ctx.strokeStyle='rgba(226,232,240,.65)'; ctx.lineWidth=1.3; ctx.setLineDash([6,5]);
    ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); ctx.restore();
    drawShip(s,true,projection);
  }

  function renderCanvas() {
    if (!state || !ctx) return;
    ctx.clearRect(0,0,viewW,viewH);
    drawGrid();
    drawFireArcs(selectedShip());
    drawMovementPreview();
    for (const s of state.ships) drawShip(s,false,null);
    drawWindRose();
  }

  function hitTestShip(clientX,clientY) {
    const rect=canvas.getBoundingClientRect();
    const mx=clientX-rect.left, my=clientY-rect.top;
    let best=null, bestD=Infinity;
    for (const s of state.ships) {
      const p=worldToScreen(s.x,s.y);
      const radius=clamp(s.historical.visual.lengthM*.55*camera.zoom,18,42);
      const d=Math.hypot(mx-p.x,my-p.y);
      if (d<radius && d<bestD) { best=s; bestD=d; }
    }
    return best;
  }

  function updateTacticalHover(ship) {
    const overlay=$('tacticalOverlay');
    const me=selectedShip();
    if (!ship || !me) { overlay.textContent='Mueve el cursor sobre un buque para información táctica.'; return; }
    if (ship.id===me.id) {
      const p=Core.projectMovement(state,me,me.order);
      overlay.textContent=`${me.name}: rumbo ${Math.round(me.heading)}° → ${Math.round(p.heading)}°, velamen ${me.sail} → ${me.order.sail}, timón ${me.rudder} → ${me.order.rudder}.`;
      return;
    }
    const d=Core.distance(me,ship);
    const rel=Math.round(Core.relativeBearing(me,ship));
    const arc=Core.broadsideArcFactor(me,ship);
    const arcText=arc.factor>0 ? `${arc.band}, ${arc.section}` : 'fuera de arco';
    overlay.textContent=`${ship.name}: ${Math.round(d)} m · marcación relativa ${rel}° · ${arcText}.`;
  }

  function pct(v,m) { return Math.round(clamp(v/m*100,0,100)); }
  function shipCard(s) {
    return `<div class="ship-card${s.id===selectedShipId?' selected':''}${s.sunk?' sunk':''}" data-card="${s.id}">
      <div class="ship-title"><span>${s.name}</span><span>${s.sunk?'FUERA':Math.round(s.hull)+' HP'}</span></div>
      <div class="info-line"><span>Casco</span><span>${pct(s.hull,s.maxHull)}%</span></div><div class="bar"><span style="width:${pct(s.hull,s.maxHull)}%"></span></div>
      <div class="info-line"><span>Aparejo</span><span>${pct(s.rig,s.maxRig)}%</span></div><div class="bar"><span style="width:${pct(s.rig,s.maxRig)}%"></span></div>
      <div class="info-line"><span>Tripulación</span><span>${s.crew}/${s.initialCrew}</span></div>
      <div class="info-line"><span>Velamen / rumbo</span><span>${s.sail} · ${Math.round(s.heading)}°</span></div>
    </div>`;
  }

  function renderForceStatus() {
    $('forceStatus').innerHTML=`<h3>Royal Navy</h3>${playerShips().map(shipCard).join('')}<h3>Real Armada</h3>${enemyShips().map(shipCard).join('')}`;
    document.querySelectorAll('[data-card]').forEach(el=>el.addEventListener('click',()=>{
      const s=shipById(el.dataset.card); if (!s) return;
      if (s.side===Core.SIDE_ROYAL_NAVY && !s.sunk) { selectedShipId=s.id; syncControlsFromShip(); renderAll(); }
      else if (s.side===Core.SIDE_REAL_ARMADA && !s.sunk) { const me=selectedShip(); if(me&&!me.confirmed){me.order.targetId=s.id; markOrderChanged(); syncControlsFromShip(); renderAll();} }
    }));
  }

  function updateHistoricalCard() {
    const s=selectedShip(); if(!s) return;
    const h=s.historical;
    const shortLabel=h.armament.shortArmType==='obus'?'obuses':'carronadas';
    $('historicalCard').innerHTML=`<strong>${h.name}</strong><br>
      ${h.rate}<br>Configuración: ${h.configurationDate}<br>
      Eslora: ${h.dimensions.lengthSource} (${h.dimensions.lengthM.toFixed(2)} m derivados)<br>
      Manga: ${h.dimensions.beamSource} (${h.dimensions.beamM.toFixed(2)} m derivados)<br>
      Dotación de trabajo: ${h.crew.actionComplement}<br>
      Piezas principales: ${h.armament.principalPieces}; por banda: ${h.armament.gunsPerBroadside}<br>
      Andanada cañones largos: ${h.armament.broadsideLongKg.toFixed(1)} kg derivados<br>
      Armamento corto registrado: ${h.armament.broadsideShortKg.toFixed(1)} kg nominales (${shortLabel}).<br><br>
      <strong>Evidencia marinera:</strong> ${h.sailingEvidence}`;
  }

  function renderOrdersSummary() {
    $('ordersSummary').innerHTML=playerShips().map(s=>{
      const fire=s.order.fire?`${s.order.fireBand} a ${shipById(s.order.targetId)?.name||'—'} (${s.order.aim==='HULL'?'casco':'aparejo'})`:'sin disparo';
      const cls=s.confirmed?'status-good':'status-warn';
      return `<div><strong>${s.name}:</strong> ${s.order.sail}, timón ${s.order.rudder}, ${fire}. <span class="${cls}">${s.confirmed?'CONFIRMADO':'pendiente'}</span></div>`;
    }).join('');
  }

  function renderLog() {
    const log=$('log');
    log.textContent=state.log.slice(-80).join('\n');
    log.scrollTop=log.scrollHeight;
  }

  function renderStatusHeader() {
    $('turnPill').textContent=`Turno ${state.turn}`;
    $('windPill').textContent=`Viento ${Math.round(state.windFromDeg)}° · ${state.windStrength}`;
    $('selectedPill').textContent=`Seleccionado: ${selectedShip()?.name||'—'}`;
    if (!state.result) $('resultPill').textContent='En combate';
    else if (state.result==='draw') $('resultPill').textContent='Empate';
    else $('resultPill').textContent=state.result===Core.SIDE_ROYAL_NAVY?'Victoria Royal Navy':'Victoria Real Armada';
    if (state.result) $('mainMessage').textContent=$('resultPill').textContent;
    else if (canResolveTurn()) $('mainMessage').textContent='Órdenes confirmadas. Puedes resolver el turno.';
    else $('mainMessage').textContent='Da órdenes a ambos navíos británicos y confírmalas antes de resolver.';
  }

  function renderAll() {
    if (!state) return;
    populateSelectors();
    updateControlButtonStates();
    renderCanvas();
    renderForceStatus();
    renderOrdersSummary();
    renderLog();
    updateHistoricalCard();
    renderStatusHeader();
  }

  document.querySelectorAll('[data-sail]').forEach(btn=>btn.addEventListener('click',()=>setSail(btn.dataset.sail)));
  document.querySelectorAll('[data-rudder]').forEach(btn=>btn.addEventListener('click',()=>setRudder(btn.dataset.rudder)));
  $('firePort').addEventListener('click',()=>setFireBand('BABOR'));
  $('fireStarboard').addEventListener('click',()=>setFireBand('ESTRIBOR'));
  $('cancelFire').addEventListener('click',()=>setFireBand(null));
  for (const id of ['targetSelect','aimSelect','fireSectionSelect','ammoSelect']) $(id).addEventListener('change',saveSelectControls);
  $('shipSelect').addEventListener('change',e=>{ selectedShipId=e.target.value; syncControlsFromShip(); renderAll(); });
  $('confirmOrder').addEventListener('click',toggleConfirm);
  $('resolveTurn').addEventListener('click',resolveTurn);
  $('resetBattle').addEventListener('click',initBattle);
  $('centerSelected').addEventListener('click',centerSelected);
  $('resetCamera').addEventListener('click',centerSelected);
  $('fitFleet').addEventListener('click',fitFleetView);
  $('zoomIn').addEventListener('click',()=>{ camera.zoom=clamp(camera.zoom*1.18,.45,2.5); renderCanvas(); });
  $('zoomOut').addEventListener('click',()=>{ camera.zoom=clamp(camera.zoom/1.18,.45,2.5); renderCanvas(); });

  canvas.addEventListener('contextmenu',e=>e.preventDefault());
  canvas.addEventListener('mousedown',e=>{
    if (e.button===2 || e.button===1) {
      isPanning=true; lastPanX=e.clientX; lastPanY=e.clientY; canvas.classList.add('panning'); e.preventDefault();
    }
  });
  window.addEventListener('mousemove',e=>{
    if (isPanning) {
      camera.x-=(e.clientX-lastPanX)/camera.zoom;
      camera.y-=(e.clientY-lastPanY)/camera.zoom;
      lastPanX=e.clientX; lastPanY=e.clientY; renderCanvas(); return;
    }
    if (!state) return;
    const hit=hitTestShip(e.clientX,e.clientY);
    hoveredShipId=hit?.id||null;
    updateTacticalHover(hit||null);
  });
  window.addEventListener('mouseup',e=>{
    if ((e.button===2||e.button===1)&&isPanning) { isPanning=false; canvas.classList.remove('panning'); }
  });
  canvas.addEventListener('wheel',e=>{
    e.preventDefault();
    const rect=canvas.getBoundingClientRect();
    const sx=e.clientX-rect.left, sy=e.clientY-rect.top;
    const before=screenToWorld(sx,sy);
    camera.zoom=clamp(camera.zoom*(e.deltaY<0?1.12:1/1.12),.45,2.5);
    const after=screenToWorld(sx,sy);
    camera.x+=before.x-after.x; camera.y+=before.y-after.y;
    renderCanvas();
  },{passive:false});
  canvas.addEventListener('click',e=>{
    if (!state) return;
    const hit=hitTestShip(e.clientX,e.clientY); if(!hit) return;
    if (hit.side===Core.SIDE_ROYAL_NAVY && !hit.sunk) { selectedShipId=hit.id; syncControlsFromShip(); renderAll(); }
    else if (hit.side===Core.SIDE_REAL_ARMADA && !hit.sunk) {
      const me=selectedShip(); if(me&&!me.sunk&&!me.confirmed){me.order.targetId=hit.id; markOrderChanged(); syncControlsFromShip(); renderAll();}
    }
  });

  window.addEventListener('keydown',e=>{
    if (!state || ['INPUT','SELECT','TEXTAREA'].includes(e.target.tagName)) return;
    const key=e.key.toLowerCase();
    const s=selectedShip(); if(!s) return;
    if (key==='w'&&!s.confirmed) { const i=SAILS.indexOf(s.order.sail); setSail(SAILS[Math.min(SAILS.length-1,i+1)]); }
    else if (key==='s'&&!s.confirmed) { const i=SAILS.indexOf(s.order.sail); setSail(SAILS[Math.max(0,i-1)]); }
    else if (key==='a'&&!s.confirmed) setRudder(Number(s.order.rudder)-1);
    else if (key==='d'&&!s.confirmed) setRudder(Number(s.order.rudder)+1);
    else if (key==='q') toggleConfirm();
    else if (key==='e') resolveTurn();
    else if (key==='c') centerSelected();
    else if (key==='tab') {
      const alive=livingPlayerShips(); if(alive.length){ const i=alive.findIndex(x=>x.id===selectedShipId); selectedShipId=alive[(i+1+alive.length)%alive.length].id; syncControlsFromShip(); renderAll(); }
    } else return;
    e.preventDefault();
  });

  try {
    data=await loadData();
    initBattle();
    const ro=new ResizeObserver(resizeCanvas); ro.observe($('canvasWrap'));
    resizeCanvas();
  } catch (err) {
    console.error(err);
    $('mainMessage').textContent='Error al iniciar el piloto: '+err.message;
  }
})();
