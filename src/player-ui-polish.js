(function (root) {
  'use strict';
  if (!root || !root.document || !root.Pilot2v2Core) return;

  const Core = root.Pilot2v2Core;
  const doc = root.document;
  const clamp = (v, min, max) => Math.max(min, Math.min(max, v));
  const camera = { x: Core.WORLD.width / 2, y: Core.WORLD.height / 2, zoom: 0.94 };
  let panning = false;
  let lastX = 0;
  let lastY = 0;

  const replacements = [
    [/Las reglas Velmad verificadas/g, 'Las reglas históricas verificadas'],
    [/Timón Velmad/g, 'Timón'],
    [/Acciones Velmad/g, 'Acciones de control'],
    [/Artillería Velmad/g, 'Artillería'],
    [/clase Velmad/g, 'clase de navío'],
    [/restricciones Velmad/g, 'restricciones de combate'],
    [/Velmad/g, 'reglamento base']
  ];

  function scrubText(rootNode) {
    if (!rootNode) return;
    const walker = doc.createTreeWalker(rootNode, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const node of nodes) {
      let value = node.nodeValue;
      for (const [pattern, replacement] of replacements) value = value.replace(pattern, replacement);
      if (value !== node.nodeValue) node.nodeValue = value;
    }
  }

  const observer = new MutationObserver(records => {
    for (const record of records) {
      if (record.type === 'characterData') scrubText(record.target.parentNode);
      for (const node of record.addedNodes) if (node.nodeType === 1 || node.nodeType === 3) scrubText(node.nodeType === 3 ? node.parentNode : node);
    }
  });

  function state() { return root.__pilot2v2State || null; }
  function canvas() { return doc.getElementById('battleCanvas'); }
  function wrap() { return doc.getElementById('canvasWrap'); }
  function selectedShip() {
    const st = state();
    const select = doc.getElementById('shipSelect');
    return st && select ? st.ships.find(s => s.id === select.value) : null;
  }

  function fitFleet() {
    const c = canvas();
    if (!c) return;
    const rect = c.getBoundingClientRect();
    camera.x = Core.WORLD.width / 2;
    camera.y = Core.WORLD.height / 2;
    camera.zoom = clamp(Math.min(rect.width / Core.WORLD.width, rect.height / Core.WORLD.height) * 0.94, 0.55, 1.25);
  }

  function centerSelected() {
    const ship = selectedShip();
    if (!ship) return;
    camera.x = ship.x;
    camera.y = ship.y;
    camera.zoom = Math.max(camera.zoom, 1.05);
  }

  function screenPosition(ship) {
    const c = canvas();
    if (!c) return null;
    const rect = c.getBoundingClientRect();
    return {
      x: (ship.x - camera.x) * camera.zoom + rect.width / 2,
      y: (ship.y - camera.y) * camera.zoom + rect.height / 2,
      rect
    };
  }

  function visualSize(ship) {
    return {
      L: clamp(ship.historical.visual.lengthM * 1.08 * camera.zoom, 34 * camera.zoom, 76 * camera.zoom),
      W: clamp(ship.historical.visual.beamM * 1.15 * camera.zoom, 12 * camera.zoom, 24 * camera.zoom)
    };
  }

  function ensureOverlay(id, className) {
    let el = doc.getElementById(id);
    if (el) return el;
    el = doc.createElement('div');
    el.id = id;
    el.className = className;
    wrap()?.appendChild(el);
    return el;
  }

  function placeRing(el, ship, label) {
    if (!el || !ship || ship.sunk) { if (el) el.style.display = 'none'; return; }
    const p = screenPosition(ship);
    if (!p) { el.style.display = 'none'; return; }
    const { L, W } = visualSize(ship);
    el.style.display = 'block';
    el.style.left = `${p.x}px`;
    el.style.top = `${p.y}px`;
    el.style.width = `${Math.max(34, W * 2.15)}px`;
    el.style.height = `${Math.max(48, L * 1.38)}px`;
    el.style.transform = `translate(-50%, -50%) rotate(${ship.heading}deg)`;
    el.dataset.label = label || '';
  }

  function placeBatteryMark(el, ship) {
    if (!el || !ship || !ship.order || !ship.order.fire || !['BABOR', 'ESTRIBOR'].includes(ship.order.fireBand)) {
      if (el) el.style.display = 'none';
      return;
    }
    const p = screenPosition(ship);
    if (!p) { el.style.display = 'none'; return; }
    const { L, W } = visualSize(ship);
    const sign = ship.order.fireBand === 'ESTRIBOR' ? 1 : -1;
    const h = ship.heading * Math.PI / 180;
    const offset = sign * W * 0.72;
    el.style.display = 'block';
    el.style.left = `${p.x + Math.cos(h) * offset}px`;
    el.style.top = `${p.y + Math.sin(h) * offset}px`;
    el.style.height = `${Math.max(22, L * 0.58)}px`;
    el.style.transform = `translate(-50%, -50%) rotate(${ship.heading}deg)`;
    el.dataset.band = ship.order.fireBand;
  }

  function updateCards(me, target, incoming) {
    doc.querySelectorAll('[data-card]').forEach(card => {
      card.classList.toggle('target-card', !!target && card.dataset.card === target.id);
      card.classList.toggle('threat-card', !!me && incoming > 0 && card.dataset.card === me.id);
    });
  }

  function updateHighlights() {
    const st = state();
    const me = selectedShip();
    const targetRing = ensureOverlay('targetShipHighlight', 'tactical-ring target-ring');
    const threatRing = ensureOverlay('threatShipHighlight', 'tactical-ring threat-ring');
    const battery = ensureOverlay('selectedBatteryHighlight', 'battery-side-highlight');
    if (!st || !me || !st.gameStarted) {
      targetRing.style.display = 'none';
      threatRing.style.display = 'none';
      battery.style.display = 'none';
      updateCards(null, null, 0);
      return;
    }

    const target = st.ships.find(s => s.id === me.order?.targetId && !s.sunk);
    const incoming = st.ships.filter(s => s.side !== me.side && !s.sunk && s.order && s.order.targetId === me.id).length;
    placeRing(targetRing, target, 'OBJETIVO');
    placeRing(threatRing, incoming ? me : null, incoming > 1 ? `APUNTADO ×${incoming}` : 'APUNTADO');
    placeBatteryMark(battery, me);
    updateCards(me, target, incoming);
  }

  function bindCameraMirror() {
    const c = canvas();
    if (!c) return;

    doc.getElementById('startBattle')?.addEventListener('click', () => setTimeout(fitFleet, 0));
    doc.getElementById('fitFleet')?.addEventListener('click', () => setTimeout(fitFleet, 0));
    for (const id of ['centerSelected', 'resetCamera']) doc.getElementById(id)?.addEventListener('click', () => setTimeout(centerSelected, 0));
    doc.getElementById('zoomIn')?.addEventListener('click', () => { camera.zoom = clamp(camera.zoom * 1.18, 0.45, 2.5); });
    doc.getElementById('zoomOut')?.addEventListener('click', () => { camera.zoom = clamp(camera.zoom / 1.18, 0.45, 2.5); });

    c.addEventListener('mousedown', e => {
      if (e.button === 2 || e.button === 1) { panning = true; lastX = e.clientX; lastY = e.clientY; }
    });
    root.addEventListener('mousemove', e => {
      if (!panning) return;
      camera.x -= (e.clientX - lastX) / camera.zoom;
      camera.y -= (e.clientY - lastY) / camera.zoom;
      lastX = e.clientX;
      lastY = e.clientY;
    });
    root.addEventListener('mouseup', e => { if (e.button === 2 || e.button === 1) panning = false; });
    c.addEventListener('wheel', e => {
      const rect = c.getBoundingClientRect();
      const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
      const beforeX = (sx - rect.width / 2) / camera.zoom + camera.x;
      const beforeY = (sy - rect.height / 2) / camera.zoom + camera.y;
      camera.zoom = clamp(camera.zoom * (e.deltaY < 0 ? 1.12 : 1 / 1.12), 0.45, 2.5);
      const afterX = (sx - rect.width / 2) / camera.zoom + camera.x;
      const afterY = (sy - rect.height / 2) / camera.zoom + camera.y;
      camera.x += beforeX - afterX;
      camera.y += beforeY - afterY;
    }, { passive: true });

    doc.getElementById('shipSelect')?.addEventListener('change', updateHighlights);
    doc.getElementById('targetSelect')?.addEventListener('change', updateHighlights);
    doc.getElementById('firePort')?.addEventListener('click', updateHighlights);
    doc.getElementById('fireStarboard')?.addEventListener('click', updateHighlights);
    doc.getElementById('cancelFire')?.addEventListener('click', updateHighlights);
    c.addEventListener('click', () => setTimeout(updateHighlights, 0));
  }

  function init() {
    scrubText(doc.body);
    observer.observe(doc.body, { subtree: true, childList: true, characterData: true });
    bindCameraMirror();
    setInterval(updateHighlights, 80);
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})(typeof window !== 'undefined' ? window : null);
