(function (root) {
  'use strict';
  if (!root || !root.document || !root.Pilot2v2Core) return;

  const Core = root.Pilot2v2Core;
  const doc = root.document;

  function state() { return root.__pilot2v2State || null; }
  function selectedShip() {
    const st = state();
    const select = doc.getElementById('shipSelect');
    return st && select ? st.ships.find(s => s.id === select.value) : null;
  }
  function escapeRegex(text) { return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function installStyles() {
    if (doc.getElementById('combatUiRulesStyle')) return;
    const style = doc.createElement('style');
    style.id = 'combatUiRulesStyle';
    style.textContent = `
      .ship-card.entangled-card { border-color:#fb923c !important; box-shadow:0 0 0 1px #fb923c inset,0 0 10px rgba(251,146,60,.35); }
      .ship-card.fire-card { box-shadow:0 0 0 1px #ef4444 inset,0 0 12px rgba(239,68,68,.45); }
      #collisionDamageControl { margin-top:9px; padding:8px; border:1px solid #7c2d12; background:#2b1b13; border-radius:7px; }
      #collisionDamageControl .danger-state { color:#fdba74; font-weight:700; }
      #collisionDamageControl .fire-state { color:#fca5a5; font-weight:700; }
    `;
    doc.head.appendChild(style);
  }

  function ensureDamageControlUi() {
    let box = doc.getElementById('collisionDamageControl');
    if (box) return box;
    const panel = doc.getElementById('leftPanel');
    if (!panel) return null;
    box = doc.createElement('section');
    box.id = 'collisionDamageControl';
    box.innerHTML = `
      <h3>Control de averías</h3>
      <div id="collisionDamageStatus" class="small">Sin averías de aferramiento.</div>
      <button id="cutEntangledMast" style="width:100%;margin-top:6px">Carpinteros: cortar palo aferrado (+10% fatiga)</button>
      <div id="fireDamageStatus" class="small" style="margin-top:6px">Sin incendio.</div>
    `;
    const orders = doc.getElementById('ordersSummary');
    const anchor = orders && orders.parentElement ? orders.parentElement : panel;
    if (anchor === panel) panel.appendChild(box);
    else panel.insertBefore(box, anchor.nextSibling);

    box.querySelector('#cutEntangledMast').addEventListener('click', () => {
      const st = state();
      const ship = selectedShip();
      if (!st || !ship || !ship.entangledWith || ship.confirmed || st.paused || !st.gameStarted) return;
      if (!ship.order) ship.order = { sail: ship.sail, rudder: ship.rudder, fire: false };
      ship.order.cutMast = true;
      ship.confirmed = false;
      const select = doc.getElementById('shipSelect');
      if (select) select.dispatchEvent(new Event('change', { bubbles: true }));
      refresh();
    });
    return box;
  }

  function hideEnemyFatigue() {
    const st = state();
    if (!st) return;
    for (const card of doc.querySelectorAll('.ship-card[data-card]')) {
      const ship = st.ships.find(s => s.id === card.dataset.card);
      if (!ship) continue;
      card.classList.toggle('entangled-card', !!ship.entangledWith);
      card.classList.toggle('fire-card', !!ship.fireLevel);
      if (ship.side === Core.SIDE_ROYAL_NAVY) continue;
      for (const line of card.querySelectorAll('.info-line')) {
        const spans = line.querySelectorAll('span');
        if (spans.length < 2) continue;
        if (spans[0].textContent.trim().startsWith('Fatiga / experiencia')) {
          spans[1].textContent = `Oculta · ${ship.crewExperience}`;
        }
      }
    }
  }

  function hideEnemyFatigueInLog() {
    const st = state();
    const log = doc.getElementById('log');
    if (!st || !log) return;
    let text = log.textContent;
    for (const ship of st.ships.filter(s => s.side !== Core.SIDE_ROYAL_NAVY)) {
      const pattern = new RegExp(`${escapeRegex(ship.name)}: no puede disparar con \\d+% de fatiga \\([^)]+\\)\\.`, 'g');
      text = text.replace(pattern, `${ship.name}: no puede disparar por fatiga de la tripulación.`);
    }
    if (text !== log.textContent) log.textContent = text;
  }

  function refreshDamageControl() {
    const box = ensureDamageControlUi();
    const st = state();
    const ship = selectedShip();
    if (!box || !st || !ship) return;
    const status = box.querySelector('#collisionDamageStatus');
    const cut = box.querySelector('#cutEntangledMast');
    const fire = box.querySelector('#fireDamageStatus');
    const other = ship.entangledWith ? st.ships.find(s => s.id === ship.entangledWith) : null;

    if (other) {
      status.className = 'small danger-state';
      status.textContent = `AFERRADO con ${other.name}${ship.entangledMastKey ? ` por ${ship.entangledMastKey === 'fore' ? 'trinquete' : ship.entangledMastKey === 'main' ? 'palo mayor' : 'mesana'} caído` : ''}. Sin traslación hasta liberarse.`;
    } else {
      status.className = 'small';
      status.textContent = 'Sin averías de aferramiento.';
    }
    cut.disabled = !other || !st.gameStarted || st.paused || ship.confirmed || !!ship.order?.cutMast;
    cut.textContent = ship.order?.cutMast ? 'Carpinteros asignados este turno' : 'Carpinteros: cortar palo aferrado (+10% fatiga)';

    const fireLevel = Math.max(0, ship.fireLevel || 0);
    if (fireLevel > 0) {
      fire.className = 'small fire-state';
      fire.textContent = `INCENDIO — nivel ${fireLevel}.`;
    } else {
      fire.className = 'small';
      fire.textContent = 'Sin incendio.';
    }
  }

  function refresh() {
    installStyles();
    hideEnemyFatigue();
    hideEnemyFatigueInLog();
    refreshDamageControl();
  }

  doc.getElementById('shipSelect')?.addEventListener('change', () => setTimeout(refresh, 0));
  setInterval(refresh, 80);
  refresh();
})(typeof window !== 'undefined' ? window : null);