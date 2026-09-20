(function (root) {
  'use strict';
  if (!root || !root.Pilot2v2Core) return;
  const Core = root.Pilot2v2Core;
  if (Core.__velmadUiBridgeInstalled) return;

  const baseBuildInitialState = Core.buildInitialState;
  const baseStartBattle = Core.startBattle;
  const baseResolveTurn = Core.resolveTurn;

  Core.buildInitialState = function (...args) {
    const state = baseBuildInitialState.apply(Core, args);
    root.__pilot2v2State = state;
    return state;
  };

  Core.startBattle = function (state, ...args) {
    const result = baseStartBattle.call(Core, state, ...args);
    root.__pilot2v2State = result;
    return result;
  };

  Core.resolveTurn = function (state, ...args) {
    const result = baseResolveTurn.call(Core, state, ...args);
    root.__pilot2v2State = result;
    return result;
  };

  function selectedPlayerShip() {
    const state = root.__pilot2v2State;
    const select = root.document && root.document.getElementById('shipSelect');
    return state && select ? state.ships.find(s => s.id === select.value) : null;
  }

  function installExtremeSailBridge() {
    if (!root.document) return;
    const buttons = Array.from(root.document.querySelectorAll('[data-sail="NV"],[data-sail="TV"]'));
    for (const button of buttons) {
      button.addEventListener('click', event => {
        const ship = selectedPlayerShip();
        if (!ship || !ship.order) return;
        const target = button.dataset.sail;
        const isExtremeJump = (ship.sail === 'NV' && target === 'TV') || (ship.sail === 'TV' && target === 'NV');
        if (!isExtremeJump) return;
        if (!root.__pilot2v2State.gameStarted || root.__pilot2v2State.paused || ship.sunk || ship.confirmed) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        ship.order.sail = target;
        ship.confirmed = false;
        const select = root.document.getElementById('shipSelect');
        if (select) select.dispatchEvent(new Event('change', { bubbles: true }));
      }, true);
    }

    setInterval(() => {
      const ship = selectedPlayerShip();
      if (!ship || !ship.order) return;
      const unlocked = root.__pilot2v2State.gameStarted && !root.__pilot2v2State.paused && !ship.sunk && !ship.confirmed;
      for (const button of buttons) {
        const target = button.dataset.sail;
        const isExtremeJump = (ship.sail === 'NV' && target === 'TV') || (ship.sail === 'TV' && target === 'NV');
        if (isExtremeJump) button.disabled = !unlocked;
      }
    }, 200);
  }

  Core.__velmadUiBridgeInstalled = true;
  if (root.document) setTimeout(installExtremeSailBridge, 0);
})(typeof window !== 'undefined' ? window : globalThis);
