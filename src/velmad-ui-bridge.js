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

  Core.__velmadUiBridgeInstalled = true;
})(typeof window !== 'undefined' ? window : globalThis);
