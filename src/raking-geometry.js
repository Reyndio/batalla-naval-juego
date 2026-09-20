(function (root, factory) {
  const Core = root && root.Pilot2v2Core
    ? root.Pilot2v2Core
    : (typeof require !== 'undefined' ? require('./pilot2v2-core.js') : null);
  const api = factory(Core);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.RakingGeometry = api;
  if (Core) api.install();
})(typeof window !== 'undefined' ? window : globalThis, function (Core) {
  'use strict';

  if (!Core) throw new Error('RakingGeometry requires Pilot2v2Core.');

  const AXIS_TOLERANCE_DEG = 15;
  const PERPENDICULAR_TOLERANCE_DEG = 15;
  const SUPPRESSION_EPSILON_DEG = 0.5;

  let installed = false;
  let baseAngleTo = null;

  function normalizeAngle(deg) { return ((deg % 360) + 360) % 360; }
  function signedDiff(a, b) {
    let d = normalizeAngle(a - b);
    if (d > 180) d -= 360;
    return d;
  }

  function axisRelation(defender, attacker, rawBearing) {
    const bearing = rawBearing == null ? baseAngleTo(defender, attacker) : rawBearing;
    const rel = normalizeAngle(bearing - defender.heading);
    if (rel <= AXIS_TOLERANCE_DEG || rel >= 360 - AXIS_TOLERANCE_DEG) return 'BOW';
    if (rel >= 180 - AXIS_TOLERANCE_DEG && rel <= 180 + AXIS_TOLERANCE_DEG) return 'STERN';
    return null;
  }

  function perpendicularError(attacker, defender) {
    const diff = Math.abs(signedDiff(attacker.heading, defender.heading));
    return Math.abs(90 - diff);
  }

  function isTPosition(attacker, defender) {
    if (!attacker || !defender || !baseAngleTo) return false;
    const axis = axisRelation(defender, attacker);
    return !!axis && perpendicularError(attacker, defender) <= PERPENDICULAR_TOLERANCE_DEG;
  }

  function correctedAngleTo(from, to) {
    const raw = baseAngleTo(from, to);
    if (!from || !to || !from.historical || !to.historical) return raw;

    const axis = axisRelation(from, to, raw);
    if (!axis) return raw;
    if (perpendicularError(to, from) <= PERPENDICULAR_TOLERANCE_DEG) return raw;

    // The firing code identifies a rake from the defender->attacker bearing alone.
    // Move only that bearing just outside the bow/stern rake cone when the ships
    // are not approximately perpendicular. Ordinary broadside geometry remains untouched.
    const center = axis === 'BOW' ? from.heading : from.heading + 180;
    let offset = signedDiff(raw, center);
    if (Math.abs(offset) < 1e-9) offset = 1;
    const sign = Math.sign(offset);
    return normalizeAngle(center + sign * (AXIS_TOLERANCE_DEG + SUPPRESSION_EPSILON_DEG));
  }

  function install() {
    if (installed || Core.__rakingGeometryInstalled) return false;
    baseAngleTo = Core.angleTo;
    Core.angleTo = correctedAngleTo;
    Core.rakingGeometry = api;
    Core.__rakingGeometryInstalled = true;
    installed = true;
    return true;
  }

  const api = {
    AXIS_TOLERANCE_DEG,
    PERPENDICULAR_TOLERANCE_DEG,
    axisRelation,
    perpendicularError,
    isTPosition,
    correctedAngleTo,
    install
  };

  return api;
});