'use strict';

// Node test bootstrap: movement and raking geometry must be installed before the gunnery layer
// so tests exercise the same movement/rake semantics as the playable page.
const Core = require('./pilot2v2-core.js');
require('./inertia-model.js');
require('./raking-geometry.js');
require('./velmad-gunnery.js');

module.exports = Core;
