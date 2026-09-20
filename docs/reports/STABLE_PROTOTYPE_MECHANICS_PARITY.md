# Stable Prototype Mechanics Parity Gate

Date: 2026-09-18

## Reference build

The behavioral reference for the historical simulator transition is the working Render service `batalla-naval-juego-1`, service id `srv-d11jigk9c44c73fdfnn0`, deployed from `main` at commit `573e809c19645c7a8a611433502715aa5c2cf504`.

The historical simulator may improve or replace a mechanic only when the replacement is deliberate, tested and documented. A feature branch must not silently omit mechanics already present in this stable build.

Velmad v1.2 remains the deeper historical-mechanics reference. When the stable prototype and Velmad differ, the stable prototype is the minimum behavior floor while evidence-backed work may move toward Velmad or a better documented model.

## Mandatory parity inventory

The 2v2 pilot and the future shared engine must retain or deliberately supersede all of these stable-build behaviors:

### Match lifecycle and turn handling

- explicit pre-battle configuration and Start/Apply button;
- configurable turn duration;
- visible countdown clock;
- timeout automatically resolves the turn;
- pause/resume;
- explicit order confirmation and manual pass-turn control;
- turn report and end-of-battle handling;
- reset/restart path.

### Navigation and orders

- NV/PV/MV/TV sail states;
- sail changes applied progressively rather than teleporting between extreme states;
- rudder positions from -4 through +4;
- sail-dependent rudder-change limits and maximum amplitudes;
- damaged-rudder restriction;
- movement projection/shadow before resolution;
- turn movement and heading change;
- wind direction and strength effects;
- wind changes during longer battles;
- movement animation/clear visual resolution;
- camera pan/recenter and keyboard controls.

### Crew

- independent crew count per ship;
- crew casualties;
- fatigue accumulation and recovery;
- NOVATA/NORMAL/VETERANA experience levels;
- experience-dependent fatigue thresholds;
- fatigue penalty to combat effectiveness.

### Artillery and ammunition

- independent port/starboard fire orders;
- full, forward-half and aft-half firing sections;
- target hull or rigging;
- loaded ammunition distinct from ammunition selected for the next load;
- round shot, grape and double shot;
- ammunition-specific effects;
- operational guns tracked by side;
- hull hits can dismount guns on the struck side;
- lost guns reduce later broadside effectiveness.

### Damage model

- hull damage;
- separate fore, main and mizzen mast health;
- mast fall;
- mast-fall casualties;
- rig/mast damage reducing speed efficiency;
- hull damage contributing to speed-efficiency loss;
- rudder damage;
- bow/stern raking fire and its special effects;
- collision detection and damage;
- collision effects on hull, rigging, crew and rudder where applicable;
- sinking/out-of-combat state.

### Tactical information and AI

- visible firing arcs;
- tactical hover/range information;
- AI movement and firing decisions;
- AI obeys the same relevant damage, fatigue, artillery and movement state as human-controlled ships.

## Historical 2v2 adaptation rule

Parity does not mean retaining prototype-only fictional constants such as generic 52-gun broadsides or generic 875-man crews. Those values must be replaced by the selected historical ship records while preserving the underlying mechanic.

Examples:

- `52/52` generic guns becomes each real ship's documented guns-per-broadside and current operational guns;
- `875` generic crew becomes the selected dated complement;
- mechanics such as gun dismounting, mast damage, fatigue, rakes, collisions, loaded ammunition and turn timing remain present.

## Acceptance rule

PR #2 remains draft until:

1. the stable-mechanics inventory above is represented in code or explicitly documented as deliberately superseded;
2. automated parity tests cover the stateful mechanics that can be tested without a browser;
3. the development Render build passes;
4. visual playtest confirms that the start flow, countdown, controls, ship rendering, shadow, camera and turn progression remain understandable.
