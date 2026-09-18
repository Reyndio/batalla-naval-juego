# Historical 2v2 Pilot — validation and playtest report

Date: 2026-09-18
Branch: `feature/historical-2v2-pilot`
Development service: `batalla-naval-2v2-dev`
Pilot route: `https://batalla-naval-2v2-dev.onrender.com/pilot`

## Scope validated

This report covers the first playable vertical slice only. It does not validate the final historical sailing, ballistics, damage, morale, fatigue, boarding, fire or flooding model.

The pilot contains four real ships in dated October 1805 configurations:

- Royal Navy: HMS Bellerophon + HMS Conqueror.
- Real Armada: Montañés + Bahama.

The historical data layer is externalized in `data/historical_ships_1805.json`. Provisional mechanics are separated in `src/pilot2v2-core.js`.

## Automated validation

Render is configured to execute `npm install && npm test` before deployment. The successful build for commit `3cc26da3ec516cec6fdbed969891e353791391f0` ran **9 tests, 9 passed, 0 failed**.

Validated behaviors:

1. exactly four historical ship records exist;
2. each side contains two ships from one coherent navy;
3. frozen 1805 complements and principal battery counts remain intact;
4. four independent runtime ship states are created with no shared damage corruption;
5. AI targeting never selects a friendly ship;
6. long seeded four-ship simulations remain numerically valid;
7. a seeded AI-vs-AI battle reaches a result instead of entering a permanent manoeuvre loop;
8. the two human-controlled Royal Navy ships retain independent orders and targets;
9. an actual local HTTP server process successfully serves `/health`, `/pilot`, and the historical ship JSON during the build smoke test.

The battle-termination test initially exposed a real AI defect: both sides could continue manoeuvring for 500 turns without completing the engagement. The deployment was intentionally failed by that test. The AI was then changed to close range first, seek an abeam firing position inside the engagement envelope, hold an existing broadside solution, and recover from map boundaries. The same benchmark then passed.

## Render deployment

A new Render development service was created instead of modifying the stable service.

- Development service: `batalla-naval-2v2-dev`
- Branch: `feature/historical-2v2-pilot`
- Runtime: Node
- Build command: `npm install && npm test`
- Start command: `npm start`
- Auto deploy: enabled
- Latest validated deploy: `dep-damoq6uq1p3s73a4sqng`
- Latest validated status: **live**

The stable service `batalla-naval-juego-1` remains on `main` and was not altered.

## Playable interaction

The pilot page allows the human player to command both Royal Navy ships independently:

- select Bellerophon or Conqueror;
- choose Montañés or Bahama as target;
- choose sail state;
- choose rudder setting;
- choose hull or rigging aim;
- choose whether to fire when a valid arc/range exists;
- resolve the turn;
- inspect per-ship hull, rigging, crew, heading, sail state and historical technical fields.

The Real Armada pair is controlled by the pilot AI. Movement is resolved for all ships from their turn orders, followed by collision and firing resolution.

## Visual validation scope

The four ships are rendered as original schematic vector silhouettes scaled from sourced historical length/beam metadata. No Royal Museums Greenwich plan image is redistributed. Montañés's CC BY 4.0 archival plan material remains available as a future attributed source for richer derived artwork.

The available external web-inspection tool could not open the Render URL directly, so this report does **not** claim a human visual browser inspection from this agent. Route serving was nevertheless exercised over real localhost HTTP during the Render build, and Render reports the deployed service as live. A human browser visual pass remains desirable before treating the UI as polished.

## Historical/mechanics boundary

Historical inputs used by the pilot include ship identity, dated configuration, dimensions, armament, complements and provenance.

The following remain deliberately provisional shared mechanics and are not presented as sourced historical values:

- 1,200 hull HP;
- 800 rigging HP;
- acceleration/sail speed constants;
- turn-rate constants;
- range falloff;
- collision damage;
- conversion from long-gun broadside projectile mass to damage;
- casualty formula;
- AI tactical logic.

The current damage formula deliberately uses only documented **long-gun broadside mass** as its historical input. British carronades and Spanish obuses are stored and displayed separately but are not treated as equivalent weapons in the damage formula.

## Known limitations

- This is a development scenario, not an exact reconstruction of a specific 2v2 action at Trafalgar.
- The sailing model is a common provisional 74-gun baseline; known qualitative sailing evidence such as Montañés's strong sailing reputation is recorded but not converted into an invented bonus.
- Gunnery does not yet model individual batteries, reload cycles, ammunition, penetration, heel, smoke, crew quality, gun crews or weapon-specific carronade/obus behavior.
- Damage remains aggregate hull/rigging rather than component-level structure.
- Fire, flooding, surrender, capture, morale, fatigue and boarding are not part of this pilot.
- Turn firing is still a deliberately simplified pilot resolution rather than the final deterministic combat pipeline.
- `npm install` currently reports **15 dependency vulnerabilities (2 low, 3 moderate, 9 high, 1 critical)** in the inherited dependency tree. No blind `npm audit fix --force` was applied because it may introduce breaking changes. This should be audited separately before production exposure.
- No full automated browser/DOM rendering test exists yet; the current HTTP smoke test validates that the page and data are served.

## Pilot conclusion

The vertical slice meets the project's definition of a first **playable historical 2v2 development version**:

- four real dated ships are present as distinct records;
- each side has two nationally coherent vessels;
- the human can issue separate orders to both Royal Navy ships;
- both Spanish ships operate under AI;
- target state and damage state remain separate per vessel;
- automated AI-vs-AI engagement can reach battle completion;
- the development service builds, passes tests and is live;
- the stable prototype service remains untouched.

This does not close the Historical 1v1 milestone. The next engineering step should be to use what this pilot exposed to begin the shared simulation-engine separation rather than growing this temporary page into a permanent fleet engine.
