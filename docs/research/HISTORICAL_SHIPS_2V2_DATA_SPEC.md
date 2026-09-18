# Historical Ships 2v2 — implementation data specification

Date: 2026-09-18
Status: research gate closed for the first playable pilot

## Selected dated configurations

The first playable 2v2 pilot will use the following historically supported configurations:

- HMS Bellerophon — 21 October 1805.
- HMS Conqueror — 21 October 1805.
- Montañés — force state 19 October / action 21 October 1805.
- Bahama — force state 19 October / action 21 October 1805.

National sides remain coherent:

- Royal Navy: Bellerophon + Conqueror.
- Real Armada: Montañés + Bahama.

## Machine-readable fields authorized for the pilot

These fields are sufficiently sourced to externalize ship identity and the first visible 2v2 differentiation:

| Ship | crew/action | principal pieces | per broadside | long-gun broadside kg | short-arm broadside kg | source length m | source beam m |
|---|---:|---:|---:|---:|---:|---:|---:|
| HMS Bellerophon | 522 | 82 | 41 | 354.3 | 39.0 | 51.21 | 14.29 |
| HMS Conqueror | 573 | 82 | 41 | 358.3 | 39.0 | 53.64 | 14.99 |
| Montañés | 749 | 76 | 38 | 370.8 | 69.0 | 52.94 | 14.21 |
| Bahama | 689 | 78 | 39 | 297.2 | 63.5 | 52.94 | 14.21 |

Short-arm field means British carronade projectile mass for the British pair and Spanish obus projectile mass for the Spanish pair. It is a data-storage grouping only. The two weapon families are **not** asserted to be physically or tactically equivalent.

## Measurement conventions

### British

- Historical dimensions remain stored in British feet/inches in the technical sheets.
- Derived SI dimensions use 1 international foot = 0.3048 m.
- Gun labels remain in British pounds.
- Derived projectile comparison mass uses 1 avoirdupois pound = 0.45359237 kg.
- British tons burthen/BM are retained in source terminology and are not treated as displacement.

### Spanish

- Historical dimensions remain stored in `pies de Burgos` in the technical sheets.
- Pilot display conversion uses approximately 0.2786 m per Burgos foot as derived metadata; original units remain authoritative.
- Gun labels remain in Spanish libras.
- Coarse comparison conversion uses 0.460093 kg per libra castellana only as derived metadata; it is not proof that every 1805 naval projectile had exactly that physical mass.
- Spanish reported tonnage is retained in source terminology and is not directly compared with British tons BM.

## What is deliberately not frozen as historical ship data

The current research does **not** justify ship-specific numerical values for:

- acceleration;
- exact maximum speed in knots;
- polar sailing curves;
- turning-radius coefficients;
- inertia constants;
- hull structural hit points;
- rigging hit points;
- crew-quality tiers;
- gunnery accuracy multipliers;
- reload-rate bonuses.

For the first pilot these remain shared mechanics-layer baseline values. They must be clearly treated as inherited/provisional simulator mechanics, not presented as sourced historical characteristics.

## Sailing evidence policy for the pilot

- Montañés retains a sourced qualitative note that it was reported very fast, manoeuvrable and stable.
- Bahama retains qualitative sailing notes, but no numerical curve is inferred.
- The British pair retains strong geometry sources but no invented individual sailing polar.
- Therefore the playable pilot uses a common 74-gun sailing baseline while displaying the known qualitative evidence in the technical information panel.

This is intentionally conservative. The later sailing subsystem will replace the shared baseline only after source-backed calibration.

## Visual policy

- Ship silhouettes may be scaled from source length/beam fields so that the four records are visually distinct.
- Montañés source plans may support derived visuals with CC BY 4.0 attribution to `Archivo Histórico de la Armada Juan Sebastián de Elcano / Biblioteca Virtual de Defensa`.
- RMG plan imagery for the British ships and Bahama is research evidence but should not be redistributed as an in-game image asset without licensing confirmation.
- The first pilot should therefore use original schematic/vector rendering generated from source dimensions, not copied plan images.

## Pilot mechanics mapping

The vertical slice may use source-backed armament fields to scale coarse broadside effects, but must label the result as **pilot mechanics**, not final historical ballistics.

Recommended implementation separation:

- `ship historical data`: identity, date, dimensions, armament counts/calibres, complements, source/provenance.
- `pilot mechanics`: common 74 sailing response, hit-point baselines, range falloff, collision constants, temporary damage formulas.

This separation is required so later historical artillery/sailing work can replace mechanics without rewriting ship records.

## Research-gate decision

The gate is closed for the **limited first playable 2v2 vertical slice** because:

1. all four vessels are individually identified real ships;
2. dated 1805 configurations are selected;
3. principal dimensions are sourced with measurement conventions preserved;
4. armament and working action complements are specified with disagreements recorded;
5. visual provenance and licensing constraints are documented;
6. unsupported sailing/crew-quality values are explicitly left outside the historical data layer instead of being invented.

Remaining uncertainties do not block the vertical slice because the pilot plan explicitly does not require the final sailing, damage or gunnery model.

## Per-ship sheets

- `docs/research/ships/BELLEROPHON_1805.md`
- `docs/research/ships/CONQUEROR_1805.md`
- `docs/research/ships/MONTANES_1805.md`
- `docs/research/ships/BAHAMA_1805.md`

## Implementation guardrails

- Do not tune historical ship records for balance.
- Do not use raw crew count as a direct gunnery-quality multiplier.
- Do not claim carronades and Spanish obuses are equivalent because both are stored in a short-arm field.
- Do not claim the shared sailing baseline is the historical individual performance of any of the four ships.
- Do not overwrite the stable Render service `batalla-naval-juego-1`.
- Implement on a dedicated `feature/*` branch and deploy only to a development service.
