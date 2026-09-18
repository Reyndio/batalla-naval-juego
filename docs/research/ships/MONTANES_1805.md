# Montañés — technical sheet for the 2v2 pilot

Configuration date: 19–21 October 1805
Nation: Spain / Real Armada
Type: 74-gun-class ship of the line, two-decker
Status: selected pilot configuration

## Evidence labels

- `documented`: directly supported by primary or strong secondary evidence.
- `reconstructed`: combined from documented facts with an explicit method.
- `estimated`: necessary approximation, not a source fact.
- `unknown`: not sufficiently supported for this pilot.

## Identity and chronology

- Name: **Montañés** — documented.
- Builder/designer context: associated with Julián Martín de Retamosa's design development — documented in Spanish naval sources.
- Launched at Ferrol: **14 May 1794** — documented.
- Pilot configuration: **force state 19 October 1805 / Battle of Trafalgar 21 October 1805** — documented/reconstructed.
- Role: two-deck ship of the line, nominal 74-gun type — documented.

## Principal dimensions

Primary source values remain in `pies de Burgos`; metric values below are derived metadata and must not replace the originals.

Working source dimensions from Spanish Defence technical synthesis:

- Length: **190 pies de Burgos** — reconstructed/medium-high confidence for the pilot; ≈ 52.94 m using ~0.2786 m per Burgos foot.
- Conflicting modern synthesis value: **194 pies** — documented as a discrepancy, not used as a balancing slider.
- Keel: **169 ft 6 in (Burgos)** — documented in the Spanish Defence synthesis; ≈ 47.23 m derived.
- Breadth: **51 ft** — documented; ≈ 14.21 m derived.
- Plan: **28 ft** — documented; ≈ 7.80 m derived.
- Depth: **25 ft 6 in** — documented; ≈ 7.10 m derived.
- Draught aft: **24 ft 7 in** — documented; ≈ 6.85 m derived.
- Draught forward: **23 ft 3 in** — documented; ≈ 6.48 m derived.
- Reported tonnage: **1,499 tons** — documented in the Spanish Defence synthesis; preserve source terminology and do not compare directly with British tons BM.

## Armament — selected 1805 combat fit

Force-state-derived principal battery:

- 28 × 36-lb long guns — documented/reconstructed, high confidence.
- 30 × 18-lb long guns — documented/reconstructed, high confidence.
- 8 × 8-lb long guns — documented/reconstructed, high confidence.
- 10 × 30-lb obuses — documented/reconstructed, high confidence.
- **76 counted principal ship-to-ship pieces** — documented/reconstructed from the 19 October force-state-derived table.

The later `76/80` wording is preserved as a source-history discrepancy. The pilot does not invent four unidentified additional combat guns.

Pilot derived fields:

- Nominal pieces per broadside: **38** — derived from the 76 principal pieces.
- Nominal long-gun broadside projectile mass: **806 Spanish lb ≈ 370.8 kg** using the project's provisional 0.460093 kg comparison conversion — reconstructed screening field.
- Nominal obus broadside projectile mass: **150 Spanish lb ≈ 69.0 kg** — reconstructed screening field.
- Nominal total broadside projectile mass: **956 Spanish lb ≈ 439.8 kg** — reconstructed screening field; not a combat-value score.

## Crew

- Working Trafalgar complement: **749** — documented/reconstructed from Spanish Trafalgar material.
- Raw headcount is not treated as equivalent to gunnery efficiency; Spanish complements include sailors, artillery personnel and troop/infantry components.
- Crew quality/training tier: **unknown for numerical simulation**. No arbitrary quality penalty or bonus is authorized.

## Rig and sailing evidence

The evidence base is unusually strong.

- Archivo Histórico de la Armada / Biblioteca Virtual de Defensa preserves Agustín Wauters y Horcasitas's **1806 thirteen-plan set** for Montañés — documented primary/near-contemporary technical evidence.
- The set includes a rigged fore/side view explicitly showing the **proportion and dimensions of the masts** and another view under full rig with wind abeam — documented.
- Specific machine-readable mast/yard/sail measurements have not yet been transcribed into the data file — unknown for numeric use in this pilot.
- Spanish Defence sources report trials in which Montañés proved **very fast, manoeuvrable and stable** relative to Monarca — documented qualitative sailing evidence.
- The pilot does **not** convert that qualitative evidence into invented knots, polar curves or hidden speed bonuses. Until the sailing subsystem is researched, it uses the common 74 baseline mechanics while retaining the qualitative note for future calibration.

Primary plan set:

- https://bibliotecavirtual.defensa.gob.es/BVMDefensa/en/consulta/registro.do?id=1016834
- Rigged mast-proportion plan: https://bibliotecavirtual.defensa.gob.es/BVMDefensa/en/consulta/registro.do?id=1016966

## Service-history relevance

Montañés fought at Trafalgar and is represented in its heavy 1805 battery state. Its documented sailing reputation and rich plan record make it especially valuable for later historical sailing-model calibration.

## Sources

Archival/primary visual source:

- Agustín Wauters y Horcasitas, 1806, *Plano del navío Montañés, de 74 cañones...*, 13 plans, Archivo Histórico de la Armada Juan Sebastián de Elcano / Biblioteca Virtual de Defensa: https://bibliotecavirtual.defensa.gob.es/BVMDefensa/en/consulta/registro.do?id=1016834

Official technical synthesis:

- Spanish Ministry of Defence Trafalgar publication: https://www.defensa.gob.es/Galerias/documentacion/revistas/2005/trafalgar.pdf

Force-state-derived armament working transcription, citing González-Aller's *Campaña de Trafalgar (1804-1805). Corpus Documental*:

- https://www.todoababor.es/historia/batalla-de-trafalgar-21-de-octubre-de-1805/
- https://www.todoababor.es/datos_docum/arm_nav_traf_vent.htm

## Rights / asset policy

The Biblioteca Virtual de Defensa digital copy is explicitly **CC BY 4.0**. Required attribution:

`Fuente: Archivo Histórico de la Armada Juan Sebastián de Elcano / Biblioteca Virtual de Defensa`

This allows the pilot to create and redistribute attributed derived visual material from the digital plan set, subject to preserving attribution.

## Pilot implementation fields authorized by this sheet

- id: `montanes-1805`
- name: `Montañés`
- side: `real-armada`
- actionComplement: `749`
- principalPieces: `76`
- gunsPerBroadside: `38`
- broadsideLongKg: `370.8`
- broadsideShortKg: `69.0`
- sourceLengthM: `52.94`
- sourceBeamM: `14.21`

Hull/rig hit points, acceleration, turning coefficients and crew-quality modifiers remain mechanics-layer values rather than direct historical facts.
