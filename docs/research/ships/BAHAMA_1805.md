# Bahama — technical sheet for the 2v2 pilot

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

- Name: **Bahama** — documented.
- Keel laid: **July 1777** — documented in Spanish Defence synthesis.
- Launched: **11 March 1783** — documented.
- Construction associated with engineer **Luis Mesía** in Havana — documented in Spanish Defence material.
- Pilot configuration: **force state 19 October 1805 / Battle of Trafalgar 21 October 1805** — documented/reconstructed.
- Role: two-deck ship of the line, nominal 74-gun type — documented.

## Principal dimensions

Primary source values remain in `pies de Burgos`; metric values below are derived metadata.

- Length: **190 pies de Burgos** — documented in Spanish Defence synthesis; ≈ 52.94 m derived using ~0.2786 m/Burgos foot.
- Clean keel: **165 ft** — documented; ≈ 45.97 m derived.
- Breadth: **51 ft** — documented; ≈ 14.21 m derived.
- Depth: **24 ft** — documented; ≈ 6.69 m derived.
- Plan: **26 ft** — documented; ≈ 7.24 m derived.
- Draught aft: **22 ft 6 in** — documented; ≈ 6.27 m derived.
- Draught forward: **20 ft 6 in** — documented; ≈ 5.71 m derived.
- Reported tonnage: **1,696 tons** — documented in the Spanish Defence synthesis; preserve the source terminology and do not compare directly with British tons BM.

## Armament — selected 1805 combat fit

- 28 × 24-lb long guns — documented/reconstructed, high confidence.
- 30 × 18-lb long guns — documented/reconstructed, high confidence.
- 10 × 8-lb long guns — documented/reconstructed, high confidence.
- 6 × 30-lb obuses — documented/reconstructed, high confidence.
- 4 × 24-lb obuses — documented/reconstructed, high confidence.
- 6 small pedreros of 4/3 lb are documented aboard but excluded from the principal ship-to-ship count under the force-state transcription convention.
- **78 counted principal pieces** — documented/reconstructed.

Pilot derived fields:

- Nominal principal pieces per broadside: **39** — derived.
- Nominal long-gun broadside projectile mass: **646 Spanish lb ≈ 297.2 kg** — reconstructed screening field.
- Nominal obus broadside projectile mass: **138 Spanish lb ≈ 63.5 kg** — reconstructed screening field.
- Nominal total broadside projectile mass: **784 Spanish lb ≈ 360.7 kg** — reconstructed screening field; not a combat-value score.

## Crew

- Working operational/action complement: **689** — reconstructed/medium-high confidence because an internally enumerated category breakdown sums to 689 and is tied to González-Aller's Trafalgar documentary corpus.
- Alternate secondary synthesis value: **702** — documented discrepancy; retained in provenance but not used as a balancing slider.
- Crew quality/training tier: **unknown for numerical simulation**. No arbitrary quality modifier is authorized.

## Rig and sailing evidence

- Three-masted, full-rigged ship of the line — documented at type level.
- Royal Museums Greenwich preserves plans taken off the captured Bahama before breakup around 1814, including upper-deck plan ZAZ0766 and orlop material — documented geometry evidence.
- Because those plans are post-capture, they are strong for hull geometry but not automatically proof of every 1805 internal fitting — documented limitation.
- Qualitative secondary evidence describes Bahama as relatively fast with wind abaft/abeam and less fine close-hauled — reconstructed qualitative evidence; not converted into numerical sailing coefficients in the pilot.
- Exact 1805 mast lengths, sail area and polar performance: **unknown** for machine-readable use.
- Pilot uses the common 74 baseline sailing mechanics without a hidden bonus or penalty.

## Service-history relevance

Bahama fought at Trafalgar and was captured. The pilot uses its 1805 Spanish service configuration rather than its later British-survey state.

## Sources

Official Spanish technical synthesis:

- Spanish Ministry of Defence Trafalgar publication: https://www.defensa.gob.es/Galerias/documentacion/revistas/2005/trafalgar.pdf

Force-state-derived armament/complement working transcription, citing González-Aller's documentary corpus:

- https://www.todoababor.es/historia/batalla-de-trafalgar-21-de-octubre-de-1805/
- https://www.todoababor.es/datos_docum/arm_nav_traf_vent.htm

Post-capture geometry source:

- Royal Museums Greenwich, Bahama upper-deck plan **ZAZ0766**, circa December 1814: https://www.rmg.co.uk/collections/objects/rmgc-object-80557

## Rights / asset policy

RMG plan imagery is not assumed redistributable. For the pilot, use original schematic/vector silhouettes derived from published dimensions and geometry; do not package RMG source imagery without license confirmation.

## Pilot implementation fields authorized by this sheet

- id: `bahama-1805`
- name: `Bahama`
- side: `real-armada`
- actionComplement: `689`
- alternateComplement: `702`
- principalPieces: `78`
- gunsPerBroadside: `39`
- broadsideLongKg: `297.2`
- broadsideShortKg: `63.5`
- sourceLengthM: `52.94`
- sourceBeamM: `14.21`

Hull/rig hit points, acceleration, turning coefficients and crew-quality modifiers remain mechanics-layer values rather than direct historical facts.
