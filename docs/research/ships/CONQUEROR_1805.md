# HMS Conqueror — technical sheet for the 2v2 pilot

Configuration date: 21 October 1805
Nation: Great Britain / Royal Navy
Type: 74-gun third-rate ship of the line, two-decker
Status: selected pilot configuration

## Evidence labels

- `documented`: directly supported by primary or strong secondary evidence.
- `reconstructed`: combined from documented facts with an explicit method.
- `estimated`: necessary approximation, not a source fact.
- `unknown`: not sufficiently supported for this pilot.

## Identity and chronology

- Name: **HMS Conqueror** — documented.
- Launch: **1801** — documented in established ship histories and museum cataloguing.
- Pilot configuration: **Trafalgar, 21 October 1805** — reconstructed/medium-high confidence.
- Role/class: **74-gun third-rate, two-decker** — documented.

## Principal dimensions

Source convention: British feet/inches; SI conversions are derived metadata only.

- Gun deck length: **176 ft 0 in** — documented in Winfield-derived design data; ≈ 53.64 m derived.
- Keel: **144 ft 2 in** — documented; ≈ 43.94 m derived.
- Breadth: **49 ft 2 in** — documented; ≈ 14.99 m derived.
- Depth in hold: **20 ft 9 in** — documented; ≈ 6.32 m derived.
- Burthen: **about 1,853 69/94 tons BM** — documented as British tons burthen; not directly comparable to Spanish displacement/tonnage.

## Armament envelope and selected 1805 fit

A stronger 1803 establishment is preserved as a documented alternative but is not used by the pilot.

### 1803 documented alternative

- 28 × 32-pdr lower deck.
- 30 × 18-pdr upper deck.
- Quarterdeck: 4 × 18-pdr long guns + 10 × 32-pdr carronades.
- Forecastle: 2 × 18-pdr long guns + 2 × 32-pdr carronades.
- Roundhouse: 6 × 18-pdr carronades.

### Selected Trafalgar 1805 fit

- 28 × 32-pdr long guns — reconstructed/medium-high confidence.
- 30 × 18-pdr long guns — reconstructed/medium-high confidence.
- 16 × 9-pdr long guns — reconstructed/medium-high confidence.
- 2 × 32-pdr carronades — reconstructed/medium-high confidence.
- 6 × 18-pdr carronades — reconstructed/medium-high confidence.

Pilot derived fields:

- Principal pieces: **82** total — derived from selected fit.
- Nominal pieces per broadside: **41** — derived.
- Nominal long-gun broadside projectile mass: **790 British lb ≈ 358.3 kg** — reconstructed screening field.
- Nominal carronade broadside projectile mass: **86 British lb ≈ 39.0 kg** — reconstructed screening field.
- Nominal total broadside projectile mass: **876 British lb ≈ 397.3 kg** — reconstructed screening field; not a combat-value score.

The heavier 1803 establishment screens at roughly 461.8 kg nominal broadside projectile mass and is intentionally not selected because the 1805 fit is the better dated match and gives a more even two-ship force without inventing modifiers.

## Crew

- Working Trafalgar action complement: **573** — reconstructed/medium-high confidence.
- Establishment complement around **590** belongs to a different administrative/design concept and remains separate.
- Crew quality/training tier: **unknown for numerical simulation**. No arbitrary Royal Navy quality bonus is authorized.

Administrative provenance:

- The National Archives, Trafalgar Ancestors: HMS Conqueror pay/muster source **ADM 36/16250**.

## Rig and sailing evidence

- Three-masted, full-rigged ship of the line — documented at type level.
- RMG plan ZAZ0701, scale 1:48, dated 7 May 1795 and signed by Surveyor John Henslow, supplies strong hull geometry/design provenance and notes later alterations — documented.
- RMG also preserves technical material including magazine plan ZAZ0700.
- Exact 1805 machine-readable mast, yard and sail dimensions: **unknown/not yet extracted**.
- Individual polar sailing curve / exact knots: **unknown**.
- Pilot implementation uses the common 74-gun baseline sailing mechanics and does not claim a ship-specific speed advantage.

## Service-history relevance

Conqueror fought at Trafalgar under Captain Israel Pellew. The pilot represents the ship as an individually identified 1805 vessel rather than as a generic 74.

## Plans / visual provenance

Primary/archival geometry source:

- Royal Museums Greenwich, plan **ZAZ0701**, scale 1:48, dated 7 May 1795: https://www.rmg.co.uk/collections/objects/rmgc-object-80492

Administrative source:

- The National Archives, Trafalgar Ancestors; ADM 36/16250. Captain Israel Pellew entry: https://www.nationalarchives.gov.uk/trafalgarancestors/details.asp?id=5288

Secondary design source:

- Rif Winfield, *British Warships in the Age of Sail 1793–1817*.

Trafalgar armament/complement working source:

- https://www.todoababor.es/historia/batalla-de-trafalgar-21-de-octubre-de-1805/

## Rights / asset policy

RMG imagery is not assumed redistributable. The pilot may derive an original schematic/vector silhouette from published dimensions and geometry, but should not bundle the museum plan image without license confirmation.

## Pilot implementation fields authorized by this sheet

- id: `conqueror-1805`
- name: `HMS Conqueror`
- side: `royal-navy`
- actionComplement: `573`
- principalPieces: `82`
- gunsPerBroadside: `41`
- broadsideLongKg: `358.3`
- broadsideShortKg: `39.0`
- sourceLengthM: `53.64`
- sourceBeamM: `14.99`

Hull/rig hit points, acceleration, turning coefficients and crew-quality modifiers remain mechanics-layer values, not direct historical facts.
