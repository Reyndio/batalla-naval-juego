# HMS Bellerophon — technical sheet for the 2v2 pilot

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

- Name: **HMS Bellerophon** — documented.
- Launch: **1786** — documented in Royal Museums Greenwich plan metadata for the group including Bellerophon.
- Pilot configuration: **Trafalgar, 21 October 1805** — documented/reconstructed from Trafalgar-specific sources and the ship's surviving administrative record trail.
- Role/class: **74-gun third-rate, two-decker** — documented.

## Principal dimensions

Source convention: British feet/inches; SI conversions are derived metadata only.

- Gun deck length: **168 ft 0 in** — documented in Winfield-derived design data; ≈ 51.21 m derived.
- Keel: **138 ft 0 in** — documented; ≈ 42.06 m derived.
- Breadth: **46 ft 10.5 in** — documented; ≈ 14.29 m derived.
- Depth in hold: **19 ft 9 in** — documented; ≈ 6.02 m derived.
- Burthen: **about 1,612 78/94 tons BM** — documented as British tons burthen; do not compare directly with Spanish displacement/tonnage values.

## Armament — selected 1805 combat fit

- 28 × 32-pdr long guns — reconstructed/medium-high confidence for Trafalgar fit.
- 28 × 18-pdr long guns — reconstructed/medium-high confidence.
- 18 × 9-pdr long guns — reconstructed/medium-high confidence.
- 2 × 32-pdr carronades — reconstructed/medium-high confidence.
- 6 × 18-pdr carronades — reconstructed/medium-high confidence.

Pilot derived fields:

- Principal pieces: **82** total — derived from the selected fit.
- Nominal pieces per broadside: **41** — derived, assuming symmetrical broadside allocation.
- Nominal long-gun broadside projectile mass: **781 British lb ≈ 354.3 kg** — reconstructed screening field.
- Nominal carronade broadside projectile mass: **86 British lb ≈ 39.0 kg** — reconstructed screening field.
- Nominal total broadside projectile mass: **867 British lb ≈ 393.3 kg** — reconstructed screening field; not a combat-value score.

## Crew

- Working action complement at Trafalgar: **522** — reconstructed/medium-high confidence from Trafalgar-specific secondary compilation.
- Men borne/on-books figure: **about 566** appears in muster-oriented literature — documented as a distinct administrative concept but not frozen as the combat complement.
- Simulation rule: preserve `actionComplement` and `borneOnBooks` as separate fields; never overwrite one with the other.
- Crew quality/training tier: **unknown for numerical simulation**. No arbitrary British bonus is authorized by this sheet.

Administrative provenance:

- The National Archives, Trafalgar Ancestors: HMS Bellerophon pay/muster source **ADM 36/16498**.

## Rig and sailing evidence

- Three-masted, full-rigged ship of the line — documented at type level.
- RMG plan ZAZ1142 provides body plan, sheer lines and longitudinal half-breadth for the Arrogant-derived group including Bellerophon — documented geometry source.
- Exact 1805 mast lengths, yard lengths and sail area have not yet been extracted into machine-readable values — unknown for this pilot.
- Individual polar sailing curve / exact knots by point of sail: **unknown**.
- Pilot implementation therefore uses the common 74-gun baseline sailing model inherited from the prototype and does not claim a Bellerophon-specific numerical sailing advantage.

## Service-history relevance

Bellerophon fought at Trafalgar and is represented specifically in that action-date configuration. The pilot uses this dated ship identity rather than a generic British 74.

## Plans / visual provenance

Primary/archival geometry source:

- Royal Museums Greenwich, plan **ZAZ1142**, scale 1:48, body plan / sheer lines / longitudinal half-breadth for the group including Bellerophon: https://www.rmg.co.uk/collections/objects/rmgc-object-80933

Administrative source:

- The National Archives, Trafalgar Ancestors; ADM 36/16498. Example database record: https://www.nationalarchives.gov.uk/trafalgarancestors/details.asp?id=3161

Secondary design source:

- Rif Winfield, *British Warships in the Age of Sail 1793–1817*.

Trafalgar armament/complement working source:

- https://www.todoababor.es/historia/batalla-de-trafalgar-21-de-octubre-de-1805/

## Rights / asset policy

RMG collection imagery is not assumed reusable in the game. The museum directs users to its image-licensing process. For the pilot, use source-derived geometry to create original vector/schematic silhouettes; do not redistribute the RMG plan image itself without license confirmation.

## Pilot implementation fields authorized by this sheet

- id: `bellerophon-1805`
- name: `HMS Bellerophon`
- side: `royal-navy`
- actionComplement: `522`
- principalPieces: `82`
- gunsPerBroadside: `41`
- broadsideLongKg: `354.3`
- broadsideShortKg: `39.0`
- sourceLengthM: `51.21`
- sourceBeamM: `14.29`

Hull hit points, rigging hit points, acceleration, turning coefficients and crew-quality modifiers are **mechanics-layer baseline values**, not historical facts from this sheet.
