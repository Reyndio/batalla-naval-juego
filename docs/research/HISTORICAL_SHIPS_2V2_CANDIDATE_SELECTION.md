# Historical Ships 2v2 — Candidate Selection Research

Status: research gate open; working quartet selected, dated configurations not yet frozen
Date: 2026-09-18

## Scope and non-negotiable side rule

This note performs the first research pass for the historical 2v2 pilot. No simulator code should be changed until the four dated ship configurations and their provenance are sufficiently resolved.

For this pilot, each side must represent one coherent navy/nation. Do not create mixed-national teams merely because countries were historical allies. Example of what is disallowed for the pilot: one British + one Spanish ship versus one French + one Portuguese ship.

## Selection methodology

Candidates were screened for:

1. real individually identified vessels from the 18th or early 19th century;
2. strong source coverage, preferably including contemporary plans/draughts or archival records;
3. ability to define a precise dated configuration rather than a generic class specification;
4. same broad period so armament and sailing evidence are comparable;
5. coherent national sides;
6. pair-level comparability without invented balance modifiers;
7. useful design variation for validating distinct ship records and silhouettes in the pilot.

Fame alone was not treated as a selection criterion.

## Working selection

### Side A — Royal Navy, Trafalgar 21 October 1805

- HMS Bellerophon (1786), 74-gun third-rate two-decker.
- HMS Conqueror (1801), 74-gun third-rate two-decker.

### Side B — Real Armada, Trafalgar 21 October 1805

- Montañés (1794), nominal 74-gun two-decker.
- Bahama (1783), nominal 74-gun two-decker.

This is the working quartet for the next research pass, not yet permission to implement the ships in code.

## Why this quartet currently leads

All four ships can be configured for the same historical date, 21 October 1805. This removes many avoidable comparability problems caused by mixing decades, refits, armament practices and crew establishments.

All four are nominal 74-gun two-deckers. This is useful for the first pilot because it keeps the broad tactical role comparable while still exposing meaningful differences in hull dimensions, design generation, battery composition, upperworks armament, crew establishment and documented sailing qualities.

The national sides are clean: two Royal Navy vessels versus two Real Armada vessels. No mixed-allied team is required.

The pair is not made from only the most famous ships. Bellerophon is well known, but Conqueror, Montañés and Bahama are especially attractive because they provide unusually useful technical or archival source coverage and design variation.

## Source quality by ship

### HMS Bellerophon

Strong sources found:

- Royal Museums Greenwich, ship plan ZAZ1142, scale 1:48. Body plan, sheer lines and longitudinal half-breadth for the Arrogant-derived group including Bellerophon. The museum explicitly identifies Bellerophon (1786) among the 74-gun third-rate two-deckers represented. Source: https://www.rmg.co.uk/collections/objects/rmgc-object-80933
- Royal Museums Greenwich construction contract ADT0009 for Bellerophon, signed 19 January 1782. Caution: later reused/annotated contract material must not be mistaken for Bellerophon's original dimensions.
- The National Archives Trafalgar Ancestors identifies HMS Bellerophon's pay/muster source as ADM 36/16498. Example captain record: https://www.nationalarchives.gov.uk/trafalgarancestors/details.asp?id=3035
- Rif Winfield, *British Warships in the Age of Sail 1793–1817*, for dimensions and establishment data.

Current working dimensions from Winfield-derived data: gun deck 168 ft 0 in; keel 138 ft 0 in; breadth 46 ft 10.5 in; depth in hold 19 ft 9 in; approximately 1,612 78/94 tons BM.

Current Trafalgar armament candidate from Trafalgar-specific secondary compilations: 28 x 32-pdr lower deck; 28 x 18-pdr upper deck; 18 x 9-pdr upperworks; 2 x 32-pdr carronades; 6 x 18-pdr carronades.

Open issue: sources distinguish between men borne on the books and men actually present/available in action. Values around 566 borne and 522 in battle appear in the literature. The final simulation field must preserve that distinction instead of silently choosing one number.

Plan/asset rights note: the RMG plan is Crown copyright / National Maritime Museum; image licensing must be checked before redistribution as a game asset.

### HMS Conqueror

Strong sources found:

- Royal Museums Greenwich plan ZAZ0701, scale 1:48, dated 7 May 1795, signed by Surveyor of the Navy John Henslow. Body plan, sheer lines and longitudinal half-breadth, including recorded later alterations. Source: https://www.rmg.co.uk/collections/objects/rmgc-object-80492
- Royal Museums Greenwich magazine plan ZAZ0700 and additional technical material in the Conqueror collection.
- The National Archives Trafalgar Ancestors identifies HMS Conqueror's pay/muster source as ADM 36/16250. Captain Israel Pellew record: https://www.nationalarchives.gov.uk/trafalgarancestors/details.asp?id=5288
- Rif Winfield, *British Warships in the Age of Sail 1793–1817*, for as-built dimensions, complement and establishment.

Working as-built dimensions from Winfield: gun deck 176 ft 0 in; keel 144 ft 2 in; breadth 49 ft 2 in; depth in hold 20 ft 9 in; approximately 1,853 69/94 tons BM.

Important unresolved armament conflict:

- Winfield gives an 1803 establishment with 28 x 32-pdr on the lower deck; 30 x 18-pdr on the upper deck; 4 x 18-pdr long guns plus 10 x 32-pdr carronades on the quarterdeck; 2 x 18-pdr long guns plus 2 x 32-pdr carronades on the forecastle; and 6 x 18-pdr carronades on the roundhouse.
- Trafalgar-specific compilations instead give 28 x 32-pdr; 30 x 18-pdr; 16 x 9-pdr; 2 x 32-pdr carronades; and 6 x 18-pdr carronades.

Do not freeze Conqueror's 21 October 1805 firepower until this conflict is resolved from a stronger dated ordnance/ship source or a defensible source hierarchy.

Trafalgar complement is commonly reported as 573, while the design/establishment complement is 590. The simulation should store a dated actual complement separately from establishment strength.

Plan/asset rights note: RMG material is Crown copyright / National Maritime Museum; licensing must be checked for in-game reproduction.

### Montañés

Exceptionally strong digital technical source:

- Biblioteca Virtual de Defensa / Archivo Histórico de la Armada Juan Sebastián de Elcano: Agustín Wauters y Horcasitas, 1806, *Plano del navío Montañés, de 74 cañones...*, a 13-plan set covering exterior and interior views and horizontal/vertical sections. Call numbers PB-063 to PB-074bis. Source: https://bibliotecavirtual.defensa.gob.es/BVMDefensa/en/consulta/registro.do?control=BMDB20236854017
- The same set includes a rigged fore/side view showing mast proportions and dimensions and a full-rig sailing view under wind abeam.
- The digital copy is explicitly distributed under CC BY 4.0 with attribution requested to "Archivo Histórico de la Armada Juan Sebastián de Elcano / Biblioteca Virtual de Defensa". This makes it especially suitable as a research and potentially derived visual source, subject to correct attribution.

Official Spanish Defence Trafalgar publication reports launch on 14 May 1794; keel 169 ft 6 in; breadth 51 ft; plan 28 ft; depth 25 ft 6 in; draught aft 24 ft 7 in and forward 23 ft 3 in; 1,499 tons; and reports sea trials against Monarca in which Montañés proved very fast, manoeuvrable and stable. Source: https://www.defensa.gob.es/Galerias/documentacion/revistas/2005/trafalgar.pdf

Important dimension issue: the same official synthesis prints an overall length of 194 Spanish feet, while other modern technical references give 190 Spanish feet for the gun-deck/length convention. The original 1806 plans and measurement convention should be used to settle the field rather than normalizing the discrepancy away.

Trafalgar complement of 749 is supported by Spanish naval-history material, including the Revista General de Marina 2020 article on Spanish naval engineering.

Important unresolved Trafalgar armament conflict:

- A compilation explicitly derived from the commanders' Estados de Fuerza of 19 October 1805 / González-Aller's *Campaña de Trafalgar. Corpus Documental* gives 28 x 36-pdr, 30 x 18-pdr, 8 x 8-pdr and 10 x 30-pdr obuses, total 76 counted pieces under its convention.
- A scholarly article by Agustín R. Rodríguez González, also citing the 19 October force states, has been indexed with a table implying additional 24-pdr obuses and a total of 80.

The actual Montañés force state or an unambiguous reproduction of it must be inspected before freezing the 21 October configuration.

### Bahama

Strong sources found:

- Spanish Ministry of Defence Trafalgar publication gives construction and 1805 configuration data: keel laid July 1777 under engineer Luis Mesía; launched 11 March 1783; length 190 Burgos feet; clean keel 165 ft; breadth 51 ft; depth 24 ft; plan 26 ft; draught aft 22 ft 6 in and forward 20 ft 6 in; 1,696 tons. Source: https://www.defensa.gob.es/Galerias/documentacion/revistas/2005/trafalgar.pdf
- Same publication gives the battery as 28 x 24-pdr; 30 x 18-pdr; 10 x 8-pdr; 6 x 30-pdr obuses, augmented by Trafalgar with 4 x 24-pdr obuses and 6 x 4-pdr pedreros.
- Royal Museums Greenwich plan ZAZ0766, scale 1:48, shows Bahama's upper deck as taken off at Chatham before breakup, circa December 1814. Source: https://www.rmg.co.uk/collections/objects/rmgc-object-80557
- RMG also has the corresponding orlop-deck plan ZAZ0764.

Caution: the surviving RMG plans are post-capture and circa 1814, so they are strong evidence for physical geometry but cannot automatically be treated as untouched 1805 configuration. Any British alterations between capture and survey must be identified where relevant.

Crew conflict to resolve: a 2020 Revista General de Marina article reports 702 men at Trafalgar, while some later battle lists use 689. The final record should follow the strongest dated source and preserve the provenance rather than choose the more common web number.

Plan/asset rights note: the RMG plans are Crown copyright / National Maritime Museum and require licensing review for reproduction.

## Pair-level comparability — preliminary only

The quartet is promising for balance because all are 74-gun two-deckers of the same battle date, but exact pair balance cannot be claimed yet.

A preliminary broadside calculation using currently available armament candidates places the two sides in the same general order of magnitude, with differences small enough to justify continuing research rather than rejecting the quartet immediately. However, this calculation is sensitive to the unresolved Conqueror and Montañés 1805 armament conflicts and to British-versus-Spanish pound definitions. It must not be converted into a permanent balance score.

Crew totals are more asymmetric: the Spanish ships carried substantially more personnel in the available Trafalgar figures than the British pair. This is historically useful rather than a reason to invent a compensating modifier. Crew composition, troops, trained seamen, gunners, fatigue and crew quality must remain separate historical variables. Velmad's treatment of crew quality as distinct from raw crew count supports preserving this distinction.

## Alternative national matchups screened

### Royal Navy vs French Navy

A British/French quartet remains the strongest fallback. Redoutable has an important primary battle report from Captain Jean Jacques Étienne Lucas, and Fougueux has unusually valuable modern archaeological study of its construction. The main disadvantage for this pilot is that an equally convenient set of directly accessible dated plans and exact 1805 individual fittings was not found as quickly as for the British/Spanish quartet.

### Alternative Spanish 74s

San Ildefonso is exceptionally important and well documented and has surviving design-plan material. It remains a strong reserve candidate. For the pilot, Bahama currently adds more design-generation contrast against Montañés, whereas San Ildefonso and Montañés are more closely related in the evolution of late Spanish 74-gun design.

## Research blockers before the quartet can be frozen for implementation

1. Resolve HMS Conqueror's exact Trafalgar upperworks battery/carronade fit.
2. Resolve Montañés's 76-versus-80 counted-piece discrepancy directly from the 19 October 1805 force state or an authoritative reproduction.
3. Resolve Bellerophon's dated battle complement versus men borne, keeping both fields if both are historically meaningful.
4. Resolve Bahama's 689-versus-702 complement discrepancy.
5. Settle the Montañés 190-versus-194 Spanish-foot length field by identifying the measurement convention in the original plans.
6. Define unit conversions only after documenting British and Spanish pound/foot conventions used by the source data.
7. Extract rig and sail dimensions where the primary plans support them; do not invent polar performance from qualitative sailing reports.
8. Record source/licensing status for every plan or illustration intended for use in the game.
9. Produce one dated technical sheet per ship, with every field labelled documented, reconstructed, estimated, or unknown.

## Decision at this stage

Working quartet: **HMS Bellerophon + HMS Conqueror versus Montañés + Bahama**, all in their Trafalgar 21 October 1805 configurations.

This selection is strong enough to concentrate the next research pass on these four ships. It is **not** yet sufficiently resolved to authorize programming or to treat all numerical fields as final.

The implementation gate remains closed until the dated ship sheets and the blockers above are resolved or explicitly documented as irreducible uncertainty.
