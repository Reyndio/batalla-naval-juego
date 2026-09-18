# Historical Ships 2v2 — Configuration Envelope and Pilot Selection

Status: configuration-selection pass complete; implementation research gate remains open
Date: 2026-09-18

## Purpose

Apply ADR-0002 to the current four-ship candidate set and choose the historically documented dated configuration of each vessel that gives the most useful 2v2 balance without inventing statistics or synthesizing a best-of-all-dates ship.

Working quartet:

- Royal Navy: HMS Bellerophon + HMS Conqueror.
- Real Armada: Montañés + Bahama.

Side composition remains nationally coherent. This note selects ship configurations only; it does not authorize simulator code changes yet.

## Method

For each vessel:

1. identify complete or substantially complete dated configurations supported by sources;
2. prefer evidence tied to the individual ship and date;
3. compare armament, crew and known sailing/size evidence;
4. use balance only to choose among genuinely historical configurations;
5. preserve source disagreements instead of using them as tuning sliders;
6. reject cross-date composites unless independently supportable as a real configuration.

For the pair-level artillery comparison below, broadside projectile mass is used only as a coarse screening diagnostic. It is **not** a historical combat-value score. It ignores muzzle velocity, penetration, rate of fire, accuracy, training, sea state, heel, ammunition state and many other variables that the simulator will eventually model separately.

## Source hierarchy used in this pass

### Spanish ships

Strongest dated artillery evidence currently available is the table derived from the `Estados de Fuerza` signed by the ship commanders on departure from Cádiz, 19 October 1805, reproduced/cited through José Ignacio González-Aller, *Campaña de Trafalgar (1804-1805). Corpus Documental*, Ministerio de Defensa, 2004. The accessible transcription used in this pass is:

- https://www.todoababor.es/historia/batalla-de-trafalgar-21-de-octubre-de-1805/
- https://www.todoababor.es/datos_docum/arm_nav_traf_vent.htm

The transcription explicitly notes that small pedreros, esmeriles and 4-lb obuses normally used in boats/landing work are excluded from the ship-to-ship artillery total.

For Montañés geometry/rig, the project has an unusually strong archival source: Agustín Wauters y Horcasitas's 1806 thirteen-plan set in the Archivo Histórico de la Armada / Biblioteca Virtual de Defensa:

- https://bibliotecavirtual.defensa.gob.es/BVMDefensa/en/consulta/registro.do?control=BMDB20236854017

The digital copy is CC BY 4.0 with required attribution to `Archivo Histórico de la Armada Juan Sebastián de Elcano / Biblioteca Virtual de Defensa`.

### British ships

For Trafalgar-day armament and action complements, this pass uses the Trafalgar-specific compilation at Todo a Babor, which in turn cites Mark Adkin for British complements and gives individual Trafalgar armament fits:

- https://www.todoababor.es/historia/batalla-de-trafalgar-21-de-octubre-de-1805/

The project also retains stronger archival geometry/provenance sources already identified:

- Royal Museums Greenwich plan ZAZ1142 for the Bellerophon/Arrogant-derived group.
- Royal Museums Greenwich plan ZAZ0701 for Conqueror, dated 7 May 1795 and signed by Surveyor John Henslow.
- The National Archives muster/pay records identified through Trafalgar Ancestors (including ADM 36/16498 for Bellerophon and ADM 36/16250 for Conqueror).

Rif Winfield, *British Warships in the Age of Sail 1793–1817*, remains the principal strong secondary reference for British design dimensions, establishments and career/refit chronology. Exact printed-page verification should be retained in the final ship sheets.

## Measurement caveat

Cross-national projectile-mass figures below are approximate comparison conversions, not literal reconstructed shot weights.

- British nominal pound: 0.45359237 kg, standard avoirdupois conversion (NIST).
- Spanish nominal pound: for comparison only, 0.460093 kg is used from the later statutory equivalence of the libra castellana. This does **not** prove that every 1805 Spanish naval projectile exactly matched that mass.

Original historical calibre labels must remain primary data in the simulator. SI conversions are derived metadata with provenance and confidence.

Likewise, Spanish dimensions should remain in the source's original `pies de Burgos` until the exact convention is attached to each field. A naval-history metrology source gives the post-1738 Burgos foot at approximately 0.2786 m, but no modern conversion should replace the original source value.

## Vessel configuration envelopes

### HMS Bellerophon

#### Earlier/design configuration

The as-built/design family is a 74-gun third-rate two-decker with the familiar battery of 28 x 32-pdr, 28 x 18-pdr and 18 x 9-pdr long guns. RMG plan ZAZ1142 and Winfield-derived dimensions provide strong geometry/design provenance.

#### Trafalgar 1805 configuration — selected

Working combat fit:

- 28 x 32-pdr long guns;
- 28 x 18-pdr long guns;
- 18 x 9-pdr long guns;
- 2 x 32-pdr carronades;
- 6 x 18-pdr carronades.

Working action complement: **522**. Preserve separately the higher `borne/on-books` figure found in muster-oriented sources; do not overwrite one concept with the other.

Nominal broadside screening calculation:

- long guns: 781 British lb;
- carronades: 86 British lb;
- total: **867 British lb ≈ 393.3 kg**.

Selection rationale: the 1805 fit is directly relevant to the common comparison date, has a complete upperworks/carronade treatment, and is already close to the pair-level balance target. There is no reason to weaken or strengthen Bellerophon by borrowing another date.

Confidence: **documented/reconstructed from strong ship/design sources plus Trafalgar-specific secondary compilation**. Final technical sheet still needs explicit archival reconciliation of action complement vs men borne.

### HMS Conqueror

#### 1803 establishment — documented alternative, not selected

Winfield gives an establishment with:

- 28 x 32-pdr lower deck;
- 30 x 18-pdr upper deck;
- quarterdeck: 4 x 18-pdr long guns + 10 x 32-pdr carronades;
- forecastle: 2 x 18-pdr long guns + 2 x 32-pdr carronades;
- roundhouse: 6 x 18-pdr carronades.

Nominal broadside screening calculation:

- long guns: 772 British lb;
- carronades: 246 British lb;
- total: **1,018 British lb ≈ 461.8 kg**.

This is a valid historical configuration envelope point, but it makes the Royal Navy pair materially stronger at short range and is not as specifically tied to Trafalgar day as the next fit.

#### Trafalgar 1805 configuration — selected

Working combat fit:

- 28 x 32-pdr long guns;
- 30 x 18-pdr long guns;
- 16 x 9-pdr long guns;
- 2 x 32-pdr carronades;
- 6 x 18-pdr carronades.

Working action complement: **573**.

Nominal broadside screening calculation:

- long guns: 790 British lb;
- carronades: 86 British lb;
- total: **876 British lb ≈ 397.3 kg**.

Selection rationale: this is a complete Trafalgar-specific fit and produces a much closer pair-level comparison than the heavier 1803 establishment. ADR-0002 permits this choice because both are dated historical configurations; no value has been interpolated or invented.

Confidence: **reconstructed / medium-high pending primary ordnance or ship-book confirmation**. The 1803 establishment remains recorded as a genuine alternative, not treated as an error.

### Montañés

#### 1794 as-built — documented alternative, not selected

Accessible technical history gives:

- 28 x 24-lb long guns;
- 30 x 18-lb long guns;
- 16 x 8-lb long guns;
- total 74.

Nominal broadside screening calculation: **670 Spanish lb ≈ 308.3 kg**.

This is historically valid but makes the Spanish pair much weaker against the selected British 1805 pair.

#### 19–21 October 1805 configuration — selected

The force-state-derived combat battery is:

- 28 x 36-lb long guns;
- 30 x 18-lb long guns;
- 8 x 8-lb long guns;
- 10 x 30-lb obuses;
- **76 counted ship-to-ship pieces**.

Working Trafalgar complement: **749**, with detailed composition preserved in the ship-sheet research.

Nominal broadside screening calculation:

- long guns: 806 Spanish lb;
- obuses: 150 Spanish lb;
- total: **956 Spanish lb ≈ 439.8 kg**.

Selection rationale: the 1805 heavy battery is both the better-balanced configuration and the best dated artillery evidence currently available. The `76/80` descriptions found in later narratives must not be converted into four invented combat pieces. Until an original/authoritative record identifies additional ship-to-ship weapons, the pilot uses the 76 counted pieces from the 19 October force-state-derived table.

Confidence: **documented/reconstructed from a transcription explicitly based on commander-signed 19 October 1805 force states; high for the 76-piece combat battery**.

Working length field: **190 pies de Burgos** is preferred for the technical record because multiple technical treatments converge on that value; the 194-foot figure in a modern Defence synthesis remains recorded as a source discrepancy. The primary 1806 plans still need direct dimension extraction before the field is marked fully documented from primary material.

### Bahama

#### 1790 configuration — documented alternative, not selected

Accessible technical history gives a 78-piece fit with:

- 28 x 24-lb long guns;
- 30 x 18-lb long guns;
- 16 x 8-lb long guns;
- 4 x 32-lb obuses;
- 4 additional small top/boat pieces described separately.

Using only the pieces with explicit calibre and broadside placement, the screening total is about **734 Spanish lb ≈ 337.7 kg**, before any unspecified small pieces.

This configuration is less complete for simulation and less balanced against the British pair than the 1805 state.

#### 19–21 October 1805 configuration — selected

The force-state-derived combat battery is:

- 28 x 24-lb long guns;
- 30 x 18-lb long guns;
- 10 x 8-lb long guns;
- 6 x 30-lb obuses;
- 4 x 24-lb obuses;
- 6 small pedreros of 4/3 lb documented aboard but excluded from the principal ship-to-ship count under the source convention;
- **78 counted principal pieces**.

Working operational/action complement: **689**. This figure is supported by a detailed category breakdown that sums to 689 and cites González-Aller's Trafalgar documentary corpus. A 2020 *Revista General de Marina* synthesis prints **702**; that value remains in provenance as a secondary discrepancy rather than being silently discarded.

Nominal broadside screening calculation, excluding the small pedreros from the main ship-to-ship battery:

- long guns: 646 Spanish lb;
- obuses: 138 Spanish lb;
- total: **784 Spanish lb ≈ 360.7 kg**.

Selection rationale: the 1805 state is the best documented battle configuration and gives better pair-level balance than the 1790 configuration. The 689-man operational field is selected because it is tied to an internally enumerated composition; 702 is retained as an alternate secondary summary value.

Confidence: **documented/reconstructed; high for artillery composition, medium-high for 689 operational complement pending direct inspection of the underlying force-state pages**.

## Pair-level result

### Selected 1805 set

Royal Navy:

- Bellerophon: 867 British lb ≈ 393.3 kg per nominal full broadside.
- Conqueror: 876 British lb ≈ 397.3 kg.
- Pair total: **≈ 790.6 kg**.

Real Armada:

- Montañés: 956 Spanish lb ≈ 439.8 kg.
- Bahama: 784 Spanish lb ≈ 360.7 kg.
- Pair total: **≈ 800.6 kg**.

On this deliberately coarse projectile-mass screen, the Spanish pair is only about **1.3% heavier** in total nominal broadside projectile mass. That is close enough that artillery mass alone gives no reason to change the quartet.

More importantly, the distribution is different:

- British selected pair, long-gun nominal broadside mass: ≈ **712.6 kg**.
- Spanish selected pair, long-gun nominal broadside mass: ≈ **668.1 kg**.
- British long-gun edge on this screen: ≈ **6.7%**.
- British carronade nominal projectile mass: ≈ **78.0 kg**.
- Spanish obus nominal projectile mass: ≈ **132.5 kg**.

The last comparison does **not** mean Spanish obuses have 70% more close-range combat power. Obuses and British carronades are different weapons. Velocity, construction, effective range, accuracy, penetration and ammunition effects must be modeled separately. The useful finding is that the pairs are close in aggregate while retaining different tactical weapon mixes.

### Rejected balance alternatives

If Conqueror uses the heavier 1803 establishment while the other three use the selected 1805 configurations, the British pair rises to about **855.0 kg**, roughly **6.8%** above the Spanish pair on the same coarse mass screen. This is less balanced and therefore the 1803 Conqueror fit is not selected for the pilot.

If Montañés uses its 1794 24-lb lower-deck configuration, the Spanish pair loses a very large part of its nominal broadside mass and the matchup becomes clearly less even. Therefore the 1794 Montañés fit is not selected.

Bahama's 1790 fit is both less completely specified for the small pieces and lighter on the same screen than its 1805 state. It is not selected.

## Crew asymmetry — preserved, not tuned away

Selected action/operational complements:

- Bellerophon: 522.
- Conqueror: 573.
- Royal Navy pair: **1,095**.
- Montañés: 749.
- Bahama: 689.
- Real Armada pair: **1,438**.

The Spanish pair therefore has about **31% more raw personnel** in these selected dated figures.

This is a real residual asymmetry and must **not** be removed by borrowing Montañés's 1806/1808 lower complements or Bahama's 1800 complement while keeping their 1805 batteries. That would create synthetic ships in violation of ADR-0002.

Raw headcount is also not equivalent to gunnery efficiency. The Spanish detailed compositions include large infantry/troop contingents, and Velmad itself treats crew quality/combat capability separately from crew number. Later simulation work must therefore distinguish at least total persons, sailors, artillery personnel, troops/marines, casualties, fatigue and evidence-based training/quality. No arbitrary crew-quality tier is assigned in this research pass.

## Sailing and hull balance

No artificial sailing numbers are introduced here.

- Montañés has strong qualitative evidence for exceptional sailing and manoeuvrability and an unusually rich 1806 rig/plan set.
- Bahama has contemporary/near-contemporary qualitative evidence describing it as fast with wind abaft/abeam but less fine close-hauled.
- British ships have strong design-plan coverage, but individual polar performance curves are not yet documented.

These statements may guide later model calibration, but they are not converted into invented knots, acceleration coefficients or polar curves at this stage.

British `tons burthen` and Spanish `arqueo/desplazamiento` are also not summed or directly compared as if they were the same measurement system.

## Pilot configuration decision

The configuration-envelope search does **not** justify moving the four ships away from Trafalgar. The best-balanced historically supported set found in this pass is, in fact, the common 1805 set:

### Royal Navy

- **HMS Bellerophon — Trafalgar, 21 October 1805**
  - 28 x 32-pdr; 28 x 18-pdr; 18 x 9-pdr; 2 x 32-pdr carronades; 6 x 18-pdr carronades.
  - working action complement 522; borne/on-books value stored separately when finalized.

- **HMS Conqueror — Trafalgar, 21 October 1805**
  - 28 x 32-pdr; 30 x 18-pdr; 16 x 9-pdr; 2 x 32-pdr carronades; 6 x 18-pdr carronades.
  - working action complement 573.
  - 1803 heavy-carronade establishment retained as a documented alternative, not used for this pilot.

### Real Armada

- **Montañés — force state 19 October / Trafalgar 21 October 1805**
  - 28 x 36-lb; 30 x 18-lb; 8 x 8-lb; 10 x 30-lb obuses.
  - 76 counted principal combat pieces.
  - working complement 749.

- **Bahama — force state 19 October / Trafalgar 21 October 1805**
  - 28 x 24-lb; 30 x 18-lb; 10 x 8-lb; 6 x 30-lb obuses; 4 x 24-lb obuses.
  - 78 counted principal pieces; small pedreros retained as documented equipment but excluded from the main ship-to-ship battery under the source convention.
  - working operational complement 689; 702 retained as a secondary-source discrepancy.

This selection is now **frozen as the working pilot configuration set** unless stronger primary evidence forces a correction.

## What this resolves

- Conqueror: pilot chooses the Trafalgar-specific 1805 fit rather than the stronger 1803 establishment.
- Montañés: pilot combat model uses the 76-piece 19 October 1805 force-state-derived battery; `80` is not used as an unidentified extra four-gun bonus.
- Bahama: pilot working operational complement is 689, with 702 preserved as a discrepancy.
- Montañés: working length uses 190 pies de Burgos, with 194 preserved as a conflicting secondary value pending primary-plan extraction.
- Pair-level artillery screening shows that the selected 1805 set is unusually close in aggregate broadside projectile mass without any invented balancing modifier.

## What remains before implementation

The configuration choice is frozen, but the **research gate is not yet fully closed**. Before creating the feature branch or modifying simulator code:

1. complete one technical sheet per ship with every field labelled documented, reconstructed, estimated or unknown;
2. explicitly preserve Bellerophon's action complement versus men-borne/muster concepts;
3. attach exact British and Spanish measurement conventions to all dimensions and derived SI values;
4. extract rig/mast/sail evidence from the available plans where possible, especially the Montañés 1806 set;
5. finish the RMG image/plan licensing review before using British plans as redistributable game assets;
6. record crew composition/training evidence without assigning arbitrary quality bonuses;
7. keep the 1803 Conqueror, 1794 Montañés and 1790 Bahama configurations as provenance/reference alternatives, not hidden tuning options.

No code changes are authorized by this note alone.
