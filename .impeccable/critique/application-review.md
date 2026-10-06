# Application critique — 2026-10-05

Method: independent Assessment A (critique_design) and Assessment B (critique_evidence). Baseline source review; connected browser unavailable. Local automated rendering is a separate verification step.

| Heuristic | Score / 4 |
| --- | --- |
| System status | 3 |
| Real-world match | 3 |
| User control | 3 |
| Consistency | 2 |
| Error prevention | 2 |
| Recognition | 3 |
| Efficiency | 3 |
| Minimalist design | 1 |
| Error recovery | 2 |
| Documentation | 3 |
| Total | 25 / 40 |

Strengths: useful live state and retry feedback; filters, saved views and bulk operations; documentation and permission templates. Visual identity is dominated by black glass panels, red glows, gradients and competing controls.

Priority issues: P1 responsive header/form/modal widths; P1 conflicting action-color semantics; P1 dashboard hierarchy; P2 inconsistent page shells; P2 small/low-contrast metadata and controls. Fix through shared styling, semantic markup, bounded overflow and component hierarchy. Keep all behavior intact.

Detector: 154 raw matches, 128 warnings and 26 advisories. 83 glow; 24 border/shadow; 23 contrast; 5 tiny text; 5 hierarchy; 3 padding; 2 each undersized UI, capitals, side-tab, em-dashes, tracking; 1 font. Baseline JSON is archived alongside this report. Counts are repeated matches, not distinct usability failures. Important false positives: fragment background assumptions, flush table wrappers, map hidden heading, command-line double hyphens, missing-value dashes, and some focus shadows.

Personas: operators face competing controls; low-vision users face small metadata; mobile users face wide forms and dialogs. Existing click-only reason chips are a markup accessibility opportunity; underlying functions must stay intact.

Questions skipped: user already specified all-pages scope, neutral contemporary design, responsive behavior, preserved login background, and no business-logic changes. An optional theme preference was offered; charcoal remains the working assumption pending any answer.

No overlay injection or live detector server. No production data inspected or changed.
