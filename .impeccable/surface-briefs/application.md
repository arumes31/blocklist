# Application redesign

Targets: cmd/server/templates and cmd/server/static/css. Mode: Operate; API documentation also serves Read.

## Direction contract

THESIS: A calm, precise workspace for managing network access, with the searchable data and its actions clearly ordered.

OWN-WORLD: Charcoal canvas, subtly lighter panels, cool neutral rules, legible off-white type, muted supporting text. Restrained red for identity and destructive intent; green only for successful state. Familiar system sans with monospace reserved for addresses and code.

STORY: Sign in, understand current status, locate a record, and act with context. Settings, lists, and documentation share the same shell.

FIRST VIEWPORT: A 216px navigation rail, compact page header, compact status band, organized search controls, then the main data table. On mobile the rail becomes a two-row navigation grid with every route visible; forms stack and tables scroll within their own containers.

FORM: User-pinned contemporary neutral operational UI. Direct code implementation is required by the brief. Concept seed 7f8a3f2e, Operate, assigned index 6; challenger service unavailable. No approved image comp: this is a code-led replacement guided by the brief and incumbent screenshots. Signature: the retained animated login background behind a quiet, legible sign-in panel. Existing motion and application state remain unchanged.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

No new raster assets; existing login background is rendered by the existing animation code. No business logic or state changes.
