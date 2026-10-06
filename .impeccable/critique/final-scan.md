# Final mechanical scan

One post-build Impeccable scan covered all templates and the shared stylesheet. It reported 22 raw matches (18 warnings, 4 advisories). These are observations, not distinct defects or a quality score.

Corrected: four skipped-heading reports by using h2 section titles without changing their visual size; three hover-contrast reports by darkening the red hover to #c34651 (white text exceeds 4.5:1).

Reviewed exceptions:

- Nine cramped-wrapper reports: table wrappers deliberately have no inset; cells have 14px by 16px padding and empty messages have 42px by 20px padding. Dashboard insight wrappers are transparent and borderless at runtime.
- The TOTP setup fragment is reported against a white fallback canvas. Its actual parent is the dark sign-in surface; white exists only behind the QR image.
- A threat-map glow belongs to the pre-existing map marker stylesheet; the map scene and visualization logic are retained. Navigation/header/status-dot glows are overridden by the shared stylesheet.
- Authentication uses a neutral shadow and defined edge to separate the retained animated background from the input surface. No decorative colored glow is added.
- Em-dash reports are pre-existing code examples containing command-line flags and map placeholder dashes, not newly authored prose.

The static scanner cannot resolve some root-relative vendor stylesheets. Browser screenshots and computed page-width checks cover the actual mounted app. No second detector run was made.
