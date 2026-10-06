---
version: 1
slug: "cmd-server-templates-threat-map-html"
primary_target: "cmd/server/templates/threat_map.html"
related_targets: ["cmd/server/static/js/threat-map.js", "cmd/server/static/js/threat-map-scene.js", "cmd/server/static/css/app.css"]
---

# Threat-map group inspection

Mode: Operate. Fix the user's inability to zoom past country level and inspect a count such as 29 IPs in Austria. Keep the incumbent map, responsive console and application design system; this is an interaction extension, not a new visual world.

## Direction contract

THESIS: Every displayed count must lead to its underlying IP records without implying more geographic accuracy than the source provides.

OWN-WORLD: Existing charcoal controls and neutral typography frame the original red globe. Reuse the IP activity rail, selected-record details, focus styles and button treatment. No new raster assets or modal.

STORY: Select a count, zoom into its region, inspect all members in the paginated IP activity list, and return to All IPs. A zoom readout and disabled end stops make the available range explicit.

FIRST VIEWPORT: Keep the map as the dominant surface. Group selection reveals a compact, wrapping explanation and View IPs / All IPs actions immediately below its toolbar. The existing list is alongside the map on desktop and below it on phones.

FORM: Code-led maintenance of a user-provided surface. No concept roll or comp round. Desktop and mobile screenshots plus real browser interaction tests are the verification evidence.

## Implemented behavior

- Globe magnification spans 0.8–128×; wheel, keyboard and buttons share the same bounds. Flat-map levels remain 1–18 and are explicitly labelled Z.
- Overlapping origins group even in small datasets; blocked and whitelisted counts stay separate. A group retains every member rather than only a representative IP.
- Selecting a group centres on an actual member and doubles magnification within its bounds. Every member remains reachable in six-record pages even when coordinates coincide. Automatic rotation pauses during group inspection.
- The list follows the selected member IDs through refreshes, updates metadata and drops removed records. New records are not silently added to that selection. Filter, region, layer, projection and reset controls clear the group scope.
- Equal coordinates are disclosed explicitly. Zoom changes projection scale, not GeoIP coordinates, source accuracy or boundary detail. No fabricated jitter, third-party tile requests or backend changes.
- The desktop console's minimum height follows the map content, including the group explanation, instead of a fixed-height floor. Short windows scroll the page without clipping the toolbar or legend; side panels retain their local scrolling.

## Verification

`tests/threat_map_scene.test.cjs` covers deep zoom, bounded canvas allocation, coincident and nearby origins, complete group membership and stationary inspection, alongside the existing 20,000-record count test. `tests/threat_map_controller.test.cjs` covers pagination, selection, refreshed metadata and zoom controls. `tests/e2e/threat_map_groups.spec.cjs` uses labelled synthetic responses in the isolated test stack on desktop and mobile; it does not write sample IPs to the database.
