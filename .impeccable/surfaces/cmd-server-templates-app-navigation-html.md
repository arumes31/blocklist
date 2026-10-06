---
version: 1
slug: "cmd-server-templates-app-navigation-html"
primary_target: "cmd/server/templates/app_navigation.html"
related_targets: ["cmd/server/static/css/app.css"]
---

# Hover navigation rail

Mode: Operate. User-assigned narrow extension: match the local Hookwise project's auto-closing sidebar behavior and settings, keeping Blocklist's routes, permissions, logo and visual language.

Source of behavior: ../hookwise/static/css/hookwise-console.css. Desktop starts at 992px; collapsed rail 68px, expanded panel 214px. Open 260ms after 70ms; close 240ms after 80ms; cubic-bezier(.4,0,.2,1). Hover or keyboard focus opens the rail. Leaving both closes it. Page content remains stationary. Below 992px, preserve Blocklist's touch-friendly top navigation.

Motion thesis: the panel slides behind stationary icons, revealing labels through a synchronized clip. No continuous animation, dependency, or business-state change. Match Hookwise's explicit Windows/RDP reduced-motion exception for user-triggered rail transitions; decorative logo motion still respects reduced motion.

## Direction contract

THESIS: Reclaim workspace width until navigation is needed, without shifting the user's work.

OWN-WORLD: Inherit Blocklist's charcoal, restrained red active states, system sans and original animated wordmark.

STORY: Recognize the active route by its icon; hover or tab into the rail to reveal all permitted destinations; choose a route and return to a compact workspace.

FIRST VIEWPORT: A 68px icon rail sits at the desktop left edge; its 214px panel overlays content on interaction. Logo mark, icons and sign-out remain reachable. Mobile retains the existing labeled navigation grid.

FORM: Precisely user-assigned Hookwise behavior inside the incumbent Operate world; no new-world roll, seed or comp. Signature interaction: a counter-translated panel with stable icon positions and clipped label reveal.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
