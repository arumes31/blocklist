---
version: 1
slug: "cmd-server-templates-admin-management-html"
primary_target: "cmd/server/templates/admin_management.html"
related_targets: ["cmd/server/static/js/identity.js"]
---

# Account search and status

Mode: Operate. Extend the existing Accounts page with Hookwise-like name/UPN search, source filtering, visible account status and reversible Disable/Enable controls. Preserve account creation, role assignment, identity details, credentials, UPN display and the current neutral visual system.

## Direction contract

THESIS: Find the intended identity quickly and understand its access state before making a reversible change.

OWN-WORLD: Inherit Blocklist's charcoal surfaces, system sans, seven-pixel control corners and semantic positive/warning colors. No new assets or identity.

STORY: Search a name or UPN, narrow by local/Entra source or status, review the matching count, then confirm a status change. Empty and failed states explain recovery without losing filters.

FIRST VIEWPORT: Existing creation disclosure stays above the workspace account table. A compact labeled search/filter toolbar joins the table heading. A Status column precedes existing actions, with textual Active/Disabled badges and adjacent Enable/Disable controls.

FORM: User-assigned Hookwise behavior inside an existing surface; no concept roll, seed or comp required. Filtering is immediate, keyboard-operable and preserved through reloads. All access is blocked while disabled; recovery and self-disable safeguards remain visible.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
