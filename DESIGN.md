---
name: Blocklist
description: A calm, precise workspace for managing network access.
colors:
  canvas: "#111316"
  surface: "#191c20"
  surface-raised: "#22262b"
  surface-hover: "#2c3138"
  ink: "#eef0f3"
  muted: "#a5adb8"
  subtle: "#909aa7"
  rule: "#30363e"
  accent: "#e36b70"
  accent-soft: "#362327"
  positive: "#84d6b1"
  warning: "#e5c17e"
  negative: "#ff9b9e"
  focus: "#b5c9ee"
  primary-red: "#b63f49"
  primary-red-hover: "#c34651"
  primary-ink: "#17191d"
  primary-hover: "#cfd5de"
  white: "#ffffff"
  input-background: "#14171b"
  input-border: "#3b424c"
  destructive-background: "#38252a"
  destructive-ink: "#ffacb0"
  destructive-hover: "#4c2a32"
  live-background: "#20372e"
typography:
  headline:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "25px"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.025em"
  heading:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "20px"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.015em"
  title:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "17px"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.01em"
  body:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  control:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "13px"
    fontWeight: 500
    lineHeight: 1.4
  label:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    fontSize: "12px"
    fontWeight: 500
    lineHeight: 1.5
  code:
    fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace'
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.7
rounded:
  inline-code: "4px"
  chip: "5px"
  control-radius: "7px"
  inset: "8px"
  popup: "10px"
  radius: "12px"
  dialog: "14px"
  auth: "16px"
spacing:
  tight: "4px"
  small: "8px"
  control-gap: "12px"
  mobile-gutter: "16px"
  filter-inset: "20px"
  panel-inset: "24px"
  dialog-inset: "28px"
  desktop-gutter: "36px"
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.primary-ink}"
    typography: "{typography.control}"
    rounded: "{rounded.control-radius}"
    padding: "8px 14px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.primary-ink}"
  button-secondary:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.ink}"
    typography: "{typography.control}"
    rounded: "{rounded.control-radius}"
    padding: "8px 14px"
  button-secondary-hover:
    backgroundColor: "{colors.surface-hover}"
  button-enforce:
    backgroundColor: "{colors.primary-red}"
    textColor: "{colors.white}"
    typography: "{typography.control}"
    rounded: "{rounded.control-radius}"
    padding: "8px 14px"
  button-enforce-hover:
    backgroundColor: "{colors.primary-red-hover}"
  button-destructive:
    backgroundColor: "{colors.destructive-background}"
    textColor: "{colors.destructive-ink}"
    typography: "{typography.control}"
    rounded: "{rounded.control-radius}"
    padding: "8px 14px"
  button-destructive-hover:
    backgroundColor: "{colors.destructive-hover}"
    textColor: "#ffd0d3"
  button-success:
    backgroundColor: "#21362e"
    textColor: "{colors.positive}"
    typography: "{typography.control}"
    rounded: "{rounded.control-radius}"
    padding: "8px 14px"
  input:
    backgroundColor: "{colors.input-background}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control-radius}"
    padding: "10px 12px"
  navigation-item:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "{rounded.control-radius}"
    padding: "10px 12px"
  navigation-item-active:
    backgroundColor: "#2a252b"
    textColor: "{colors.ink}"
  chip-live:
    backgroundColor: "{colors.live-background}"
    textColor: "{colors.positive}"
    typography: "{typography.label}"
    rounded: "{rounded.chip}"
    padding: "3px 8px"
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.radius}"
    padding: "{spacing.panel-inset}"
  auth-panel:
    backgroundColor: "#191c20ed"
    textColor: "{colors.ink}"
    rounded: "{rounded.auth}"
    padding: "{spacing.desktop-gutter}"
  auth-login-panel:
    backgroundColor: "#191c20f2"
    textColor: "{colors.ink}"
    rounded: "{rounded.auth}"
    padding: "{spacing.desktop-gutter}"
---

# Design System: Blocklist

## Overview

**Creative North Star: "A calm, precise workspace"**

Blocklist uses charcoal surfaces, restrained color, and familiar controls to make network access records easy to scan and act on. The visual voice is contemporary, neutral, and exact. Shared navigation, quiet borders, and compact typography give dense operational screens a consistent rhythm.

The original animated APNG wordmark anchors the shared shell and sign-in screen. Sign-in pairs the wordmark with a stable translucent form and the restored original Aether particle animation. Five related backgrounds use the same engine with distinct flow patterns. At the user's explicit request, branding animations autoplay even under reduced-motion or remote-session settings; sign-in retains its manual Pause control. The system records the presentation implemented in `cmd/server/static/css/app.css` and the API documentation field stylesheet; workflow and content decisions remain in PRODUCT.md and the application surface brief.

**Key Characteristics:**

- Neutral surfaces with clear text and subtle dividing rules.
- Color distinguishes routine actions, enforcement, destructive intent, and state.
- Compact data layouts adapt to narrow screens without hiding permitted routes.
- Motion supports feedback; sign-in branding autoplays and remains manually pausable.

## Colors

The palette is cool charcoal with off-white text and restrained semantic accents. Frontmatter values are normative; compatibility aliases in the stylesheet resolve to the same underlying roles.

### Primary

Off-white **ink** fills routine primary actions such as Add Webhook and Create Token. Deep **primary red** fills Block IP and authentication actions; its lighter hover shade gives immediate feedback. Soft **accent red** marks the identity, active navigation icons, selected map origins, and API documentation emphasis.

### Secondary

Muted red **destructive background** with pale **destructive ink** identifies delete and revoke actions. **Positive** green indicates live, healthy, active, or successful state. **Warning** amber indicates paused or cautionary state; **negative** pink-red indicates offline, failed, or blocked state. Existing IP/type badges retain their contextual blue, violet, and ochre distinctions.

### Neutral

**Canvas**, **surface**, **surface-raised**, and **surface-hover** establish the background and interaction layers. **Ink** carries principal content, **muted** supports it, and **subtle** serves small contextual text and placeholders. **Rule** separates regions. Inputs use a darker inset and a stronger border; **focus** blue identifies keyboard interaction.

**The Semantic Action Rule.** Routine primary actions use off-white; enforcement and sign-in use solid red; destructive actions use muted red; green communicates live or successful state.

## Typography

System sans is intentional for this operational UI: the native Apple or Windows face falls back through Roboto, Helvetica, and Arial. There is no separate display family or imported webfont. Monospace is reserved for addresses, secrets, and code, using SFMono-Regular, Consolas, and Liberation Mono.

Page headings use **headline**, section headings use **title**, and longer content uses **body**. The general secondary heading role is **heading**. Controls and table cells are compact (13px); labels, status chips, and supporting metadata generally use **label**. Paragraphs increase line-height to 1.65. Ordinary explanatory text is limited to about 65–75 characters per line; selected notices allow 85.

Dashboard values use tabular numerals (25px, weight 550, line-height 1.2); map totals use a larger equivalent (32px). At the mobile breakpoint, page headings become 23px and editable fields become 16px. Authentication headings are 24px. The existing logo supplies its own lettering; its raster type is not a UI font.

## Layout

At desktop widths (992px and above), the shell reserves a compact icon rail (68px) beside the flexible main column. Its full navigation panel (214px) overlays content when hovered or focused; the main column does not move. Content uses 36px horizontal gutters and a maximum width of 1740px; settings cap at 1500px. Page headers wrap their action group. Cards use the panel inset, settings cards use 28px, and search panels use the filter inset. Small gaps are typically 8–12px; related sections separate by 20–28px.

Threat Map is a display-filling exception: its header and content have no maximum-width cap. Above 1200px, 28px gutters frame bounded side panels (200–280px left, 220–320px right) and a flexible visualization column. The console consumes the remaining viewport height after the header, live status, and statistics, with a 660px usability floor; short windows retain normal page scrolling and long side-panel content scrolls locally. The existing canvas renderer sizes the globe to this larger region without changing its projection or zoom logic. At 1200px and below the map-first stacked layout returns, with 24px gutters and 16px on phones.

| Viewport | Implemented change |
| --- | --- |
| 1200px and below | Gutters become 24px; permission and webhook grids use two columns; map viewport moves above its supporting columns. The desktop rail retains its compact and expanded widths. |
| 991px and below | Rail becomes a top navigation area with four columns and up to three rows for ten permitted routes; account actions remain accessible. |
| 900px and below | Content headers and filters become more compact. Roles stack their list above the editor, and sign-in stacks its logo above the form. |
| 600px and below | Gutters become 16px; navigation labels remain visible while icons hide; forms and permission sections stack; ordinary cards use 18px padding. |
| 1800px and above | Standard page headers align to the 1740px maximum width; Threat Map remains full-width. |

Dashboard summaries use seven desktop columns, four at the intermediate breakpoint, and three on mobile with the final statistic spanning the row. Detailed tables preserve their columns in local scrolling containers (680px minimum table width; dashboard 960px). Code examples scroll locally. The API documentation uses its exported CSS parts to wrap request action buttons on mobile. The map places the viewport first, then stacks its supporting regions on small screens.

Dashboard rankings retain all server-provided top-ten entries on initial load and live refresh. Countries, ASNs and reasons share compact neutral chips; long labels wrap within their column while tabular counts never shrink or truncate. The three ranking columns stack below 600px. Refreshes preserve the same presentation, and a failed refresh keeps the previous entries visible.

Desktop sign-in uses a two-column composition capped at 1040px: a 270px wordmark in the flexible identity column and a 420px form, separated by 100px (48px below 1200px). Below 900px the composition stacks within 430px, with a 230px wordmark and no introductory identity copy. The form remains visible throughout interaction. Roles use a 280px list beside a flexible editor (230px below 1200px); the list becomes three columns below 900px and one column below 600px. Grouped permission choices and account form fields use two columns before stacking on mobile.

**The Local Overflow Rule.** Wide tables and code scroll inside their own region; they must not widen the page.

**The Stationary Workspace Rule.** Desktop navigation reveals its labels over the page while icons and the main content stay in place; hover and keyboard focus share the same open state.

## Elevation & Depth

The workspace uses tonal layering and single-pixel borders. Cards and ordinary controls have no shadow or background blur. Modals use a darker scrim with modest blur (3px), a raised surface, and a stronger outline. The sign-in panel is the deliberate translucent exception, using blur (16px) over the Aether particle field.

Toast shadow: `0 12px 40px #0005`. Authentication panel shadow: `0 24px 80px #0006`. Focused inputs use a soft ring (`0 0 0 3px #b5c9ee1a`); focusable controls also receive a two-pixel focus outline with a three-pixel offset.

**The Quiet Surface Rule.** Keep ordinary workspace surfaces flat; reserve shadow and blur for transient feedback and the authentication panel.

## Shapes

The form language is softly rectangular: the shared surface radius is **radius**, controls use **control-radius**, and compact status chips use **chip**. Insets and code panels use **inset**, popups and toasts use **popup**, dialogs use **dialog**, and the login panel uses **auth**. Circular geometry is reserved for actual dots, the spinner, and map imagery.

Use thin rules to divide records and regions. Buttons retain a visible rectangular footprint; navigation icons are inline stroked SVG, not text glyph substitutes.

## Components

### Buttons

Routine primary, secondary, enforcement, destructive, and successful variants share the same geometry and sentence-style labels. General controls have a 38px minimum height; standard mobile buttons increase to 42px. Table actions and compact data controls have smaller established variants. Authentication actions fill the panel width and are at least 46px tall.

Hover changes fill and border without lifting the button. State transitions take 160ms; active secondary controls darken. Disabled controls reduce opacity to 0.45 and show the disabled cursor. Legacy class names do not determine semantics: the inherited danger class also appears on routine off-white actions.

### Inputs and fields

Dark insets, visible borders, and restrained placeholders keep fields legible. Text-like inputs, including inputs without an explicit type, selects, and textareas inherit the shared rounded field treatment without requiring a class. Standard fields have a 42px minimum height, with mobile fields at least 44px and 16px text; compact table/filter variants retain their established sizing. Textareas start at 96px and resize vertically. Authentication fields use the wider panel layout. Focus changes the border and adds the pale blue ring over 150ms; enabled editable fields strengthen their border on hover. Read-only fields use muted text on the canvas tone, disabled fields reduce opacity, and invalid fields use the negative border color.

Single-choice selects retain native selection behavior with an inset SVG chevron; forced-colors mode restores the native appearance. Preserve visible labels, accessible names, and checkbox/radio behavior. API documentation fields use the same inset, border, radius, and responsive sizing through RapiDoc's shadow-root stylesheet and exported field parts.

### Navigation

The shared rail uses the original wordmark, 18px stroked icons, muted labels, and a quiet raised hover surface. The current route receives a tinted neutral fill, a muted red border, off-white text, and an accent icon. Its ten destinations are Dashboard, Threat Map, Whitelist, Excluded, Event logs, System audit logs, Settings, Accounts, Roles, and API Docs. Accounts and Roles respect their read/manage permissions; system audit and IP event history have separate permission-aware destinations. Narrow layouts show all permitted route labels in the navigation grid; a skip link becomes visible on keyboard focus.

On desktop, the panel starts translated left (-146px) while its inner navigation translates right (146px). These opposing translations keep the logo mark and icons stationary. Link and wordmark clipping reveal their labels with the panel; the caption and account details fade with the same timing. Hover or focus within opens the panel, and it closes after both leave. Opening takes 260ms after a 70ms delay; closing takes 240ms after an 80ms delay, both using `cubic-bezier(.4,0,.2,1)`. Links retain accessible text while clipped, and desktop keyboard focus uses an inset two-pixel blue ring that stays inside the clipped area. The inner rail scrolls vertically when needed, keeping account actions reachable on shorter screens.

Selecting a navigation destination preserves the expanded panel through the full page load, with no closing/reopening animation. A small shared script carries a one-use, destination-scoped state through session storage and restores it before the sidebar renders. Menu scroll position is retained; keyboard navigation also restores focus to the destination link. Moving into page content releases the carried state so normal CSS hover/focus behavior resumes. The handoff expires after one minute, ignores modified/new-tab clicks, and does not affect the mobile navigation grid. If JavaScript or storage is unavailable, ordinary links and CSS hover/focus remain usable.

The user-requested Hookwise behavior retains its rail transition timing under reduced-motion preferences, including Windows/RDP sessions. The original animated wordmark also runs in visible pages at the user's explicit request, using a static poster only while the document is hidden. Below 992px, the existing labeled top navigation grid has no sliding or clipping interaction.

### Chips

Status chips combine a short textual state with semantic color and a thin border. Live/success is green, paused is amber, and offline/failure is pale red. Record-type badges retain their existing labels and contextual colors. Static status chips are informational, not buttons.

### Cards and tables

Cards group forms or related content with a flat surface and thin rule. Tables use a slightly lighter header, compact labels, tabular numerals, and a subtle row hover. An empty region shows a short title and explanation; the empty state stays inside its table region. Pagination wraps, with the page count moving above mobile actions.

### Identity and activity

Roles use a compact selectable list and one editor, with capabilities grouped by named fieldset legends and explanatory text. Selected roles gain a raised fill and visible border. Accounts pair a collapsible creation form with a metadata table. Microsoft Entra creation asks for UPN and role; local name/password fields are hidden and disabled for that method. Help text explains automatic first-sign-in binding and app-role synchronization. Unbound accounts show “Pending first sign-in”; after binding, immutable IDs remain available in the row's secondary details rather than in the creation form. Row actions wrap within the available width. Read-only views omit write controls. System audit and event logs retain the common table and filter vocabulary while separating their activity categories.

Entra account labels use the stored UPN in the account table, navigation footer,
role-field labels and confirmation dialogs. Local accounts keep their account
name; Entra accounts without a UPN fall back to their existing name. Account
labels wrap within a bounded table column, while the compact navigation footer
retains its ellipsis and exposes the full label in its title. Immutable account,
tenant and object keys remain under Identity binding; action payloads and
authorization continue to use the original account key.

### Dialogs and authentication

Dialogs remain constrained to the viewport, with independently scrolling content and wrapped forms. Drawers enter from the right over 220ms using `cubic-bezier(.22,1,.36,1)`. Toasts enter over 200ms; row arrival and highlight feedback remain short and localized.

The sign-in form uses the split composition described in Layout, left-aligned title and introduction, and the more opaque auth-login-panel surface without a border. The form stays visible while local credentials, TOTP, or configured Microsoft authentication progress. Setup screens retain the centered auth-panel treatment.

The restored Aether engine retains the original red noise-driven particles, cursor gravity, quantum effects, glowing mesh interactions, ripples, and roaming scanners on black. Neural Mesh is the user-selected default. A labeled native Background selector keeps Original Aether and five sibling presets available: Ember Tide (warm horizontal currents), Vortex (crimson spiral), Aurora (teal-blue ribbons), Neural Mesh (blue drifting connections), and Sonar (outward red flow and signal rings). All presets share the original interactions. Selection changes immediately and is stored only as a local browser preference; unavailable or invalid storage falls back to Neural Mesh. The versioned preference starts with this approved default rather than a choice saved during the earlier preview. On desktop the selector sits opposite the utility links; below 900px it moves to a second row, with 44px controls and 16px select text on phones. Selection while paused paints a still preview without restarting motion.

The background and original animated logo autoplay on every sign-in page load, regardless of reduced-motion settings or earlier saved pause preferences, as explicitly requested by the user. The visible Play/Pause control stops both for the current page; reloading starts them again. Playing uses full canvas opacity. The loop targets about 30 frames per second, advances movement by bounded elapsed time, caps pixel ratio at 1.5, and starts with 1,000 particles on desktop or 500 on phones. Neural Mesh connections use a bounded particle sample. Hidden documents stop painting and use static logo posters, then resume their prior state when visible. The form and utilities repel particles; layout observers refresh these bounds when authentication steps change. Shared-shell wordmarks likewise animate whenever visible. Other reduced-motion CSS remains intact: it shortens transitions and animations to 0.01ms, limits animation iterations to one, and disables smooth scrolling, except for the user-triggered desktop rail transitions described in Navigation. The sign-in script independently controls its animation loop. If the animation cannot initialize, sign-in remains usable and motion controls are disabled.

**The Presentation Boundary Rule.** Visual changes preserve application requests, state, permissions, element IDs, event attributes, and script-owned behavior.

## Do's and Don'ts

### Do:

- Do reuse the shared shell, tokens, and control geometry.
- Do keep action and status colors tied to their documented meaning.
- Do keep forms readable and permitted navigation visible at narrow widths.
- Do preserve keyboard focus and local scrolling for wide records and code.
- Do keep desktop icons and content stationary as navigation opens on hover or keyboard focus.
- Do retain the original animated wordmark and the sign-in particle character, with pause and reduced-motion behavior.

### Don'ts:

- Don't turn routine actions red because a legacy class name contains danger.
- Don't add decorative elevation or blur to ordinary workspace panels.
- Don't use the logo lettering as a general interface font.
- Don't change workflows, requests, permissions, or script behavior during presentation work.
