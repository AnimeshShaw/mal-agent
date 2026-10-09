---
name: mal-agent Screening Console
description: A baggage-X-ray screening station for malware triage — primary classifier screening, secondary LLM inspection, and a verdict, never a tool-card grid.
colors:
  ground: "#0a1013"
  panel: "#10181c"
  panel-2: "#152026"
  rule: "#22323a"
  ink: "#e4edf1"
  ink-2: "#a9bcc5"
  ink-3: "#7f949e"
  tool: "#5fb0ff"
  tool-bg: "#0f2638"
  sample: "#ffa24a"
  sample-bg: "#2d1c0c"
  clear: "#5ed69a"
  clear-bg: "#0e2a1e"
  alarm: "#ff5c74"
  alarm-bg: "#33121a"
  inspect: "#f4c542"
  inspect-bg: "#2e260b"
  idle: "#5f7580"
typography:
  display:
    fontFamily: "Barlow Condensed, Barlow, ui-sans-serif, sans-serif"
    fontSize: "clamp(1.875rem, 3vw, 3rem)"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "0.02em"
  headline:
    fontFamily: "Barlow Condensed, Barlow, ui-sans-serif, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.03em"
  label:
    fontFamily: "Barlow Condensed, Barlow, ui-sans-serif, sans-serif"
    fontSize: "13px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.05em"
  body:
    fontFamily: "Barlow, ui-sans-serif, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  data:
    fontFamily: "JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "0.86em"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
rounded:
  sm: "2px"
  md: "6px"
  lg: "8px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
components:
  panel:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.lg}"
  chip:
    backgroundColor: "{colors.tool-bg}"
    textColor: "{colors.tool}"
    rounded: "{rounded.sm}"
    padding: "2px 6px"
    typography: "{typography.label}"
  button-primary:
    backgroundColor: "{colors.tool}"
    textColor: "{colors.ground}"
    rounded: "{rounded.md}"
    padding: "12px 20px"
    typography: "{typography.headline}"
  button-primary-hover:
    backgroundColor: "{colors.tool}"
    textColor: "{colors.ground}"
    rounded: "{rounded.md}"
    padding: "12px 20px"
---

# Design System: mal-agent Screening Console

## Overview

**Creative North Star: "The Baggage X-Ray Screening Station"**

The interface is built around one operational fact, not a marketing shell: every file passes through primary screening (the EMBER classifier reading a calibrated score), and only files that read as hard cases go on to secondary inspection (an LLM adjudicator that must cite tool evidence). The signature component, the `LaneStrip`, makes this literal — two stations connected by directional connectors, ending in a verdict — so the page's own layout is the file's route through the checkpoint, not a badge slapped over a grid of tool cards.

Colour is borrowed directly from baggage X-ray false-colour imaging and carries real semantic weight, not decoration: blue is a tool-derived fact, orange is text copied verbatim out of the sample (attacker-controlled, so it can supply context but never proof), green is cleared, red is flagged, amber is secondary inspection in progress, and a desaturated gray is idle/not-applicable. Dark is the default scene — an analyst at a monitor beside a disassembler — with a lighter "printed screening slip" mode as the alternate. The one authored motion, a single blue sweep across the lane strip on report open, echoes a bag's image resolving on a screening monitor; it never repeats and respects `prefers-reduced-motion`.

This is an Operate-mode tool for a professional under time pressure (per internal/PRODUCT.md): density and legibility outrank visual flourish, tool failures are never hidden, and the classifier is the only mechanism that decides — every other panel explains.

**Key Characteristics:**
- Six-colour semantic system borrowed from a real-world imaging convention (X-ray false colour), not an arbitrary brand palette.
- Barlow Condensed for all signage/UI chrome (headings, labels, buttons); Barlow for reading prose; JetBrains Mono strictly for data (hashes, scores, paths).
- Flat, panel-and-rule construction with almost no shadow; the only glow is a small state lamp.
- One authored motion (the scan sweep), everything else is instant or a simple opacity/width transition.

## Colors

The palette pairs a near-black console ground with six saturated semantic accents; each accent owns a paired `-bg` wash used for chips and highlighted rows, never for large surfaces.

### Primary
- **Tool Blue** (`--tool` `#5fb0ff` dark / `#0b5fb3` light): the "fact" colour. Used for anything a deterministic tool computed — links, focus rings, the submit button, evidence citations, the primary-screening station's active elements. Its paired wash `--tool-bg` marks tool-provenance chips and the highlighted/target evidence row.

### Secondary
- **Sample Orange** (`--sample` `#ffa24a` dark / `#a44c00` light): attacker-controlled text. Any string copied verbatim out of the sample (extracted IOCs, sample-text evidence excerpts) is rendered in this colour on its `--sample-bg` wash, so it is visually inseparable from *unverified* — the product's hard rule that sample text is context only, never support for a verdict, is carried in colour, not just prose.

### Tertiary
- **Inspect Amber** (`--inspect` `#f4c542` dark / `#8a6400` light): secondary inspection in progress or unresolved. Used for the classifier's gray band on the score scale, the "flagged" connector, route-reason warning icons, and any "set aside" or "could not determine" note.

### Neutral
- **Console Ground** (`--ground` `#0a1013` dark / `#eef2f3` light): page background.
- **Panel** (`--panel` `#10181c` dark / `#ffffff` light): card/station surfaces; **Panel 2** (`--panel-2` `#152026` dark / `#f5f8f9` light) is the one-step-up surface for active tabs, hovered rows, and score-scale track backgrounds.
- **Rule** (`--rule` `#22323a` dark / `#d3dde1` light): all borders and dividers — the system has no shadow-drawn separation, only rule lines.
- **Ink / Ink-2 / Ink-3** (`#e4edf1` / `#a9bcc5` / `#7f949e` dark; `#0e1a1f` / `#3c5059` / `#5a6e77` light): primary text, secondary text/labels, and tertiary/disabled text, in descending emphasis.
- **Clear Green** (`--clear` `#5ed69a` dark / `#11774a` light) and **Alarm Red** (`--alarm` `#ff5c74` dark / `#b3163a` light) complete the six-colour verdict set alongside Tool Blue, Sample Orange, and Inspect Amber; **Idle Gray** (`--idle` `#5f7580`) marks not-yet-applicable/not-needed state (e.g. the secondary-inspection station when a file was cleared and never routed).

### Named Rules
**The Six-Colour Limit Rule.** Every colour on screen resolves to one of exactly six semantic roles (tool / sample / clear / alarm / inspect / idle) or the neutral ink/panel/rule scale. There is no seventh accent, no decorative colour, and no verdict word or chip is ever coloured outside `TONE_TEXT`/`TONE_CHIP`'s fixed mapping.

**The Orange Never Proves Rule.** Sample-text orange is a warning colour, not a highlight colour: anywhere it appears (evidence excerpts, extracted IOCs), the surrounding copy says the same thing the colour says — this is the sample's own words, not a verified fact.

## Typography

**Display/Signage Font:** Barlow Condensed (with Barlow, ui-sans-serif fallback)
**Body Font:** Barlow (with ui-sans-serif, system-ui fallback)
**Data Font:** JetBrains Mono (with ui-monospace, SFMono-Regular, Menlo fallback)

**Character:** A condensed, uppercase signage face for every piece of UI chrome (page titles, station labels, button text, chips, tab labels) paired with a plain grotesque for reading prose, and a strict mono carve-out for anything that is literally data. The pairing reads as instrumentation, not editorial: labels are terse and tracked wide; body copy is short and never decorative.

### Hierarchy
- **Display** (700, `text-3xl`/`text-2xl`, tracking-wide): page `<h1>` titles ("Screen a file", "Run log", the sample filename on the report).
- **Headline** (700, `text-lg`, uppercase, tracking-wide): `SectionHead` titles, fieldset legends, tab/radio labels.
- **Verdict word** (700, `text-4xl`–`text-5xl` on the report, uppercase, tracking-wide): the one place display-scale type carries a single word rather than a sentence — the verdict itself.
- **Label** (600, 12.5–13px, uppercase, tracking-wide): chips, station titles, table headers, status words (Ran/Partial/Skipped/Error).
- **Body** (400, 15px base, 1.5 line-height): all prose — descriptions, findings, narrative text, route-reason detail. Narrative prose is capped at `max-w-[75ch]`.
- **Data** (mono, 0.86em): hashes, scores, byte counts, file paths, locators — anything copied or computed rather than composed.

### Named Rules
**The Mono-For-Data-Only Rule.** JetBrains Mono is reserved for values a tool produced or a user typed verbatim (hashes, scores, paths, locators, IOC values). It never sets a heading, label, or sentence of prose — mono signals "this is exact," and using it anywhere else would dilute that signal.

**The No-Kicker Rule.** No small-caps or uppercase label ever sits directly above a display-scale heading as a kicker/eyebrow. The Verdict station is the load-bearing case: its title is screen-reader-only (`hideTitle`) precisely so the verdict word doesn't get a kicker sitting over it; the station's colour-coded lamp dot carries the identity work instead.

## Layout

Three pages, each a centered max-width column (`max-w-[1180px]` for Intake/Log, `max-w-[1440px]` for the Report) with generous but not lavish horizontal padding (`px-5` mobile, `px-8`–`px-10` desktop). The Report page splits into a main column plus a `380px` right rail at the `xl` breakpoint; below that everything stacks to one column. The Intake page pairs a form column with a `340px` "Recent" rail at `lg`.

The signature layout is the `LaneStrip`: a five-column grid at `lg` (`minmax(0,1fr) 84px minmax(0,1.2fr) 84px minmax(0,1fr)`) — Primary screening, a connector, Secondary inspection, a connector, Verdict — collapsing to a single stacked column below `lg`, where the connectors rotate from a horizontal arrow to a downward one and their label collapses to screen-reader-only text (fixed after finish review round 2, which found a mobile kicker-over-heading regression here).

Spacing is a tight, consistent rhythm built from Tailwind's default scale: `gap-2`/`gap-3` between closely related elements, `px-4 py-2.5`–`py-3` as the standard list-row padding, `mt-5`/`mt-6`/`gap-6` between major report sections. Panels/lists use `divide-y divide-rule` rather than repeated card borders for internal rows.

## Elevation & Depth

Flat by design: there is no box-shadow-drawn card elevation anywhere in the system. Depth is conveyed by two flat surface tones (`--panel` over `--ground`, with `--panel-2` one step up for hover/active states) and by `1px` rule-coloured borders, never by shadow. The one exception is a small `0 0 8px` glow on the Station status lamp dots (inspect/clear/alarm) — a targeted state indicator, not a card-elevation shadow.

### Named Rules
**The Flat Station Rule.** Every Panel and Station is a flat rectangle: `border border-rule` + `bg-panel`, no shadow. If a component needs to signal state, it does so with the lamp-dot glow or a colour change, never by lifting off the page.

## Shapes

Corners are small and consistent: `rounded-sm` (2px) for tight elements like chips, swatches, and score-scale tracks; `rounded-md` (6px) for stations, inputs, and buttons; `rounded-lg` (8px) for Panels and the upload drop-zone. Nothing in the system uses a large or pill radius. The `Swatch` primitive — a small filled square with a 2px corner — is the recurring channel-marker shape borrowed directly from the X-ray false-colour vocabulary; it appears next to every finding, evidence row, and verdict word as a colour-coded identity marker.

## Components

### Buttons
- **Shape:** `rounded-md` (6px).
- **Primary:** `bg-tool` background, `text-ground` text, uppercase signage label, `px-5 py-3`; used once per page for the single decisive action ("Send to screening").
- **Secondary/Ghost:** bordered (`border border-rule bg-panel`) with `text-ink-2`, used for report-download and copy actions; hover darkens to `text-ink`/`bg-panel-2`.

### Chips (`Chip`)
- **Style:** small pill-corner (`rounded` = 2px per Tailwind's base `rounded`), uppercase Barlow Condensed label, background/text pair drawn from the six-colour `TONE_CHIP` map (e.g. alarm chip = `bg-alarm-bg text-alarm`).
- **State:** no selected/unselected variant — a chip's colour is always its semantic tone (severity, provenance, or ATT&CK tag), not an interactive toggle state.

### Panels / Containers (`Panel`)
- **Corner Style:** `rounded-lg` (8px).
- **Background:** `bg-panel`.
- **Shadow Strategy:** none — see Elevation & Depth.
- **Border:** `1px solid var(--rule)`.
- **Internal Padding:** header rows at `px-4 py-3`; list rows at `px-4 py-2.5`; prose panels at `px-5 py-4`.

### Inputs / Fields
- **Style:** `border border-rule bg-panel`, `rounded-md`, no default focus ring beyond the global `:focus-visible` (2px tool-blue outline); text inputs holding data (file paths) use the mono `.data` class.
- **Focus:** border shifts to `border-tool`; the drop-zone (drag state) fills with `bg-tool-bg` and its dashed border turns `border-tool`.
- **Error / Disabled:** errors surface through `Notice tone="alarm"`, not inline field-level red borders; the submit button's disabled state is a flat 40% opacity, no colour change.

### Navigation
Top-level navigation is minimal (route links, not a persistent chrome bar in the files read); in-page navigation uses the same uppercase-signage tab pattern (`role="tablist"`/`role="radiogroup"`) seen in Intake's source picker, the Report's evidence-channel filter, and the Log page's verdict filter: active state is a solid `bg-ink`/`bg-panel-2` fill or a `border-b-2 border-tool` underline, inactive is `text-ink-3` with a hover step to `text-ink-2`.

### The Lane Strip (signature component)
The `LaneStrip` is the page's spine on the Report view: two `Station` panels (Primary screening, Secondary inspection) and a terminal Verdict station, joined by `Connector` arrows labelled with the route outcome ("Flagged"/"Cleared", "Decision"). Each `Station` carries a colour-coded lamp dot (idle/inspect/clear/alarm) in its title row that is the load-bearing identity signal — this is why the Verdict station can safely hide its text title for sighted users (`hideTitle`) without losing identity, and why no kicker sits over the verdict word. The primary-screening station renders the classifier's score against a fixed three-zone scale (clear 0–0.05, gray 0.05–0.30, flag 0.30–1, cut line at 0.15) so the number is always read against its calibration, never in isolation.

## Do's and Don'ts

### Do:
- **Do** keep the six semantic tones (`tool`/`sample`/`clear`/`alarm`/`inspect`/`idle`) as the only source of colour meaning; add new UI by reusing `TONE_CHIP`/`TONE_TEXT`, never a new ad hoc colour.
- **Do** render any text copied verbatim from a sample in Sample Orange on its `-bg` wash, whether it's an evidence excerpt, an extracted IOC, or a future surface that quotes the file — the colour is the "attacker-controlled, context only" flag.
- **Do** use `.data`/JetBrains Mono for hashes, scores, paths, and locators; use Barlow Condensed uppercase only for structural labels (titles, tabs, chips, buttons), never for data values.
- **Do** build depth with flat panels + rule borders + panel-2 hover steps; reserve the lamp-dot glow for genuine state, not decoration.
- **Do** keep the lane-strip's own responsive collapse pattern (row→column, arrow rotates, label goes screen-reader-only below `lg`) as the model for any future multi-station flow — it was the fix for a real mobile kicker regression found in finish review.

### Don't:
- **Don't** place any small-caps/uppercase label directly above a display-scale heading as a kicker or eyebrow — the system explicitly bans this device (see The No-Kicker Rule); if a component needs an identity marker near a large headline, use a lamp dot or swatch beside it instead, as the Verdict station does.
- **Don't** add a hard-offset ("neobrutalist") drop shadow anywhere; this is a flat, rule-bordered console, and any shadow beyond the small lamp glow is off-system.
- **Don't** introduce a glyph icon font or a system display face; the only icon set in use is Phosphor (rendered as inline SVG via `@phosphor-icons/react`), and the only display face is Barlow Condensed.
- **Don't** let a chip or verdict word take a colour outside the fixed `TONE_CHIP`/`TONE_TEXT`/`VERDICT` maps in `lib/vocab.ts` — those maps are the single source of truth for tone-to-colour, and a one-off inline colour would fork it.
- **Don't** treat the classifier's score as legible without its scale: any future surface showing the EMBER score must render it against the same three-zone gray-band scale used in the Lane Strip, not as a bare number.
