---
name: Telltale SOC
description: The analyst console for Telltale; trust read as triage on manila card stock.
colors:
  manila-paper: "#ebe2c8"
  card-stock: "#f8f4e6"
  card-hover: "#f1ead5"
  hairline: "#d5c9a8"
  hairline-strong: "#b3a588"
  ink: "#1c1b18"
  ink-quiet: "#57503f"
  rail-ink: "#1e1d1a"
  rail-hover: "#2b2925"
  rail-text: "#ece5d4"
  rail-muted: "#a99f8a"
  selection-straw: "#f3d58a"
  triage-revoked: "#1c1b18"
  triage-failed: "#b42318"
  triage-lower-trust: "#e8a317"
  triage-verified: "#276a31"
typography:
  display:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, sans-serif"
    fontSize: "2rem"
    fontWeight: 700
    lineHeight: 1.15
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, sans-serif"
    fontSize: "2.5rem"
    fontWeight: 700
    lineHeight: 1
    fontFeature: "tnum"
  title:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.25
  body:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "\"Segoe UI Variable Text\", \"Segoe UI\", system-ui, -apple-system, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "0.05em"
  mono:
    fontFamily: "\"Cascadia Mono\", Consolas, ui-monospace, \"SF Mono\", monospace"
    fontSize: "0.8125rem"
    fontWeight: 400
rounded:
  sm: "2px"
  md: "3px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  page: "32px"
components:
  button:
    backgroundColor: "{colors.card-stock}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "2rem"
  button-hover:
    backgroundColor: "{colors.card-hover}"
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.manila-paper}"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "2rem"
  button-danger:
    backgroundColor: "{colors.card-stock}"
    textColor: "{colors.triage-failed}"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "2rem"
  button-danger-solid:
    backgroundColor: "{colors.triage-failed}"
    textColor: "#ffffff"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "2rem"
  input-field:
    backgroundColor: "{colors.card-stock}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0 10px"
    height: "2rem"
  nav-link:
    textColor: "{colors.rail-text}"
    rounded: "{rounded.md}"
    padding: "0 10px"
    height: "2.25rem"
  nav-link-hover:
    backgroundColor: "{colors.rail-hover}"
  nav-link-active:
    backgroundColor: "{colors.manila-paper}"
    textColor: "{colors.ink}"
  chip-new:
    backgroundColor: "{colors.triage-lower-trust}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "2px 6px"
  table-row:
    height: "2.25rem"
    padding: "0 12px"
  dialog:
    backgroundColor: "{colors.card-stock}"
    textColor: "{colors.ink}"
    padding: "26px 22px 18px"
    width: "min(28rem, calc(100vw - 32px))"
---

# Design System: Telltale SOC

## Overview

**Creative North Star: "The Triage Tag"**

Trust is triage. Every device carries a tag: Revoked, Lower trust or Verified, and every request may carry one more, Failed. The console is printed on manila card stock beside an ink-black rail, in black ink type. Colour is rationed: four triage inks exist, they state trust on the four-band strip and the board's name tabs, take a few named secondary roles elsewhere, and always travel with a word.

The density is that of a working desk tool for long sessions with the live log open: hairline module rules, 36px table rows, tabular figures everywhere numbers sit in columns. Hierarchy comes from scale and weight inside one system sans, never from a second face or from decoration. Surfaces are flat; depth exists only for things that float above the page (the confirm dialog and the toast).

The world refuses the black-and-neon "hacker terminal" and the grey SaaS card grid. It reads like a printed field form: paper, ink, a coloured tab where a state needs to be seen from across the room.

**Key Characteristics:**
- Manila paper ground, ink rail, ink type; colour reserved for trust state.
- The four-band triage strip, one band filled, always next to its word.
- One sans family for everything; mono only for IDs, IPs, hashes and paths.
- Hairline rules and flat tonal panels instead of shadows.
- Revoked prints in greyscale; new live rows stay marked until seen.

## Colors

A warm, low-chroma paper-and-ink palette with four saturated triage inks held back for state.

### Primary
- **Ink** (`ink`): Body text, headings, focus rings, the primary button fill, the selected toggle. Black ink is the voice of the console; there is no brand accent.

### Tertiary (triage inks: state only)
- **Revoked Black** (`triage-revoked`): Level 0. The filled band and name tab for revoked devices. Same value as Ink on purpose: revocation is the absence of trust, not an alarm.
- **Signal Red** (`triage-failed`): Level 1, Failed, a request state only. Also the Kill verdict word, the danger button, the problem banner, and the dialog band for destructive confirms.
- **Tag Amber** (`triage-lower-trust`): Level 2, Lower trust. A fill only, always with Ink text on it; never used as text colour. Also carries the "New" chip and the 16% tint on fresh live-log rows.
- **Ledger Green** (`triage-verified`): Level 3, Verified. Fill, word colour on the tag, and the sign-in card's top band.

### Neutral
- **Manila Paper** (`manila-paper`): Page ground, table header, footer strips of panels, the active nav tab (a piece of paper showing through the rail).
- **Card Stock** (`card-stock`): Panels, tables, inputs, buttons, the dialog body.
- **Card Hover** (`card-hover`): Row and button hover.
- **Hairline** (`hairline`) and **Strong Hairline** (`hairline-strong`): Row dividers inside modules, and module borders / control strokes / empty bands respectively.
- **Quiet Ink** (`ink-quiet`): Secondary text, field labels, counts, ledes, greyscale revoked rows.
- **Rail Ink** (`rail-ink`), **Rail Hover** (`rail-hover`), **Rail Text** (`rail-text`), **Rail Muted** (`rail-muted`): The navigation rail and everything printed on it.
- **Selection Straw** (`selection-straw`): Text selection only.

### Named Rules
**The Triage Ink Rule.** The four-band strip and the band name tabs mean trust state and nothing else. Outside the strip the inks keep only their listed secondary roles (red for destructive and Kill, amber for unseen or exhausted markers, green for the sign-in band). Every appearance is paired with a word; colour alone never carries status.

**The Amber Is a Fill Rule.** Amber never colours text. It is a background with Ink on top.

**The No Brand Accent Rule.** Interactive emphasis is Ink on paper. Red appears on controls only for destructive actions, and in row-action columns only on hover or focus.

## Typography

**Display Font:** Segoe UI Variable Text (with Segoe UI, system-ui, -apple-system, sans-serif)
**Body Font:** the same family
**Label/Mono Font:** Cascadia Mono (with Consolas, ui-monospace, SF Mono), for identifiers only

**Character:** One plain system sans carries every role; hierarchy is scale contrast and weight. Mono marks machine strings so an analyst can tell an ID from prose at a glance.

### Hierarchy
- **Display** (700, 2rem, 1.15, -0.02em): Page title, one per view. 1.625rem on phones.
- **Headline** (700, 2.5rem, 1, tabular): Triage band counts on Overview; the numerals are the headline. 2rem on phones. Zero counts drop to 400 in Quiet Ink.
- **Title** (600, 1.125rem, 1.25): Section headings within a page; 1.25rem in the dialog.
- **Body** (400, 0.9375rem, 1.5): Running text and ledes (ledes capped at 70ch). Tables and controls step down to 0.875rem; meta and counts to 0.8125rem.
- **Label** (600, 0.75rem, 0.05em, uppercase): The triage tag word and the "New" chip (0.6875rem). Rail nav group names use the same treatment in Rail Muted.
- **Mono** (400, 0.8125rem): Device IDs, IPs, hashes, paths, the dialog target line.

### Named Rules
**The One Family Rule.** No second face. A new role gets a size or weight, not a font.

**The Tabular Rule.** Any number that sits in a column, a count or a figure strip uses tabular figures.

## Layout

A two-column shell: a fixed 15rem ink rail (sticky, full viewport height) and a fluid main column padded 28px 32px 48px. Content is a vertical stack of modules (triage board, one-hour figure strip, tables) separated by section titles with 36px above and 12px below. Spacing steps are 4 / 8 / 12 / 16 / 24 / 32px, with 20px for page head and rail insets.

Density is fixed at a 2.25rem table row with 12px cell padding. The one-hour figure strip is an auto-fit grid (min 9.5rem) divided by vertical hairlines with no boxes. Device facts are an auto-fit definition grid (min 12rem) with the trust row spanning full width on a paper tint.

At 760px and below the rail collapses into a top bar with a 44px Menu button; every control grows to a 44px minimum; triage bands restack into a name tab on the left with count, share bar and link stacked to its right; the figure strip becomes two columns; tables scroll sideways with the first column pinned behind a strong hairline.

## Elevation & Depth

Flat by default. Panels are separated by hairline borders and by tone (paper ground, card-stock module, paper footer strip), never by shadow. One shadow exists, and only on elements that float above the page: the confirm dialog and the toast. The dialog backdrop is Ink at 50%.

### Shadow Vocabulary
- **Float** (`box-shadow: 0 10px 28px rgb(28 27 24 / 0.22), 0 2px 6px rgb(28 27 24 / 0.12)`): Modal dialog and toast only.

### Named Rules
**The Paper Doesn't Lift Rule.** Anything that lives in the page is flat. Only an overlay casts a shadow.

## Shapes

Nearly square. Controls and modules take a 3px corner (`rounded.md`); chips, skeleton bars and inset target boxes take 2px (`rounded.sm`). Dialog and sign-in card corners are square. Borders are 1px hairlines throughout. The recurring silhouette is the tab: a flat 6px colour band across the top of a card (dialog, sign-in) and the filled name tab at the left of each triage band. Bands are hard colour stops, never blends.

## Components

### Triage Tag (signature)
The house component. Four narrow bands (5px wide, 13px tall, 1px gap) outlined in Strong Hairline; the band at the item's level fills with its triage ink, then the word in uppercase Label type. Failed words print red, Verified words green, Lower trust and Revoked words in Ink. A large variant (9px by 22px bands, 0.875rem word) heads the device detail trust row. The strip means trust only; model verdicts never use it.

### Triage Board (signature)
Overview's stacked bands, one per device trust level (Revoked, Lower trust, Verified; devices are never Failed). Each row: a filled name tab in the band's ink (Paper text on black, Ink on amber, white on green), a Headline count, a share-of-fleet bar (8px, paper track, ink fill) with its percentage in words, and a link to the filtered list. A paper footer strip carries the fleet totals.

### Verdicts
Kill is the word "Kill" in bold Signal Red; Benign is plain body text; anything else is Quiet Ink. No chip, no band.

### Buttons
- **Shape:** gently squared (3px), 2rem tall, 12px side padding, 600 weight at 0.875rem, 1px Strong Hairline stroke.
- **Default:** Card Stock with Ink text. Hover moves to Card Hover with a Quiet Ink stroke; active to Hairline.
- **Primary:** solid Ink with Paper text; hover lightens to a warm charcoal.
- **Danger:** red outline and text; hover or the `solid` variant fills red with white text. In table row-action columns danger buttons print as default until hovered or focused.
- **Pressed toggle:** solid Ink, like Primary.
- **On rail:** transparent with Rail Text and a dark stroke.
- **Focus:** 2px Ink outline, 2px offset (Rail Text on the rail). Transitions are 150ms ease-out on colour only.

### Chips
- **Style:** Tag Amber fill, Ink text, Label type at 0.6875rem, 2px corner, 2px by 6px padding.
- **Use:** state markers that need a word, such as "New" on fresh live-log rows and "Full" on a licence with no seats left.

### Cards / Containers
- **Corner Style:** 3px.
- **Background:** Card Stock on Manila Paper; footer and header strips revert to Paper.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px Strong Hairline outside, 1px Hairline between rows.
- **Internal Padding:** 12px by 16px.

### Inputs / Fields
- **Style:** Card Stock, 1px Strong Hairline, 3px corner, 2rem tall, 10px padding; label above in 0.75rem 600 Quiet Ink.
- **Focus:** the global 2px Ink outline. Hover darkens the stroke to Quiet Ink.

### Navigation
The ink rail: brand mark (a tiny three-band tag) and wordmark at top, uppercase group names in Rail Muted, 2.25rem links in Rail Text. Hover fills Rail Hover; the current page is a Manila Paper tab with Ink text at 600, as if the page shows through. Signed-in user and Sign out sit in a foot strip. Collapses to a Menu button at 760px.

### Tables
Card Stock in a bordered wrap, sticky Paper header whose cells are full-width sort buttons in Quiet Ink (Ink when sorted, with a small CSS triangle). Rows 2.25rem, hover Card Hover. Revoked rows render greyscale in Quiet Ink with the device link struck through. Fresh live-log rows carry an amber tint (`rgb(232 163 23 / 0.16)`) plus a "New" chip until the analyst marks them seen.

### Confirm Dialog
Native `<dialog>`, 28rem max, square, Card Stock with a flat 6px top band: Ink for ordinary confirms, Signal Red for destructive ones. Title, Quiet Ink body, the target in a mono inset box on Paper, then Cancel and the action button right-aligned. Destructive confirms use the solid danger button.

### Problem Banner
Red 1px border on Card Stock, red 600 text, inline retry action.

## Do's and Don'ts

### Do:
- **Do** pair every triage ink with its word and its band position.
- **Do** keep amber as a fill with Ink text on it.
- **Do** confirm every destructive action in the dialog with the red top band and the solid danger button.
- **Do** print revoked items in greyscale and keep new live rows tinted and chipped until seen.
- **Do** use tabular figures for every column of numbers and mono for every machine identifier.
- **Do** keep all styling in the same-origin stylesheet; set dynamic values through CSSOM custom properties (as the share bar does with `--share`).

### Don't:
- **Don't** use the triage strip for anything but trust; verdicts, severities and statuses get words.
- **Don't** mark a device Failed; Failed is a request state.
- **Don't** add a second typeface or load fonts from a third party.
- **Don't** use inline style attributes; the CSP forbids them.
- **Don't** put shadows on in-page panels, or blend triage inks into gradients or glows.
- **Don't** introduce a neon-on-black terminal look or a grey SaaS card grid.
