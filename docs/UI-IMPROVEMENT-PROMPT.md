# UI Improvement Brief — Actionability Scoring Dashboard

> **How to use this file:** paste everything below into the target model
> (GPT‑6 Astra) as the task brief. It contains the project context, the design
> problem, the constraints, the design-system spec, the per-page requirements,
> and an acceptance checklist. Keep the guardrails: do **not** change backend
> scoring logic, API contracts, or the data model.

---

## 1. Project context (read first)

**What it is.** A research dashboard for a bachelor's thesis titled roughly
*"Actionability Scoring Dashboard for Wazuh/Sysmon alerts"*. It ingests endpoint
telemetry from **Wazuh** (which collects **Sysmon** events) and scores every
alert and correlated case from **0–100** on **evidence completeness**, not threat
severity. The question it answers is: *"Is this alert complete enough for an
analyst to investigate, or do they still have to dig through raw logs?"*

**Who uses it.** The thesis author and examiners; conceptually a SOC analyst.
It is a serious, academic/technical tool — it must look like a product a security
team would trust, not a demo or a template.

**Stack.**
- Frontend: React 18 + Vite, Tailwind CSS 3, plain JSX (no TypeScript), no UI kit.
- Backend: FastAPI (Python), served at `/api`.
- Data: Wazuh Indexer (OpenSearch) via `backend/wazuh_client.py`; two modes,
  **MOCK** (deterministic fixtures) and **LIVE** (real Wazuh alerts).
- Routing is query-param based: `?view=cases|alerts&case=<id>&alert=<id>`.

**Domain objects shown in the UI.**
- **Alert** — one scored Wazuh/Sysmon event. Fields: technique (T1059.001
  PowerShell, T1059.003 Windows Command Shell, T1105 Ingress Tool Transfer),
  Wazuh rule level, actionability score (0–100) and band (Low < 25, Medium 25–50,
  High > 50), timestamp, endpoint.
- **Case** — a seed alert plus correlated evidence. Has case score, required
  evidence coverage, node/edge counts, evidence facts (field, role, AHP weight
  `W`, quality `Q`, evidence confidence `E`, contribution, carriers), typed
  relations (SAME_PROCESS, PARENT_CHILD, PROCESS_CONNECTED_TO, …), a **process
  creation tree**, and a chronological event order.
- **Views:** `Cases` (list), `Alerts` (list + overview stats), `Case detail`,
  `Alert detail`.

**Key framing to respect.** A score of 100 means *the expected evidence fields
for that technique are present* — it is **not** "100% dangerous" and **not** an
ATT&CK rating. High actionability bands are good (complete evidence). The UI must
never imply severity. Wazuh's own `rule.level` is shown separately as a neutral
badge (e.g. `L15`).

**Frontend files to focus on.**
```
frontend/src/App.jsx                         # shell: header, tabs, source switch
frontend/src/index.css                       # base styles, selection, scrollbars
frontend/tailwind.config.js                  # design tokens (colors, fonts)
frontend/src/components/ui.jsx               # primitives: Panel, Badge, Meter, LevelBadge, TechniqueTag, KeyValue, SkeletonRows, Spinner, EmptyState
frontend/src/components/StatsOverview.jsx    # alerts overview: metric tiles + technique coverage
frontend/src/components/ScoringDashboard.jsx # alerts table
frontend/src/components/CasesView.jsx        # cases table
frontend/src/components/CaseDetail.jsx       # case header, evidence facts, score composition, relations, tree, event order
frontend/src/components/AlertDetail.jsx      # alert header + per-category field breakdown
frontend/src/components/ProcessTree.jsx      # parent→child process creation tree
frontend/src/components/TimelineView.jsx     # chronological event order
```

**Current look (for reference, do not just tweak it).** A dark console theme with
hard-coded hex tokens: `base #0E1218`, `panel #161C24`, `raised #1D242E`,
`edge #2A323E`, ink `#E9EDF3 / #A9B4C2 / #7E8A99`, accent `#5B9DFF`, actionability
bands `high #3ECF8E / medium #F0B429 / low #E07070`, technique colors
`pwsh #A78BFA / cmd #38BDF8 / transfer #FB7185`. Font is system Inter stack;
the base font-size is 14px.

---

## 2. The design problem

The current UI is functional but reads as **generic AI-generated output** and
slightly **dated**. Typical symptoms to eliminate:

- Uniform rounded "cards in a grid" with the same border everywhere; no clear
  hierarchy between a page section and a table row.
- Overuse of pill badges and chips for everything, so nothing stands out.
- Flat, muddy dark surfaces with low separation between background / panel /
  raised, plus shadows that do nothing on dark.
- Timid type scale: most text is 12–14px; headers are small; data is not
  aligned; numbers are not consistently tabular.
- Generic accent-blue everywhere, including for actionability that should read
  as "good".
- Emoji or cartoon icons, heavy gradients, glassmorphism, or marketing-style
  hero blocks would make it worse — avoid all of these.

**Design goals.**

1. Look like a credible, modern security/analytics product — the quality bar of
   Linear, Vercel dashboards, Grafana, or Microsoft Sentinel, but calmer.
2. Strong typographic hierarchy and density suited to reading data tables.
3. Clear, legible typography (see font requirement below). No tiny 10–11px text
   for primary content.
4. Clear separation of the three semantic axes: **Wazuh severity** (neutral),
   **ATT&CK technique** (identity color), **actionability** (green = complete).
5. Restrained, intentional use of color; color carries meaning, not decoration.
6. Accessible: contrast, visible focus, text selection, reduced-motion aware.

---

## 3. Hard constraints / guardrails

- **Do not change** backend logic, API contracts, data shapes, scoring formulas,
  or the meaning of any score. UI/presentation only.
- **Keep** the query-param routing and the MOCK/LIVE toggle behaviour.
- **Keep** it a dark theme (it is an analyst console); you may refine the exact
  palette but do not switch to light.
- **No** new heavy dependencies. Tailwind + React only, plus at most one
  self-hosted font package. Do not add a component library or CSS-in-JS.
- **No** emojis in the UI. **No** gradients as decoration, **no** glassmorphism,
  **no** parallax, **no** decorative illustrations.
- Keep components small and reusable; extend `ui.jsx` primitives rather than
  scattering one-off styles.
- All data numbers must use `font-variant-numeric: tabular-nums`.
- Respect `prefers-reduced-motion` for any animation.

---

## 4. Typography & font requirement (explicit)

The brief explicitly asks for a **clear, legible font** that does not look
default/dated.

- Self-host a **variable sans** for the UI — recommended: **Inter Variable**
  (or **IBM Plex Sans** if a slightly more distinctive, technical voice is
  wanted). Load it via a self-hosted package such as `@fontsource-variable/inter`
  or `@fontsource-variable/ibm-plex-sans` (one font package only), imported in
  `frontend/src/main.jsx`. Do **not** rely on a Google Fonts `<link>` at runtime.
- Self-host a **monospace** for paths, GUIDs, command lines, hashes — recommended
  **JetBrains Mono** (`@fontsource/jetbrains-mono`) or **IBM Plex Mono**. These
  values are long and must be readable; the mono font is a first-class citizen
  here, not a fallback.
- Set an explicit type scale and use it consistently, e.g.
  `display 30/34`, `title 20/26`, `heading 16/22`, `body 14/20`, `small 13/18`,
  `caption 12/16`, `micro 11/14` (only for metadata, never for primary content).
- Body base is 14px; do not go below 12px for anything a user must read.
- Headings: tight tracking (`-0.01em`), medium/semibold weight, not all-caps.
  Reserve small-caps/uppercase-with-tracking only for short meta labels.

---

## 5. Design system to define (replace the ad-hoc tokens)

Redefine `frontend/tailwind.config.js` and `index.css` around a small, coherent
system. Suggested direction (adjust values with judgement; keep it restrained):

**Surfaces (dark, layered, low-chroma):**
- `bg` (app): near-black cool grey, e.g. `#0B0E13`
- `surface` (panel): one step up, e.g. `#12161D`
- `surface-2` (raised rows/inputs): `#171C24`
- `border`: subtle, e.g. `#232A34`; `border-strong` only for emphasis.
- Prefer 1px borders + spacing for separation; avoid box-shadows on dark.

**Text:**
- `text` `#E6EAF0`, `text-muted` `#9BA6B4`, `text-faint` `#6C7887`.
- Ensure ≥ 4.5:1 contrast for body text on surfaces.

**Semantic colors:**
- **Actionability bands:** `high #34D399` (green, "good"), `medium #F5B54A`
  (amber), `low #F87171` (red). Used for band badges and meters only.
- **Technique identity:** keep three distinguishable but muted hues, e.g.
  PowerShell `#A78BFA`, Command Shell `#38BDF8`, Transfer `#FB7185`. Used as a
  small dot/label, never as a full-row background.
- **Severity (Wazuh level):** neutral (`text-muted`) badge; never reuse band
  colors for it, to avoid conflating "complete evidence" with "dangerous".
- Accent: a single restrained brand blue (e.g. `#5B9DFF`) for interactive focus,
  links, active tab; do not spray it across charts.

**Spacing & shape:**
- 4px base scale; page padding 24–32px; section gap 20–24px; card padding 16–20px.
- Radius: panels ~10–12px, controls ~8px, pills only for genuine status chips.
- One consistent elevation model: surface change + 1px border, not shadows.

**Data display:**
- Tables: comfortable row height (~40px), sticky header, right-align numerics,
  tabular numerals, hover row tint, clear column separation via spacing (not
  vertical rules everywhere).
- Meters: thin (4–6px), rounded, colored by band; always paired with the numeric
  value and a label so color is never the only signal.
- Empty/loading states: quiet skeleton rows, no spinners in the middle of tables.

**Motion:** 120–160ms ease for hover/focus and meter width; nothing playful.

---

## 6. Per-page requirements

**App shell (`App.jsx`).** Header with product name + one-line description, two
tabs (`Cases`, `Alerts`) that read as a segmented control or underline nav, and a
right-aligned status cluster: source (MOCK/LIVE), active time window, seed
threshold, and the MOCK/LIVE switch. On smaller widths, collapse the status text
into a tooltip/compact form — no wrapping mess.

**Stats overview (`StatsOverview.jsx`).** Make this the clearest hierarchy on the
page: a primary "Alerts analyzed" figure, then actionability bands as secondary
stats (green/amber/red), then per-technique coverage with thin meters. Add a
one-line explanation that the score is evidence completeness. Avoid seven equal
boxes.

**Case list (`CasesView.jsx`).** A serious data table: seed alert (with rule
description + short id), endpoint, technique (dot + label), observed time, case
actionability (score + meter, colored by band), Wazuh rule level (neutral badge),
evidence coverage, telemetry counts. Two filters (technique, band) styled as
compact selects. Sticky header, row hover, no cell collisions.

**Case detail (`CaseDetail.jsx`).** Top summary: technique, rule description,
metadata (case id, host, Wazuh level, seed time, events), and a score card that
states the number `/100`, the band, and the "expected fields present" count, with
one sentence that this is evidence completeness, not severity. Then: evidence
facts table (field, role, value/carriers, `W`, `Q`, `E`, contribution, carriers)
with a "hide missing" toggle and an export; a **process creation tree** as the
primary structural view; score composition bars; typed relations; chronological
event order. Make the tree visually distinct (indentation + connector lines,
clear System/User session labels, seed marker, and an "uncaptured parent" flag).

**Alert detail (`AlertDetail.jsx`).** Header with technique, rule description,
agent, tactic, Wazuh level, time, and a score card (score `/100`, band, expected
fields present). Then per-category evidence panels (identity, behavioral,
relationship, IOC, network, timeline) each with a meter, an `x / y` completeness
figure, and the field list with presence indicators and the MITRE data component.

**Process tree (`ProcessTree.jsx`).** Parent→child indentation; group all events
of one process under that process; label System vs User; mark the SEED; show a
short note when a node's parent was not captured. Must stay readable with ~10–15
processes and connector lines aligned to the indentation.

---

## 7. Deliverables

1. Updated `frontend/tailwind.config.js` and `frontend/src/index.css` with the new
   tokens, font imports (self-hosted), base type scale, selection/focus styles,
   and scrollbar styling.
2. Updated `frontend/src/main.jsx` (or an entry import) for the font packages.
3. Refined `ui.jsx` primitives (Panel, SectionTitle, Badge, LevelBadge,
   TechniqueTag, Meter, KeyValue, Skeleton, EmptyState) as the single source of
   styling — no inline one-offs elsewhere where a primitive fits.
4. Refined `App.jsx`, `StatsOverview.jsx`, `ScoringDashboard.jsx`,
   `CasesView.jsx`, `CaseDetail.jsx`, `AlertDetail.jsx`, `ProcessTree.jsx`,
   `TimelineView.jsx`.
5. A short `docs/UI-NOTES.md` describing the final tokens, type scale, and rules
   (so the system is maintainable).
6. `npm run build` must pass in `frontend/`; no console errors; no layout
   regressions at 1280px and 1440px widths.

---

## 8. Acceptance checklist

- [ ] No emojis, gradients-as-decoration, glassmorphism, or oversized rounded cards.
- [ ] Clear typographic hierarchy; nothing important below 12px; body 14px.
- [ ] Self-hosted Inter/IBM Plex Sans (UI) + JetBrains/IBM Plex Mono (data).
- [ ] Actionability = green when high; Wazuh severity stays neutral; the two are
      never visually conflated.
- [ ] Technique is an identity cue (dot + label), not a background color.
- [ ] Tables: sticky header, tabular numerals, right-aligned numbers, row hover,
      no text/meter collisions; filters compact and obvious.
- [ ] Case detail clearly states the score means evidence completeness.
- [ ] Process tree reads as a hierarchy, not a flat list or graph.
- [ ] Visible focus states; text selection readable; `prefers-reduced-motion` respected.
- [ ] Backend untouched; MOCK/LIVE toggle and query-param routing still work.
- [ ] `npm run build` passes; layout holds at 1280–1440px.

---

## 9. Do / Don't summary

**Do:** restrained dark palette with layered surfaces; one accent; strong type
scale; tabular numerals; semantic color used sparingly; generous but consistent
spacing; quiet motion; professional data density.

**Don't:** look like a Bootstrap/Material template, a “purple gradient AI SaaS”,
or a cluttered neon SOC board; don't use color as the only signal; don't invent
new metrics or reword domain meaning; don't touch the backend or the scoring.
