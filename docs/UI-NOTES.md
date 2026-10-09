# Dashboard UI

This presentation refresh is based on upstream commit `e822432`. Backend scoring,
API endpoints, response shapes and correlation rules are unchanged.

## Tokens and typography

Tokens live in `frontend/tailwind.config.js`; global behavior and shared layouts
live in `frontend/src/index.css`. Components reuse `components/ui.jsx`.

| Purpose | Token | Value |
| --- | --- | --- |
| App / panel / raised surface | `base`, `panel`, `raised` | `#0B0E13`, `#12161D`, `#1A2029` |
| Borders | `edge`, `edge.strong` | `#29313D`, `#485362` |
| Text / secondary / metadata | `ink`, `ink.muted`, `ink.faint` | `#E6EAF0`, `#ABB5C3`, `#8995A6` |
| Links, focus, active navigation, seed | `accent` | `#78AAFA` |
| Actionability: high / medium / low | `band.*` | `#34D399`, `#F5B54A`, `#F87171` |
| PowerShell / Command Shell / Transfer | `tech.*` | `#B5A0EF`, `#74C7EA`, `#EAA0AE` |

Inter Variable is self-hosted through the single added font package,
`@fontsource-variable/inter`, imported in `main.jsx`. JetBrains Mono Regular is a
local WOFF2 asset under `src/assets/fonts/`, with its OFL license alongside it.
Both use `font-display: swap`; no Google Fonts or runtime font CDN is used.

| Style | Size / line height |
| --- | --- |
| Display | 30 / 36px |
| Title | 20 / 28px |
| Heading | 16 / 24px |
| Body | 14 / 21px |
| Small | 13 / 19px |
| Caption, technical values | 12 / 18px |

The main metric uses 44px. All numbers inherit tabular numerals. Paths, commands,
IDs and evidence weights use JetBrains Mono. Metadata stays at least 12px; text
colors have at least 4.5:1 contrast on the three solid surfaces.

## Presentation rules

- Actionability describes evidence completeness. Bands use the API's labels;
  category and mean-score meters use the existing 25/50 boundaries. Every meter
  has adjacent numeric information. Wazuh levels always use a neutral `L15` badge.
- Technique colors identify techniques through a dot and label. They do not
  color entire rows. System/User session labels and field presence are neutral.
- Panels use 12px corners, controls 8px, and 1px borders. No decorative gradients,
  shadows, glass effects or emoji. Hover/focus transitions are 150ms.
- Tables keep sticky column headings inside bounded scroll regions, right-aligned
  numeric cells and keyboard-accessible record buttons. Minimum table widths
  preserve column spacing on small screens; the table scrolls within the page.
- Full rule descriptions, IDs and evidence provenance are available through
  disclosure controls. The case export retains the full evidence report.
- Case fields present, required coverage and weighted actionability remain
  separate quantities. The UI does not equate field count with weighted score.
- The process tree groups existing events by process GUID and attaches children
  using the supplied parent GUID. Creation events represent each process. Missing
  parents and malformed cyclic references are explicitly marked; no correlation
  edges or evidence are invented. Details reveal all events in each group.
- Event times use UTC consistently. LIVE uses the API's explicit study window
  when configured; MOCK is identified as deterministic sample data. Compact
  source status exposes window and seed threshold through its title.
- `?view=cases|alerts&case=...&alert=...` routing and the MOCK/LIVE API switch are
  retained. Empty, loading and unavailable states are distinct. Failed list
  requests show an error instead of an apparently empty dataset.
- Focus outlines and text selection are explicit. A skip link leads to main
  content. Reduced-motion preference disables animations and transitions.

## Validation — 9 October 2026

Run from `frontend/`:

```sh
npm run build
node --test tests/processTreeModel.test.mjs
```

The four tree tests cover creation-event grouping, a non-creation seed, missing
parents/GUIDs, cyclic references and ordering without mutating the input.

Headless Edge/Playwright checks passed for all four LIVE views at 1280px and
1440px, all four MOCK views at 1280px, and compact views at 375px. The 22 browser
checks included sticky headings, filters, empty/error states, encoded URL refresh,
hide-missing, report download, local fonts, focus and reduced motion. No unexpected
console errors, external asset requests or page-wide horizontal overflow occurred.
The source was restored to LIVE with 91 cases in the configured study window.

See [UI review](UI-REVIEW.md) for screenshots using deterministic MOCK data and
instructions for reviewing this branch locally.
