# SentinelAPI Design System Specification

## 1. Design Tokens Table

### Surface & Layout Foundations
| Token Name | Hex Value | Purpose & Application |
|---|---|---|
| `canvas-base` | `#06080F` | Abyssal black base canvas; non-reflective background for minimal cognitive fatigue |
| `surface-panel` | `#0D111C` | Primary structural containers, table cards, sidebars, header navigation |
| `surface-elevated` | `#151B2B` | Raised cards, active row selections, modal bodies, popover menus |
| `surface-highlight` | `#182033` | Hover states, active selection highlights, code console headers |
| `border-structural` | `#232D42` | 1px keyed boundaries, table row dividers, grid separation wireframes |
| `border-subdued` | `rgba(35, 45, 66, 0.45)` | Subordinate inner borders, split lines, drawer separators |
| `brand-primary` | `#38BDF8` | Sky blue interactive focus, primary buttons, active tabs, progress highlights |
| `brand-hover` | `#7DD3FC` | Primary button hover state with radial micro-glow |

### Threat Severity & Health Status Tokens
| Severity / Status | Hex Value | Border / Alpha Tint | Icon Token | Description & Usage |
|---|---|---|---|---|
| **CRITICAL** | `#EF4444` | `rgba(239, 68, 68, 0.15)` | `error` / `warning` | Active BOLA/IDOR breaches, unauthorized write access, privilege usurpation |
| **HIGH** | `#F97316` | `rgba(249, 115, 22, 0.15)` | `emergency` / `bolt` | State-changing authorization flaws, unauthorized configuration alteration |
| **MEDIUM** | `#F59E0B` | `rgba(245, 158, 11, 0.15)` | `shield_alert` / `info` | Excessive data exposure, PII field leakage, missing rate limits |
| **LOW** | `#3B82F6` | `rgba(59, 130, 246, 0.15)` | `info` / `policy` | Minor exposure, informative variance, defense-in-depth deviations |
| **INFO** | `#64748B` | `rgba(100, 116, 139, 0.15)` | `help` / `tag` | Neutral telemetry metadata, raw payload timestamps, observations |
| **SECURE / VERIFIED** | `#10B981` | `rgba(16, 185, 129, 0.15)` | `verified_user` / `check_circle` | Verified access controls, expected 403/401 denial enforcement |

### HTTP Method Badge Tokens
| Method | Text & Border Hex | Background Fill | Semantic Application |
|---|---|---|---|
| `GET` | `#38BDF8` | `rgba(56, 189, 248, 0.12)` | Read operations, query retrieval |
| `POST` | `#10B981` | `rgba(16, 185, 129, 0.12)` | Creation, authentication login routes |
| `PUT` | `#F59E0B` | `rgba(245, 158, 11, 0.12)` | Idempotent updates, state replacement |
| `PATCH` | `#A855F7` | `rgba(168, 85, 247, 0.12)` | Partial resource modifications |
| `DELETE` | `#EF4444` | `rgba(239, 68, 68, 0.12)` | Destructive operations, object purges |

---

## 2. Ready-to-Paste Tailwind CSS Theme Snippet

```javascript
/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: {
          base: '#06080F',
        },
        surface: {
          panel: '#0D111C',
          elevated: '#151B2B',
          highlight: '#182033',
        },
        border: {
          structural: '#232D42',
          subdued: 'rgba(35, 45, 66, 0.45)',
        },
        brand: {
          primary: '#38BDF8',
          hover: '#7DD3FC',
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#3B82F6',
          info: '#64748B',
          secure: '#10B981',
        },
        method: {
          get: '#38BDF8',
          post: '#10B981',
          put: '#F59E0B',
          patch: '#A855F7',
          delete: '#EF4444',
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      borderRadius: {
        tactical: '4px',
        panel: '6px',
        modal: '8px',
      },
      boxShadow: {
        'glow-primary': '0 0 12px rgba(56, 189, 248, 0.35)',
        'glow-critical': '0 0 12px rgba(239, 68, 68, 0.35)',
        'glow-high': '0 0 12px rgba(249, 115, 22, 0.30)',
        'glow-secure': '0 0 12px rgba(16, 185, 129, 0.30)',
      },
    },
  },
  plugins: [],
}
```

---

## 3. Severity Icon & Visual Presentation Rules
1. **Never Color Alone:** Every severity chip, badge, and indicator must include both an explicit icon and an uppercase text label (`[!] CRITICAL`, `[▲] HIGH`, `[◆] MEDIUM`, `[●] LOW`, `[i] INFO`, `[✔] SECURE`).
2. **WCAG AA Compliance:** All severity chips pair a keyed 1px border and 10–15% tinted background with high-luminance text, achieving >= 4.5:1 contrast against `#06080F` and `#0D111C`.
3. **Pulsing Accents:** Critical severity tags display an inner pulsating dot (`w-1.5 h-1.5 rounded-full bg-severity-critical animate-ping`), restricted under `prefers-reduced-motion`.

---

## 4. Typography Rules

| Role | Font Family | Size / Leading | Weight / Tracking | Context & Usage |
|---|---|---|---|---|
| Headline XL | Inter | `2rem` (`32px`) / `2.5rem` | 600 / `-0.025em` | Page titles, primary modal headers |
| Headline LG | Inter | `1.5rem` (`24px`) / `2rem` | 600 / `-0.02em` | Section headers, inspector titles |
| Headline SM | Inter | `1.125rem` (`18px`) / `1.5rem` | 600 / `-0.015em` | Sub-panel headers, card group labels |
| Body MD | Inter | `0.8125rem` (`13px`) / `1.25rem` | 400 / `0.005em` | Operational descriptions, root cause callouts |
| Body SM | Inter | `0.75rem` (`12px`) / `1.125rem` | 400 / `0.01em` | Metadata hints, table secondary copy |
| Monospace MD | JetBrains Mono | `0.8125rem` (`13px`) / `1.25rem` | 400 / `-0.01em` | cURL commands, raw JSON diff payloads |
| Monospace SM | JetBrains Mono | `0.6875rem` (`11px`) / `1rem` | 500 / `0em` | Telemetry logs, event logs, HTTP status codes |
| Label MD | JetBrains Mono | `0.75rem` (`12px`) / `1rem` | 500 / `0.04em` | Method badges, filter tabs, table column headers |
| Label SM | JetBrains Mono | `0.625rem` (`10px`) / `0.875rem` | 600 / `0.06em` | Severity chips, metric labels, target tags |

---

## 5. Component Inventory (One-Line Technical Specifications)

1. **`SeverityChip`**: Compact badge rendering severity level with icon, uppercase label, 1px border, and 12% alpha tinted background.
2. **`ConfidenceBar`**: Horizontal micro-gauge displaying confidence ratio `0.0 - 1.0` (or `0% - 100%`) with color-coded fills.
3. **`RiskBreakdown`**: Four labeled progress bars displaying Impact (0-40), Exploitability (0-25), Data Sensitivity (0-30), and Evidence Strength (0-15).
4. **`MethodBadge`**: Monospace chip displaying HTTP verbs (`GET`, `POST`, `PUT`, `DELETE`) with dedicated semantic method colors.
5. **`StageStepper`**: Eight-node pipeline tracking execution stages with completed checkmarks, glowing active ring, and queued states.
6. **`StatCard`**: High-density metric HUD container displaying primary integer telemetry, trend sparkline, and monospace caption.
7. **`FindingCard`**: Left-rail list item with method badge, monospace path, severity chip, confidence rating, OWASP tag, and active cyan indicator.
8. **`InspectorHeader`**: Forensics title row displaying vulnerability name, composite risk score (0-100), OWASP tag, and triage action buttons.
9. **`CurlConsole`**: Monospace terminal box featuring shell-safe curl reproduction command with `$TOKEN` substitution and copy micro-interaction.
10. **`DiffViewer`**: Side-by-side split panels comparing legitimate owner baseline (200 OK) with attacker probe (Expected 403, got 200) highlighting leaked fields.
11. **`MatrixGrid`**: Cross-identity heatmap table mapping resource objects against personas with color-coded cells (`OWNS`, `ALLOWED`, `DENIED`, `VIOLATION`).
12. **`EmptyState`**: Clean zero-state panel featuring tactical crosshair icon, positive status headline, and audit launch/download actions.
13. **`ErrorState`**: Diagnostic failure card detailing sanitized error descriptions, affected stage, connection retry button, and log export.
14. **`Skeleton`**: Low-contrast pulsing slate placeholder frames mimicking HUD cards, finding rows, and code blocks during async loading.
15. **`ScopeBanner`**: Pinned isolation banner confirming target allow-list enforcement and blocking off-scope network exploration.

---

## 6. Accessibility & Interaction Guidelines (WCAG AA)
- **Focus Rings:** All interactive inputs, buttons, and row items must show a crisp `2px` focus ring in `#38BDF8` with a `2px` offset on `:focus-visible`.
- **Keyboard Navigation:**
  - Finding explorer list supports `ArrowUp` / `ArrowDown` navigation and `Enter` selection.
  - Search input opens globally with `Cmd+K` / `Ctrl+K`.
  - Modals close on `Escape` and trap focus while open.
- **ARIA Labeling:**
  - Every `SeverityChip` includes `aria-label="Severity: Critical"` (or High/Medium/Low/Info).
  - Every cell in `MatrixGrid` carries `aria-label="Object orders:101 for persona userB: Violation, unauthorized access granted"`.
  - Toggle switches provide `role="switch"` and `aria-checked`.
- **Reduced Motion (`prefers-reduced-motion`):**
  - Disable ping animations on critical indicator dots.
  - Skeletons use static opacity (`0.6`) instead of animated shimmer.
  - Transition durations snap to `0ms` when reduced motion is preferred.
