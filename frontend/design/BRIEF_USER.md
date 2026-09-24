# Visual Design Brief: SentinelAPI Dashboard
**Theme: Tactical Cyber Reconnaissance**

## 1. Design Philosophy & Aesthetic Vision
The design system establishes a high-precision, mission-critical workspace engineered for SecOps analysts, incident response teams, and security researchers operating under intense cognitive load. It balances tactical utilitarianism with deep optical comfort during sustained triage sessions. The interface communicates surgical exactness, systemic authority, and instant situational awareness.

Drawing from modern high-density developer ergonomics, technical telemetry displays, and refined tactical HUD design, the visual language rejects decorative clutter in favor of crisp delineation, information hierarchy, and signal purity. Every pixel serves verification, isolation, and rapid response. High-contrast severity flags puncture an ultra-low-reflectance obsidian canvas, transforming complex threat topologies and API payload traces into immediate actionable intelligence.

---

## 2. Color Palette & Visual Hierarchy

### Surface Foundations
- **Base Canvas:** `#06080F` (abyssal black for minimal eye strain and maximum contrast)
- **Surface Panel:** `#0D111C` (structural container layer, sidebars, header)
- **Surface Elevated:** `#151B2B` (active rows, inspector drawers, popovers, modal panels)
- **Surface Elevated Highlight:** `#182033` (selected card fill)
- **Border Structural:** `#232D42` (crisp division lines, structural wireframe grid)
- **Border Subdued:** `rgba(35, 45, 66, 0.45)` (subordinate splitters, list row separators)

### Functional Status & Threat Severities
- **Primary / System Brand:** `#38BDF8` (Sky blue: interactive states, active nodes, focal targets)
- **Critical Severity:** `#EF4444` (Red: active breaches, severe vulnerabilities, unmitigated exploits)
- **High Severity:** `#F97316` (Orange: elevated threats, exposed attack surfaces)
- **Medium Severity:** `#F59E0B` (Amber: anomalous telemetry, review-pending triggers)
- **Low Severity:** `#3B82F6` (Blue: minor exposure, informative variance, defense-in-depth)
- **Info Severity:** `#64748B` (Slate: neutral metadata, raw payload timestamps, low-risk observations)
- **Secure / Verified Control:** `#10B981` (Emerald: verified access controls, expected 403 denied)

Background fills for status chips, badges, and alerts use tinted alpha channels (`10-15%` opacity) paired with solid 1px keyed borders to preserve contrast without creating visual weight traps.

---

## 3. Typography & Micro-Layout

- **Proportional Text (Inter):** Configured with tight tracking on headings to maintain solid structural anchors across dense dashboards. Body copy utilizes compact line heights (`1.25rem` on `13px` base) specifically calibrated for dense multi-line log inspection.
- **Monospace Telemetry (JetBrains Mono):** Applied systematically to all raw data streams, cryptographic hashes, network addresses, keyboard shortcuts, HUD status labels, and cURL commands. Labels leverage slight uppercase tracking (`0.04em` to `0.06em`) for immediate scannability at miniature scales.

---

## 4. Layout Architecture: Results Triage Workspace

### Zone 1: Global Status Bar & Navigation
- **Brand Mark:** SentinelAPI with tactical shield icon and version tag.
- **Scanner Status Indicator:** Real-time state pill (e.g. `● READY`, `● SCANNING`, `● ERROR`) - honest copy, replacing zero-trust claims.
- **Target Pill:** Target host (`http://target_api:9000`) and OpenAPI specification source (`openapi.json`).
- **Scope-Guard Badge:** Persistent lock indicator: `Scope Guard: Active (target_api:9000 allow-listed)`.
- **Global Actions:**
  - **Run Scan Button:** Primary sky-blue button opening New Scan modal with prefilled target parameters.
  - **Export Menu:** Dropdown offering `JSON Report`, `Markdown Report`, and `cURL Attack Suite`.

### Zone 2: Tactical Metric HUD Cards
A horizontal grid of modular HUD containers displaying telemetry:
1. **Endpoints Audited:** Total routes analyzed (e.g., `12 / 12`).
2. **Critical Findings:** Active critical authorization breaches (`#EF4444`).
3. **High Findings:** Privileged and write-access vulnerabilities (`#F97316`).
4. **Medium Findings:** Data exposure & anomaly counts (`#F59E0B`).
5. **Verified Controls (Secure):** Expected 403 access denials validated (`#10B981`, flagged as proposed backend gap).

### Zone 3: Split Workspace (Finding Explorer & Deep-Dive Inspector)

#### Zone 3A: Finding Explorer (Left Rail, 420px - 480px)
- **Filter Pills:** Segmented tabs with counts: `All (6)`, `Critical (2)`, `High (1)`, `Medium (3)`, `Low (0)`, `Info (0)`, `Secure (14)`.
- **Search Bar:** Real-time fuzzy query input with filter prefix support (e.g. `path:/orders`, `method:GET`).
- **Finding Cards:**
  - Method chip (`GET`, `PUT`, `DELETE` with standardized HTTP method colors).
  - Endpoint path in JetBrains Mono (`/orders/{id}`, `/admin/users`).
  - Finding title & check identifier (e.g., `BOLA in Order Resource Access`).
  - Severity chip (Icon + Label: `● CRITICAL`).
  - Confidence rating (`95%` or `0.95`).
  - OWASP API Security Top 10 identifier (e.g., `API1:2023`).
  - Attacker persona indicator (`Attacker: userB`).

#### Zone 3B: Deep-Dive Inspector (Main Viewport)
- **Header:** Title, Severity badge, OWASP category badge, confidence score, and composite Risk Score (0-100).
- **Plain-English Impact & Root Cause:** Concise executive description of why the endpoint failed authorization.
- **"Why this severity" Component Score Breakdown:** Four labeled component progress bars:
  1. *Impact (0-40)*
  2. *Exploitability (0-25)*
  3. *Data Sensitivity (0-30)*
  4. *Evidence Strength (0-15)*
- **cURL Reproducer Console:**
  - Shell-safe cURL command formatted in JetBrains Mono.
  - Authentication headers use `$TOKEN` variable placeholder.
  - Callout: `export TOKEN=<attacker token> first`.
  - Copy micro-interaction button with checkmark feedback.
- **Side-by-Side Dual-Identity Differential Inspector:**
  - **Left Panel (Owner Baseline):** Legitimate owner request & response (`userA`). Shows 200 OK baseline status and legitimate object fields.
  - **Right Panel (Attacker Probe):** Attacker probe (`userB`). Highlights status discrepancy (`expected 403, got 200 - access granted`).
  - **Data Diff Highlighting:** Leaked fields flagged with highlighted badges; sensitive values masked (e.g., `"credit_card": "44*******66"`).
- **Reproduction Badge:** Empirical verification status (e.g., `● 2 of 2 reproduced`, or `● Downgraded - failed to reproduce`).
- **Affected Objects:** List of probed object IDs confirmed vulnerable (`[101, 102, 103]`).
- **Remediation & Fix Guidance:**
  - Direct scanner fix hint (e.g., *Enforce ownership check: verify req.user.id == order.owner_id before returning payload*).
  - Collapsible section: *AI-suggested code fix (verify before use)* labeled `Available after AI analysis in Phase 10`.

---

## 5. Screen Inventory
1. **Results Triage Workspace:** The primary command center.
2. **New Scan:** Modal/dialog to configure target, identities, test budget, and scope.
3. **Live Scan Progress:** Real-time 8-stage stepper, telemetry metrics, and monospace event logs.
4. **Authorization Matrix:** Cross-identity resource ownership vs permission heatmap.
5. **Attack Surface:** Comprehensive inventory of discovered endpoints, auth requirements, and priority weights.
6. **Scan History:** Historical scan runs, execution durations, severity distributions, and report downloads.
7. **States Sheet:** System states covering loading skeleton, scan failure, interruption, empty findings, and unreachable targets.
