# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: sentinel.spec.ts >> SentinelAPI End-to-End Suite >> 5. Axe Accessibility Audits (Zero Serious/Critical Violations)
- Location: e2e/sentinel.spec.ts:249:3

# Error details

```
Error: expect(received).toEqual(expected) // deep equality

- Expected  -   1
+ Received  + 484

- Array []
+ Array [
+   Object {
+     "description": "Ensure the contrast between foreground and background colors meets WCAG 2 AA minimum contrast ratio thresholds",
+     "help": "Elements must meet minimum color contrast ratio thresholds",
+     "helpUrl": "https://dequeuniversity.com/rules/axe/4.13/color-contrast?application=playwright",
+     "id": "color-contrast",
+     "impact": "serious",
+     "nodes": Array [
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "9.0pt (12px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"relative p-3.5 rounded-panel bg-canvas-panel border border-border-structural overflow-hidden flex flex-col justify-between \">",
+                 "target": Array [
+                   ".p-3\\.5.relative.rounded-panel:nth-child(1)",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span class=\"font-mono text-xs text-slate-500 truncate\">100% surface mapped</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".p-3\\.5.relative.rounded-panel:nth-child(1) > .items-baseline.gap-2.flex > .text-slate-500.truncate.text-xs",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "9.0pt (12px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"relative p-3.5 rounded-panel bg-canvas-panel border border-border-structural overflow-hidden flex flex-col justify-between \">",
+                 "target": Array [
+                   ".p-3\\.5.relative.rounded-panel:nth-child(2)",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span class=\"font-mono text-xs text-slate-500 truncate\">BOLA &amp; write access</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".p-3\\.5.relative.rounded-panel:nth-child(2) > .items-baseline.gap-2.flex > .text-slate-500.truncate.text-xs",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "9.0pt (12px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"relative p-3.5 rounded-panel bg-canvas-panel border border-border-structural overflow-hidden flex flex-col justify-between \">",
+                 "target": Array [
+                   ".p-3\\.5.relative.rounded-panel:nth-child(3)",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span class=\"font-mono text-xs text-slate-500 truncate\">State modification</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".p-3\\.5.relative.rounded-panel:nth-child(3) > .items-baseline.gap-2.flex > .text-slate-500.truncate.text-xs",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "9.0pt (12px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"relative p-3.5 rounded-panel bg-canvas-panel border border-border-structural overflow-hidden flex flex-col justify-between \">",
+                 "target": Array [
+                   ".p-3\\.5.relative.rounded-panel:nth-child(4)",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span class=\"font-mono text-xs text-slate-500 truncate\">Data exposure</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".p-3\\.5.relative.rounded-panel:nth-child(4) > .items-baseline.gap-2.flex > .text-slate-500.truncate.text-xs",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "9.0pt (12px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"relative p-3.5 rounded-panel bg-canvas-panel border border-border-structural overflow-hidden flex flex-col justify-between \">",
+                 "target": Array [
+                   ".p-3\\.5.relative.rounded-panel:nth-child(5)",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 9.0pt (12px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span class=\"font-mono text-xs text-slate-500 truncate\">Expected 403 Denied</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".p-3\\.5.relative.rounded-panel:nth-child(5) > .items-baseline.gap-2.flex > .text-slate-500.truncate.text-xs",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#2b1f2e",
+               "contrastRatio": 4.17,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#ef4444",
+               "fontSize": "7.5pt (10px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 4.17 (foreground color: #ef4444, background color: #2b1f2e, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<span role=\"status\" aria-label=\"Severity: CRITICAL\" class=\"inline-flex items-center gap-1.5 font-mono font-semibold rounded-tactical border text-severity-critical border-severity-critical/40 bg-severity-critical/10 px-1.5 py-0.5 text-[10px] \">",
+                 "target": Array [
+                   ".border-brand.shadow-glow-primary[role=\"button\"] > .justify-between.gap-2.items-center > .border-severity-critical\\/40[aria-label=\"Severity: CRITICAL\"][role=\"status\"]",
+                 ],
+               },
+               Object {
+                 "html": "<div role=\"button\" tabindex=\"0\" class=\"p-3 rounded-tactical cursor-pointer transition-all border text-left flex flex-col gap-2 relative bg-canvas-elevated border-brand shadow-glow-primary\">",
+                 "target": Array [
+                   ".border-brand.shadow-glow-primary[role=\"button\"]",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 4.17 (foreground color: #ef4444, background color: #2b1f2e, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span>CRITICAL</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".border-brand.shadow-glow-primary[role=\"button\"] > .justify-between.gap-2.items-center > .border-severity-critical\\/40[aria-label=\"Severity: CRITICAL\"][role=\"status\"] > span",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "7.5pt (10px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"lg:col-span-8 xl:col-span-8 bg-canvas-panel p-4 sm:p-5 rounded-panel border border-border-structural space-y-5\">",
+                 "target": Array [
+                   ".lg\\:col-span-8",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span class=\"text-[10px] text-slate-500\">(0.98)</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".text-slate-400.text-xs.font-mono > .text-slate-500.text-\\[10px\\]",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "7.5pt (10px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"space-y-3 p-4 rounded-panel bg-canvas-panel border border-border-structural \">",
+                 "target": Array [
+                   ".p-4.space-y-3.rounded-panel",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span class=\"font-mono text-[10px] text-slate-500\">Deterministic Telemetry Assessment</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".text-slate-500.text-\\[10px\\].font-mono",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "7.5pt (10px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"space-y-3 p-4 rounded-panel bg-canvas-panel border border-border-structural \">",
+                 "target": Array [
+                   ".p-4.space-y-3.rounded-panel",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<p class=\"text-[10px] text-slate-500 truncate\">Unauthorized access &amp; system state influence</p>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".space-y-1:nth-child(1) > p",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "7.5pt (10px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"space-y-3 p-4 rounded-panel bg-canvas-panel border border-border-structural \">",
+                 "target": Array [
+                   ".p-4.space-y-3.rounded-panel",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<p class=\"text-[10px] text-slate-500 truncate\">Attacker privilege &amp; request complexity</p>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".md\\:grid-cols-2.grid-cols-1.grid > .space-y-1:nth-child(2) > p",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "7.5pt (10px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"space-y-3 p-4 rounded-panel bg-canvas-panel border border-border-structural \">",
+                 "target": Array [
+                   ".p-4.space-y-3.rounded-panel",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<p class=\"text-[10px] text-slate-500 truncate\">PII, credentials &amp; financial records exposure</p>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".space-y-1:nth-child(3) > p",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "7.5pt (10px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"space-y-3 p-4 rounded-panel bg-canvas-panel border border-border-structural \">",
+                 "target": Array [
+                   ".p-4.space-y-3.rounded-panel",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<p class=\"text-[10px] text-slate-500 truncate\">Empirical reproduction &amp; differential confidence</p>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".space-y-1:nth-child(4) > p",
+         ],
+       },
+       Object {
+         "all": Array [],
+         "any": Array [
+           Object {
+             "data": Object {
+               "bgColor": "#0d111c",
+               "contrastRatio": 3.95,
+               "expectedContrastRatio": "4.5:1",
+               "fgColor": "#62748e",
+               "fontSize": "7.5pt (10px)",
+               "fontWeight": "normal",
+               "messageKey": null,
+             },
+             "id": "color-contrast",
+             "impact": "serious",
+             "message": "Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+             "relatedNodes": Array [
+               Object {
+                 "html": "<div class=\"bg-canvas-panel px-3 py-2 border-b border-border-structural flex items-center justify-between\">",
+                 "target": Array [
+                   ".rounded-panel.overflow-hidden.bg-canvas-base:nth-child(4) > .py-2.px-3.border-b",
+                 ],
+               },
+             ],
+           },
+         ],
+         "failureSummary": "Fix any of the following:
+   Element has insufficient color contrast of 3.95 (foreground color: #62748e, background color: #0d111c, font size: 7.5pt (10px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "html": "<span class=\"text-[10px] text-slate-500 hidden sm:inline\">[Press 'c' to copy]</span>",
+         "impact": "serious",
+         "none": Array [],
+         "target": Array [
+           ".sm\\:inline",
+         ],
+       },
+     ],
+     "tags": Array [
+       "cat.color",
+       "wcag2aa",
+       "wcag143",
+       "TTv5",
+       "TT13.c",
+       "EN-301-549",
+       "EN-9.1.4.3",
+       "ACT",
+       "RGAAv4",
+       "RGAA-3.2.1",
+     ],
+   },
+ ]
```

# Page snapshot

```yaml
- generic [ref=f2e3]:
  - banner [ref=f2e4]:
    - generic [ref=f2e5]:
      - link "SentinelAPI v0.9.0-alpha" [ref=f2e6] [cursor=pointer]:
        - /url: /
        - generic [ref=f2e10]:
          - generic [ref=f2e11]: SentinelAPI
          - generic [ref=f2e12]: v0.9.0-alpha
      - navigation [ref=f2e13]:
        - link "Scan History" [ref=f2e14] [cursor=pointer]:
          - /url: /
    - generic [ref=f2e15]:
      - generic [ref=f2e16]:
        - generic [ref=f2e17]: "Target:"
        - generic [ref=f2e18]: target_api:9000
        - generic [ref=f2e19]: (url:target_api:9000)
      - region "Scope Guard Indicator" [ref=f2e20]:
        - generic [ref=f2e24]: "Scope Guard: Active"
        - generic [ref=f2e25]: (allow-listed only)
      - generic [ref=f2e29]: READY
    - generic [ref=f2e32]:
      - button "Open Security Settings" [ref=f2e33]
      - link "Run Scan" [ref=f2e37] [cursor=pointer]:
        - /url: /scans/new
  - main [ref=f2e41]:
    - generic [ref=f2e42]:
      - generic [ref=f2e47]:
        - generic [ref=f2e48]:
          - generic [ref=f2e49]: WORKSPACE // Results Triage
          - generic [ref=f2e50]: "[COMPLETED]"
        - heading "target_api:9000" [level=1] [ref=f2e51]
      - generic [ref=f2e52]:
        - generic [ref=f2e53]:
          - button "Findings" [ref=f2e54]
          - button "Authorization Matrix" [ref=f2e60]
          - button "Attack Surface" [ref=f2e64]
          - button "Analytics" [ref=f2e69]
        - button "Export audit artifacts" [ref=f2e73]:
          - generic [ref=f2e77]: Export
        - button "Keyboard shortcuts" [ref=f2e80]
    - generic [ref=f2e84]:
      - generic [ref=f2e85]:
        - generic [ref=f2e86]: Endpoints Audited
        - generic [ref=f2e88]:
          - generic [ref=f2e89]: 14 / 14
          - generic [ref=f2e90]: 100% surface mapped
      - generic [ref=f2e91]:
        - generic [ref=f2e92]:
          - generic [ref=f2e93]: Critical Findings
          - generic [ref=f2e94]: CLEAN
        - generic [ref=f2e95]:
          - generic [ref=f2e96]: "0"
          - generic [ref=f2e97]: BOLA & write access
      - generic [ref=f2e98]:
        - generic [ref=f2e99]:
          - generic [ref=f2e100]: High Severity
          - generic [ref=f2e101]: CLEAN
        - generic [ref=f2e102]:
          - generic [ref=f2e103]: "0"
          - generic [ref=f2e104]: State modification
      - generic [ref=f2e105]:
        - generic [ref=f2e106]:
          - generic [ref=f2e107]: Medium Severity
          - generic [ref=f2e108]: CLEAN
        - generic [ref=f2e109]:
          - generic [ref=f2e110]: "0"
          - generic [ref=f2e111]: Data exposure
      - generic [ref=f2e112]:
        - generic [ref=f2e113]: Verified Controls
        - generic [ref=f2e115]:
          - generic [ref=f2e116]: "14"
          - generic [ref=f2e117]: Expected 403 Denied
        - generic [ref=f2e118]: "* Backend Gap (Proposed in Phase 9B/10)"
    - generic [ref=f2e120]:
      - generic [ref=f2e121]:
        - generic [ref=f2e122]:
          - generic [ref=f2e123]: Target Findings Stream
          - generic [ref=f2e124]: 8 of 8 Issues
        - generic [ref=f2e125]:
          - generic [ref=f2e126]:
            - button "All 8" [ref=f2e127]:
              - generic [ref=f2e128]: All
              - generic [ref=f2e129]: "8"
            - button "Critical 4" [ref=f2e130]:
              - generic [ref=f2e131]: Critical
              - generic [ref=f2e132]: "4"
            - button "High 2" [ref=f2e133]:
              - generic [ref=f2e134]: High
              - generic [ref=f2e135]: "2"
            - button "Medium 2" [ref=f2e136]:
              - generic [ref=f2e137]: Medium
              - generic [ref=f2e138]: "2"
            - button "Low 0" [ref=f2e139]:
              - generic [ref=f2e140]: Low
              - generic [ref=f2e141]: "0"
            - button "Info 0" [ref=f2e142]:
              - generic [ref=f2e143]: Info
              - generic [ref=f2e144]: "0"
            - button "Secure" [ref=f2e145]
          - generic [ref=f2e147]:
            - textbox "Search findings (e.g. /orders, BOLA)... [Press /]" [ref=f2e152]
            - combobox "Filter by security check suite" [ref=f2e153]:
              - option "All Checks" [selected]
              - option "BOLA"
              - option "BFLA"
              - option "DATA_EXPOSURE"
              - option "RATE_LIMIT"
              - option "UNAUTH_ACCESS"
              - option "INPUT_HANDLING"
          - generic [ref=f2e154]:
            - generic [ref=f2e155]: "Min Confidence:"
            - generic [ref=f2e156]:
              - slider "Minimum confidence threshold slider" [ref=f2e157] [cursor=pointer]: "0"
              - generic [ref=f2e158]: 0%
        - generic [ref=f2e159]:
          - 'button "GET /admin/users Severity: CRITICAL Broken Function Level Authorization on /admin/users API5:2023 by: userA 98" [ref=f2e160] [cursor=pointer]':
            - generic [ref=f2e162]:
              - generic [ref=f2e163]:
                - generic [ref=f2e164]: GET
                - generic [ref=f2e165]: /admin/users
              - 'status "Severity: CRITICAL" [ref=f2e166]':
                - generic [ref=f2e169]: CRITICAL
            - generic [ref=f2e170]: Broken Function Level Authorization on /admin/users
            - generic [ref=f2e171]:
              - generic [ref=f2e172]:
                - generic [ref=f2e173]: API5:2023
                - generic [ref=f2e174]: "by: userA"
              - 'progressbar "Confidence: 98%" [ref=f2e176]'
          - 'button "GET /admin/users Severity: CRITICAL Broken Function Level Authorization on /admin/users API5:2023 by: userB 98" [ref=f2e178] [cursor=pointer]':
            - generic [ref=f2e179]:
              - generic [ref=f2e180]:
                - generic [ref=f2e181]: GET
                - generic [ref=f2e182]: /admin/users
              - 'status "Severity: CRITICAL" [ref=f2e183]':
                - generic [ref=f2e186]: CRITICAL
            - generic [ref=f2e187]: Broken Function Level Authorization on /admin/users
            - generic [ref=f2e188]:
              - generic [ref=f2e189]:
                - generic [ref=f2e190]: API5:2023
                - generic [ref=f2e191]: "by: userB"
              - 'progressbar "Confidence: 98%" [ref=f2e193]'
          - 'button "GET /users/{id} Severity: CRITICAL Excessive Data Exposure on /users/{id} API3:2023 by: userA 98" [ref=f2e195] [cursor=pointer]':
            - generic [ref=f2e196]:
              - generic [ref=f2e197]:
                - generic [ref=f2e198]: GET
                - generic [ref=f2e199]: "/users/{id}"
              - 'status "Severity: CRITICAL" [ref=f2e200]':
                - generic [ref=f2e203]: CRITICAL
            - generic [ref=f2e204]: "Excessive Data Exposure on /users/{id}"
            - generic [ref=f2e205]:
              - generic [ref=f2e206]:
                - generic [ref=f2e207]: API3:2023
                - generic [ref=f2e208]: "by: userA"
              - 'progressbar "Confidence: 98%" [ref=f2e210]'
          - 'button "GET /users/{id} Severity: CRITICAL Excessive Data Exposure on /users/{id} API3:2023 by: userB 98" [ref=f2e212] [cursor=pointer]':
            - generic [ref=f2e213]:
              - generic [ref=f2e214]:
                - generic [ref=f2e215]: GET
                - generic [ref=f2e216]: "/users/{id}"
              - 'status "Severity: CRITICAL" [ref=f2e217]':
                - generic [ref=f2e220]: CRITICAL
            - generic [ref=f2e221]: "Excessive Data Exposure on /users/{id}"
            - generic [ref=f2e222]:
              - generic [ref=f2e223]:
                - generic [ref=f2e224]: API3:2023
                - generic [ref=f2e225]: "by: userB"
              - 'progressbar "Confidence: 98%" [ref=f2e227]'
          - 'button "GET /orders/{id} Severity: HIGH Broken Object Level Authorization (BOLA/IDOR) on /orders/{id} API1:2023 by: userA 100" [ref=f2e229] [cursor=pointer]':
            - generic [ref=f2e230]:
              - generic [ref=f2e231]:
                - generic [ref=f2e232]: GET
                - generic [ref=f2e233]: "/orders/{id}"
              - 'status "Severity: HIGH" [ref=f2e234]':
                - generic [ref=f2e237]: HIGH
            - generic [ref=f2e238]: "Broken Object Level Authorization (BOLA/IDOR) on /orders/{id}"
            - generic [ref=f2e239]:
              - generic [ref=f2e240]:
                - generic [ref=f2e241]: API1:2023
                - generic [ref=f2e242]: "by: userA"
              - 'progressbar "Confidence: 100%" [ref=f2e244]'
          - 'button "GET /orders/{id} Severity: HIGH Broken Object Level Authorization (BOLA/IDOR) on /orders/{id} API1:2023 by: userB 100" [ref=f2e246] [cursor=pointer]':
            - generic [ref=f2e247]:
              - generic [ref=f2e248]:
                - generic [ref=f2e249]: GET
                - generic [ref=f2e250]: "/orders/{id}"
              - 'status "Severity: HIGH" [ref=f2e251]':
                - generic [ref=f2e254]: HIGH
            - generic [ref=f2e255]: "Broken Object Level Authorization (BOLA/IDOR) on /orders/{id}"
            - generic [ref=f2e256]:
              - generic [ref=f2e257]:
                - generic [ref=f2e258]: API1:2023
                - generic [ref=f2e259]: "by: userB"
              - 'progressbar "Confidence: 100%" [ref=f2e261]'
          - 'button "POST /auth/login Severity: MEDIUM Missing Rate Limiting on /auth/login API4:2023 by: anonymous 60" [ref=f2e263] [cursor=pointer]':
            - generic [ref=f2e264]:
              - generic [ref=f2e265]:
                - generic [ref=f2e266]: POST
                - generic [ref=f2e267]: /auth/login
              - 'status "Severity: MEDIUM" [ref=f2e268]':
                - generic [ref=f2e271]: MEDIUM
            - generic [ref=f2e272]: Missing Rate Limiting on /auth/login
            - generic [ref=f2e273]:
              - generic [ref=f2e274]:
                - generic [ref=f2e275]: API4:2023
                - generic [ref=f2e276]: "by: anonymous"
              - 'progressbar "Confidence: 60%" [ref=f2e278]'
          - 'button "GET /reports/summary Severity: MEDIUM Unauthenticated Access Permitted on /reports/summary API2:2023 by: anonymous 98" [ref=f2e280] [cursor=pointer]':
            - generic [ref=f2e281]:
              - generic [ref=f2e282]:
                - generic [ref=f2e283]: GET
                - generic [ref=f2e284]: /reports/summary
              - 'status "Severity: MEDIUM" [ref=f2e285]':
                - generic [ref=f2e288]: MEDIUM
            - generic [ref=f2e289]: Unauthenticated Access Permitted on /reports/summary
            - generic [ref=f2e290]:
              - generic [ref=f2e291]:
                - generic [ref=f2e292]: API2:2023
                - generic [ref=f2e293]: "by: anonymous"
              - 'progressbar "Confidence: 98%" [ref=f2e295]'
      - generic [ref=f2e297]:
        - generic [ref=f2e298]:
          - generic [ref=f2e299]:
            - generic [ref=f2e300]:
              - generic [ref=f2e301]: GET
              - generic [ref=f2e302]: /admin/users
              - 'status "Severity: CRITICAL" [ref=f2e303]':
                - generic [ref=f2e306]: CRITICAL
              - generic [ref=f2e307]: API5:2023
            - generic [ref=f2e308]:
              - generic [ref=f2e309]:
                - generic [ref=f2e312]: 100 / 100
                - generic [ref=f2e313]: Risk Score
              - button "Copy deep link to finding" [ref=f2e314]:
                - generic [ref=f2e318]: Share
          - heading "Broken Function Level Authorization on /admin/users" [level=2] [ref=f2e319]
          - generic [ref=f2e320]:
            - generic [ref=f2e321]: "Scanner Confidence:"
            - generic [ref=f2e322]:
              - 'progressbar "Confidence: 98%" [ref=f2e323]'
              - generic [ref=f2e325]:
                - text: 98%
                - generic [ref=f2e326]: (0.98)
        - generic [ref=f2e327]:
          - generic [ref=f2e328]: Vulnerability Summary & Root Cause
          - paragraph [ref=f2e333]: "Privileged endpoint '/admin/users' was successfully accessed by non-administrative identity 'userA' (role: user) with HTTP 200."
        - generic [ref=f2e334]:
          - generic [ref=f2e335]:
            - generic [ref=f2e336]: Severity Breakdown Factors
            - generic [ref=f2e337]: Deterministic Telemetry Assessment
          - generic [ref=f2e338]:
            - generic [ref=f2e339]:
              - generic [ref=f2e340]:
                - generic [ref=f2e341]: "Impact: 35 / 40"
                - generic [ref=f2e342]: 88%
              - 'progressbar "Impact: 35 out of 40" [ref=f2e343]'
              - paragraph [ref=f2e345]: Unauthorized access & system state influence
            - generic [ref=f2e346]:
              - generic [ref=f2e347]:
                - generic [ref=f2e348]: "Exploitability: 20 / 25"
                - generic [ref=f2e349]: 80%
              - 'progressbar "Exploitability: 20 out of 25" [ref=f2e350]'
              - paragraph [ref=f2e352]: Attacker privilege & request complexity
            - generic [ref=f2e353]:
              - generic [ref=f2e354]:
                - generic [ref=f2e355]: "Data Sensitivity: 0 / 30"
                - generic [ref=f2e356]: 0%
              - 'progressbar "Data Sensitivity: 0 out of 30" [ref=f2e357]'
              - paragraph [ref=f2e358]: PII, credentials & financial records exposure
            - generic [ref=f2e359]:
              - generic [ref=f2e360]:
                - generic [ref=f2e361]: "Evidence Strength: 15 / 15"
                - generic [ref=f2e362]: 100%
              - 'progressbar "Evidence Strength: 15 out of 15" [ref=f2e363]'
              - paragraph [ref=f2e365]: Empirical reproduction & differential confidence
        - generic [ref=f2e366]:
          - generic [ref=f2e367]:
            - generic [ref=f2e368]:
              - generic [ref=f2e371]: bash — curl
              - generic [ref=f2e372]: "[Press 'c' to copy]"
            - button "Copy cURL command to clipboard" [ref=f2e373]:
              - generic [ref=f2e377]: Copy cURL
          - region "cURL PoC command" [ref=f2e379]:
            - generic [ref=f2e380]: "# Note: export TOKEN=<attacker token> first"
            - generic [ref=f2e381]: "curl -X GET http://target_api:9000/admin/users -H \"Authorization: Bearer $TOKEN\""
        - generic [ref=f2e382]:
          - generic [ref=f2e383]:
            - generic [ref=f2e384]: Dual-Identity Response Differential
            - generic [ref=f2e385]: "Left: Owner Baseline vs Right: Attacker Probe"
          - generic [ref=f2e386]:
            - generic [ref=f2e387]:
              - generic [ref=f2e388]:
                - generic [ref=f2e389]:
                  - generic [ref=f2e391]: Legitimate Owner
                  - generic [ref=f2e392]: (Legitimate Owner)
                - generic [ref=f2e393]: 200 OK
              - region "Owner baseline response" [ref=f2e394]:
                - generic [ref=f2e395]: "[ { \"id\": 1, \"username\": \"userA\", \"password_hash\": \"***REDACTED***\", \"full_name\": \"Alice Anderson\", \"email\": \"userA@example.com\", \"ssn\": \"***REDACTED***\", \"role\": \"user\" }, { \"id\": 2, \"username\": \"userB\", \"password_hash\": \"***REDACTED***\", \"full_name\": \"Bob Baker\", \"email\": \"userB@example.com\", \"ssn\": \"***REDACTED***\", \"role\": \"user\" }, { \"id\": 3, \"username\": \"admin\", \"password_hash\": \"***REDACTED***\", \"full_name\": \"Super Administrator\", \"email\": \"admin@example.com\", \"ssn\": \"***REDACTED***\", \"role\": \"admin\" } ]"
            - generic [ref=f2e396]:
              - generic [ref=f2e397]:
                - generic [ref=f2e398]:
                  - generic [ref=f2e400]: userA
                  - generic [ref=f2e401]: (Attacker Persona)
                - generic [ref=f2e402]:
                  - generic [ref=f2e403]: "Expected: 403 Forbidden"
                  - generic [ref=f2e404]: "Actual: 200 OK"
              - region "Attacker probe response" [ref=f2e408]:
                - generic [ref=f2e409]:
                  - generic [ref=f2e410]: "[ { \"id\": 1, \"username\": \"userA\", \"password_hash\": \"***REDACTED***\", \"full_name\": \"Alice Anderson\", \"email\": \"userA@example.com\", \"ssn\": \"***REDACTED***\", \"role\": \"user\" }, { \"id\": 2, \"username\": \"userB\", \"password_hash\": \"***REDACTED***\", \"full_name\": \"Bob Baker\", \"email\": \"userB@example.com\", \"ssn\": \"***REDACTED***\", \"role\": \"user\" }, { \"id\": 3, \"username\": \"admin\", \"password_hash\": \"***REDACTED***\", \"full_name\": \"Super Administrator\", \"email\": \"admin@example.com\", \"ssn\": \"***REDACTED***\", \"role\": \"admin\" } ]"
                  - generic [ref=f2e411]:
                    - generic [ref=f2e412]: "\"password_hash\": \"17************************************************************80\""
                    - generic [ref=f2e413]: "[LEAKED PII]"
                  - generic [ref=f2e414]:
                    - generic [ref=f2e415]: "\"ssn\": \"11*******33\""
                    - generic [ref=f2e416]: "[LEAKED PII]"
                  - generic [ref=f2e417]:
                    - generic [ref=f2e418]: "\"email\": \"us*************om\""
                    - generic [ref=f2e419]: "[LEAKED PII]"
                  - generic [ref=f2e420]:
                    - generic [ref=f2e421]: "\"role\": \"****\""
                    - generic [ref=f2e422]: "[LEAKED PII]"
        - generic [ref=f2e423]: ● 2 of 2 reproduced (Live Differential Verified)
        - generic [ref=f2e427]:
          - generic [ref=f2e428]: Suggested Remediation
          - generic [ref=f2e434]: Enforce strict role-based access control (RBAC). Verify that the calling user possesses administrative permissions prior to executing the operation.
        - button "AI-suggested code fix (verify before use) Phase 10" [ref=f2e436]:
          - generic [ref=f2e437]:
            - generic [ref=f2e440]: AI-suggested code fix (verify before use)
            - generic [ref=f2e441]: Phase 10
        - button "[View Secure Endpoint 403 Variant]" [ref=f2e445]
```

# Test source

```ts
  172 |             leaks.push(`sessionStorage[${key}] leaked ${secret}`);
  173 |           }
  174 |         }
  175 |         if (/Bearer ey[A-Za-z0-9_-]+/.test(val)) {
  176 |           leaks.push(`sessionStorage[${key}] leaked JWT token`);
  177 |         }
  178 |       }
  179 | 
  180 |       return leaks;
  181 |     });
  182 | 
  183 |     expect(storageAudit).toEqual([]);
  184 | 
  185 |     // Assert page HTML contains no password hashes or seed SSNs
  186 |     const pageHtml = await page.content();
  187 |     expect(pageHtml).not.toContain('$2b$12$');
  188 |     expect(pageHtml).not.toContain('111-22-3333');
  189 |     expect(pageHtml).not.toContain('444-55-6666');
  190 |   });
  191 | 
  192 |   test('3. Secure Mode Zero-Finding All-Clear State Verification', async ({ page }) => {
  193 |     // 1. Restart target in SECURE mode
  194 |     execSync(`bash "${STACK_SCRIPT}" secure`, { stdio: 'inherit' });
  195 | 
  196 |     try {
  197 |       // 2. Launch scan against secure target
  198 |       await page.goto('/scans/new');
  199 |       await page.click('button:has-text("Load demo target")');
  200 |       await page.click('button[type="submit"]');
  201 | 
  202 |       // 3. Wait for completion
  203 |       await page.waitForURL((url) => !url.pathname.endsWith('/live') && url.pathname.includes('/scans/'), {
  204 |         timeout: 120_000,
  205 |       });
  206 |       await page.waitForLoadState('networkidle');
  207 | 
  208 |       // 4. Assert All-Clear honest-copy state
  209 |       await expect(page.locator('text=No Access-Control Vulnerabilities Detected')).toBeVisible({
  210 |         timeout: 15_000,
  211 |       });
  212 |       await expect(
  213 |         page.locator('text=All differential tests satisfied expected security boundaries')
  214 |       ).toBeVisible();
  215 |       await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'all-clear.png') });
  216 |     } finally {
  217 |       // 5. Restore vulnerable stack
  218 |       execSync(`bash "${STACK_SCRIPT}" vulnerable`, { stdio: 'inherit' });
  219 |     }
  220 |   });
  221 | 
  222 |   test('4. Scan Cancellation & Target Resource Cleanup', async ({ page }) => {
  223 |     await page.goto('/scans/new');
  224 |     await page.click('button:has-text("Load demo target")');
  225 |     await page.click('button[type="submit"]');
  226 | 
  227 |     // Wait for live view
  228 |     await page.waitForURL('**/scans/*/live', { timeout: 15_000 });
  229 | 
  230 |     // Click Cancel Audit
  231 |     await page.click('button:has-text("Cancel Audit")');
  232 |     // Confirm dialog
  233 |     await page.click('button:has-text("Confirm Cancel")');
  234 | 
  235 |     // Assert status transitions to CANCELLED
  236 |     await expect(page.locator('text=CANCELLED').first()).toBeVisible({ timeout: 20_000 });
  237 | 
  238 |     // Assert via target API that no scanner created orders remain
  239 |     const ordersRes = await fetch('http://127.0.0.1:9000/orders');
  240 |     if (ordersRes.ok) {
  241 |       const orders = await ordersRes.json();
  242 |       const testOrders = Array.isArray(orders)
  243 |         ? orders.filter((o: any) => o.item && o.item.includes('scanner'))
  244 |         : [];
  245 |       expect(testOrders.length).toBe(0);
  246 |     }
  247 |   });
  248 | 
  249 |   test('5. Axe Accessibility Audits (Zero Serious/Critical Violations)', async ({ page }) => {
  250 |     // Check History page
  251 |     await page.goto('/');
  252 |     let results = await new AxeBuilder({ page }).analyze();
  253 |     let severeViolations = results.violations.filter(
  254 |       (v) => v.impact === 'serious' || v.impact === 'critical'
  255 |     );
  256 |     expect(severeViolations).toEqual([]);
  257 | 
  258 |     // Check New Scan page
  259 |     await page.goto('/scans/new');
  260 |     results = await new AxeBuilder({ page }).analyze();
  261 |     severeViolations = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
  262 |     expect(severeViolations).toEqual([]);
  263 | 
  264 |     // Check Results page
  265 |     if (createdScanId) {
  266 |       await page.goto(`/scans/${createdScanId}`);
  267 |       await page.waitForLoadState('networkidle');
  268 |       results = await new AxeBuilder({ page }).analyze();
  269 |       severeViolations = results.violations.filter(
  270 |         (v) => v.impact === 'serious' || v.impact === 'critical'
  271 |       );
> 272 |       expect(severeViolations).toEqual([]);
      |                                ^ Error: expect(received).toEqual(expected) // deep equality
  273 | 
  274 |       // Check Matrix tab
  275 |       await page.click('button:has-text("Authorization Matrix")');
  276 |       results = await new AxeBuilder({ page }).analyze();
  277 |       severeViolations = results.violations.filter(
  278 |         (v) => v.impact === 'serious' || v.impact === 'critical'
  279 |       );
  280 |       expect(severeViolations).toEqual([]);
  281 |     }
  282 |   });
  283 | 
  284 |   test('6. Responsive Layout Smoke Test (No Horizontal Scroll)', async ({ page }) => {
  285 |     const viewports = [
  286 |       { width: 1440, height: 900 },
  287 |       { width: 768, height: 1024 },
  288 |       { width: 375, height: 667 },
  289 |     ];
  290 | 
  291 |     for (const vp of viewports) {
  292 |       await page.setViewportSize(vp);
  293 |       await page.goto(createdScanId ? `/scans/${createdScanId}` : '/');
  294 |       await page.waitForLoadState('networkidle');
  295 | 
  296 |       const isOverflowing = await page.evaluate(() => {
  297 |         return document.body.scrollWidth > window.innerWidth;
  298 |       });
  299 |       expect(isOverflowing).toBe(false);
  300 |     }
  301 |   });
  302 | });
  303 | 
```