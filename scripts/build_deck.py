#!/usr/bin/env python3
"""
SentinelAPI — Hackathon Pitch Deck Generator (python-pptx)
Builds slides/SentinelAPI_Pitch.pptx programmatically using design tokens from
frontend/design/DESIGN_SYSTEM.md and real assets from docs/screenshots/ & docs/architecture.png.
"""

import os
import sys
from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.dml.color import RGBColor

# ── Paths ───────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
SLIDES_DIR = ROOT_DIR / "slides"
DOCS_DIR = ROOT_DIR / "docs"
SCREENSHOTS_DIR = DOCS_DIR / "screenshots"
OUTPUT_PPTX = SLIDES_DIR / "SentinelAPI_Pitch.pptx"

# ── Design Tokens (from frontend/design/DESIGN_SYSTEM.md) ───────────────────
COLOR_CANVAS_BASE    = RGBColor(6, 8, 15)       # #06080F
COLOR_SURFACE_PANEL  = RGBColor(13, 17, 28)     # #0D111C
COLOR_SURFACE_ELEV   = RGBColor(21, 27, 43)     # #151B2B
COLOR_SURFACE_HIGH   = RGBColor(24, 32, 51)     # #182033
COLOR_BORDER_STRUCT  = RGBColor(35, 45, 66)     # #232D42
COLOR_BORDER_LIGHT   = RGBColor(51, 65, 85)     # #334155

COLOR_BRAND_PRIMARY  = RGBColor(56, 189, 248)   # #38BDF8 (Sky blue)
COLOR_BRAND_ACCENT   = RGBColor(99, 102, 241)   # #6366F1 (Indigo)
COLOR_BRAND_HOVER    = RGBColor(125, 211, 252)  # #7DD3FC

COLOR_TEXT_PRIMARY   = RGBColor(248, 250, 252)  # #F8FAFC
COLOR_TEXT_SECONDARY = RGBColor(148, 163, 184)  # #94A3B8
COLOR_TEXT_MUTED     = RGBColor(100, 116, 139)  # #64748B

COLOR_CRITICAL       = RGBColor(239, 68, 68)    # #EF4444
COLOR_HIGH           = RGBColor(249, 115, 22)   # #F97316
COLOR_MEDIUM         = RGBColor(245, 158, 11)   # #F59E0B
COLOR_SECURE         = RGBColor(16, 185, 129)   # #10B981
COLOR_PURPLE         = RGBColor(168, 85, 247)   # #A855F7

FONT_HEADING = "Inter"
FONT_BODY    = "Inter"
FONT_CODE    = "JetBrains Mono"


def create_blank_slide(prs):
    """Creates a slide with dark background #06080F."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    # Set full-screen background
    bg = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height
    )
    bg.fill.solid()
    bg.fill.fore_color.rgb = COLOR_CANVAS_BASE
    bg.line.color.rgb = COLOR_CANVAS_BASE
    bg.line.width = Pt(0)
    return slide


def add_header(slide, title, category, slide_num, total_slides=10):
    """Adds a standardized top header bar and bottom footer."""
    # Top Header Box
    header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.9))
    tf = header_box.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p_cat = tf.paragraphs[0]
    p_cat.text = category.upper()
    p_cat.font.name = FONT_HEADING
    p_cat.font.size = Pt(10)
    p_cat.font.bold = True
    p_cat.font.color.rgb = COLOR_BRAND_PRIMARY
    p_cat.space_after = Pt(2)

    p_title = tf.add_paragraph()
    p_title.text = title
    p_title.font.name = FONT_HEADING
    p_title.font.size = Pt(22)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_TEXT_PRIMARY

    # Header Divider Line
    line = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.35), Inches(11.733), Pt(1.5)
    )
    line.fill.solid()
    line.fill.fore_color.rgb = COLOR_BORDER_STRUCT
    line.line.color.rgb = COLOR_BORDER_STRUCT

    # Footer
    footer_box = slide.shapes.add_textbox(Inches(0.8), Inches(7.0), Inches(11.733), Inches(0.35))
    ftf = footer_box.text_frame
    ftf.margin_left = ftf.margin_top = ftf.margin_right = ftf.margin_bottom = 0
    fp = ftf.paragraphs[0]
    fp.text = f"SentinelAPI · AmiHacks 2026 (Track C: Cybersecurity)                                                           Slide {slide_num} of {total_slides}"
    fp.font.name = FONT_BODY
    fp.font.size = Pt(9)
    fp.font.color.rgb = COLOR_TEXT_MUTED


def add_card(slide, left, top, width, height, bg_color=COLOR_SURFACE_PANEL, border_color=COLOR_BORDER_STRUCT, border_width=Pt(1)):
    """Draws a tactical container card."""
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = bg_color
    card.line.color.rgb = border_color
    card.line.width = border_width
    return card


# ─────────────────────────────────────────────────────────────────────────────
# SLIDE BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def build_slide_1_title(prs):
    """Slide 1: Title & Pitch"""
    slide = create_blank_slide(prs)

    # Tactical grid background accent line
    top_bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(0.6), Inches(1.8), Pt(4))
    top_bar.fill.solid()
    top_bar.fill.fore_color.rgb = COLOR_BRAND_PRIMARY
    top_bar.line.color.rgb = COLOR_BRAND_PRIMARY

    # Main Hero Box
    hero_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.1), Inches(11.7), Inches(3.2))
    tf = hero_box.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = "TRACK C — CYBERSECURITY & API SECURITY"
    p0.font.name = FONT_HEADING
    p0.font.size = Pt(12)
    p0.font.bold = True
    p0.font.color.rgb = COLOR_BRAND_PRIMARY
    p0.space_after = Pt(8)

    p1 = tf.add_paragraph()
    p1.text = "SentinelAPI"
    p1.font.name = FONT_HEADING
    p1.font.size = Pt(46)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_TEXT_PRIMARY
    p1.space_after = Pt(8)

    p2 = tf.add_paragraph()
    p2.text = "Autonomous Differential API Security Testing"
    p2.font.name = FONT_HEADING
    p2.font.size = Pt(22)
    p2.font.bold = True
    p2.font.color.rgb = COLOR_BRAND_ACCENT
    p2.space_after = Pt(14)

    p3 = tf.add_paragraph()
    p3.text = "Ingesting OpenAPI 3.x specifications, dynamically authenticating multiple test personas, learning ground-truth resource ownership without brute-forcing, and executing differential response analysis to eliminate authorization blindspots before production."
    p3.font.name = FONT_BODY
    p3.font.size = Pt(13)
    p3.font.color.rgb = COLOR_TEXT_SECONDARY

    # Highlights Row (3 cards)
    cards_data = [
        ("OWASP API TOP 10", "Automated detection of BOLA/IDOR, BFLA, and excessive data exposure."),
        ("EMPIRICAL PROOF", "Zero false positives via live attack reproduction and reproducible cURL PoCs."),
        ("ENTERPRISE GUARDRAILS", "Strict scope guards, 20 RPS rate cap, zero secrets leaked, evidence-only AI.")
    ]
    for i, (title, desc) in enumerate(cards_data):
        c_left = Inches(0.8 + i * 4.0)
        c_top = Inches(4.5)
        add_card(slide, c_left, c_top, Inches(3.733), Inches(1.3), COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)
        tb = slide.shapes.add_textbox(c_left + Inches(0.2), c_top + Inches(0.15), Inches(3.333), Inches(1.0))
        ctf = tb.text_frame
        ctf.word_wrap = True
        cp0 = ctf.paragraphs[0]
        cp0.text = title
        cp0.font.name = FONT_HEADING
        cp0.font.size = Pt(11)
        cp0.font.bold = True
        cp0.font.color.rgb = COLOR_BRAND_PRIMARY
        cp0.space_after = Pt(4)
        cp1 = ctf.add_paragraph()
        cp1.text = desc
        cp1.font.name = FONT_BODY
        cp1.font.size = Pt(10)
        cp1.font.color.rgb = COLOR_TEXT_SECONDARY

    # Team & Links Footer Card
    add_card(slide, Inches(0.8), Inches(6.0), Inches(11.733), Inches(0.75), COLOR_SURFACE_ELEV, COLOR_BRAND_ACCENT, Pt(1))
    meta_box = slide.shapes.add_textbox(Inches(1.0), Inches(6.1), Inches(11.333), Inches(0.55))
    mtf = meta_box.text_frame
    mtf.word_wrap = True
    mp = mtf.paragraphs[0]
    mp.text = "Lead Architect: Tanuj  |  Event: AmiHacks 2026  |  GitHub: https://github.com/x03tanuj/sentinel-api"
    mp.font.name = FONT_HEADING
    mp.font.size = Pt(11)
    mp.font.bold = True
    mp.font.color.rgb = COLOR_TEXT_PRIMARY


def build_slide_2_problem(prs):
    """Slide 2: Problem Statement"""
    slide = create_blank_slide(prs)
    add_header(slide, "The API Authorization Blindspot in Modern Software", "Problem Statement", 2)

    pillars = [
        ("OWASP API #1 THREAT", COLOR_CRITICAL,
         "Broken Object Level Authorization (BOLA / IDOR)",
         "BOLA remains the undisputed #1 critical vulnerability on the OWASP API Security Top 10. A user simply replaces id=101 with id=102 in an API request and immediately reads or alters another customer's private data, invoices, or medical records without authorization."),
        
        ("TRADITIONAL SCANNERS ARE BLIND", COLOR_HIGH,
         "DAST & SAST Cannot Understand Multi-User Business Logic",
         "Traditional security tools test for syntax injection (SQLi, XSS) and missing headers. They operate in a single-user sandbox and have zero understanding of object ownership, tenant boundaries, or role privileges across multiple user accounts."),
        
        ("MANUAL AUDITS MISS REGRESSIONS", COLOR_MEDIUM,
         "Fast Agile CI/CD Cycles Outpace Manual Penetration Testing",
         "Engineering teams ship dozens of API changes weekly. Manual penetration tests are expensive, infrequent (quarterly/annual), and produce point-in-time reports that miss day-to-day authorization regressions introduced during active development."),
        
        ("HIGH BLAST RADIUS & DATA LEAKS", COLOR_BRAND_PRIMARY,
         "Silent Exploitation Leads to Severe Regulatory & Financial Fallout",
         "Authorization flaws are completely silent—firewalls and WAFs see valid HTTP 200 OK responses with legitimate JSON formatting. Flaws evade perimeter defenses, causing catastrophic GDPR, HIPAA, and data-breach compliance violations.")
    ]

    for i, (tag, tag_color, headline, body) in enumerate(pillars):
        top_offset = Inches(1.6 + i * 1.3)
        add_card(slide, Inches(0.8), top_offset, Inches(11.733), Inches(1.15), COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)

        # Left Accent Strip
        strip = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), top_offset, Inches(0.12), Inches(1.15))
        strip.fill.solid()
        strip.fill.fore_color.rgb = tag_color
        strip.line.color.rgb = tag_color

        tb = slide.shapes.add_textbox(Inches(1.1), top_offset + Inches(0.12), Inches(11.2), Inches(0.9))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = f"{tag}  —  {headline}"
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(13)
        p0.font.bold = True
        p0.font.color.rgb = tag_color
        p0.space_after = Pt(3)

        p1 = tf.add_paragraph()
        p1.text = body
        p1.font.name = FONT_BODY
        p1.font.size = Pt(10.5)
        p1.font.color.rgb = COLOR_TEXT_SECONDARY


def build_slide_3_solution(prs):
    """Slide 3: Proposed Solution"""
    slide = create_blank_slide(prs)
    add_header(slide, "Autonomous Differential API Security Testing", "Proposed Solution", 3)

    # Core Value Prop Banner
    add_card(slide, Inches(0.8), Inches(1.6), Inches(11.733), Inches(0.9), COLOR_SURFACE_ELEV, COLOR_BRAND_ACCENT, Pt(1))
    banner_tb = slide.shapes.add_textbox(Inches(1.0), Inches(1.68), Inches(11.333), Inches(0.75))
    btf = banner_tb.text_frame
    btf.word_wrap = True
    bp = btf.paragraphs[0]
    bp.text = "SentinelAPI solves the authorization blindspot by reading OpenAPI contracts, orchestrating multi-persona credentials, discovering legitimate resource ownership, and proving access violations mathematically via differential response comparison."
    bp.font.name = FONT_BODY
    bp.font.size = Pt(12)
    bp.font.bold = True
    bp.font.color.rgb = COLOR_TEXT_PRIMARY

    # 4 Solution Pillars (2x2 Grid)
    grid_items = [
        ("1. SPEC-DRIVEN ATTACK SURFACE MAPPING", COLOR_BRAND_PRIMARY,
         "Ingests OpenAPI 3.x contracts from URLs or JSON/YAML. Automatically validates schemas, resolves complex circular $ref pointers, and prioritizes endpoints based on state-changing operations and authentication requirements."),
        
        ("2. MULTI-PERSONA GROUND-TRUTH MATRIX", COLOR_SECURE,
         "Logs in distinct test personas (userA, userB, admin) via JWT/OAuth2. Without guessing random IDs, it queries legitimate endpoints to learn owned resources and compiles a mathematical Allow/Deny expectation matrix."),
        
        ("3. DIFFERENTIAL RESPONSE ANALYSIS", COLOR_MEDIUM,
         "Executes rate-limited cross-user attack probes. Analyzes baseline vs attack responses using weighted Jaccard similarity distance, status code shifts, and sensitive field leakage to detect unauthorized access."),
        
        ("4. EMPIRICAL PROOF & REPRODUCIBLE POCS", COLOR_CRITICAL,
         "Re-executes top findings against the live API to empirically prove reproducibility and eliminate false positives. Generates copy-pasteable, shell-safe cURL PoCs with masked tokens for immediate developer remediation.")
    ]

    for idx, (title, color, text) in enumerate(grid_items):
        col = idx % 2
        row = idx // 2
        c_left = Inches(0.8 + col * 5.966)
        c_top = Inches(2.7 + row * 2.05)
        c_width = Inches(5.766)
        c_height = Inches(1.9)

        add_card(slide, c_left, c_top, c_width, c_height, COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)

        # Header tag
        tb = slide.shapes.add_textbox(c_left + Inches(0.25), c_top + Inches(0.18), c_width - Inches(0.5), c_height - Inches(0.36))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(12)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(6)

        p1 = tf.add_paragraph()
        p1.text = text
        p1.font.name = FONT_BODY
        p1.font.size = Pt(10.5)
        p1.font.color.rgb = COLOR_TEXT_SECONDARY


def build_slide_4_architecture(prs):
    """Slide 4: System Architecture"""
    slide = create_blank_slide(prs)
    add_header(slide, "Decoupled Architecture & Enforced Safety Boundaries", "System Architecture", 4)

    # Embed High-Res Architecture Diagram
    arch_png = DOCS_DIR / "architecture.png"
    if arch_png.exists():
        # Place the diagram centered and framed
        img_left = Inches(0.8)
        img_top = Inches(1.55)
        img_width = Inches(11.733)
        img_height = Inches(4.7)

        # Frame backing
        add_card(slide, img_left - Inches(0.04), img_top - Inches(0.04), img_width + Inches(0.08), img_height + Inches(0.08), COLOR_CANVAS_BASE, COLOR_BORDER_LIGHT, Pt(1))
        slide.shapes.add_picture(str(arch_png), img_left, img_top, img_width, img_height)

    # Caption / Invariants Bar
    caption_top = Inches(6.35)
    add_card(slide, Inches(0.8), caption_top, Inches(11.733), Inches(0.55), COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)
    cap_tb = slide.shapes.add_textbox(Inches(0.95), caption_top + Inches(0.08), Inches(11.4), Inches(0.4))
    ctf = cap_tb.text_frame
    ctf.word_wrap = True
    cp = ctf.paragraphs[0]
    cp.text = "Core Invariant: Deterministic Security Engine is strictly decoupled from presentation and storage. The AI Analyst is an evidence-only side-branch with zero raw data egress."
    cp.font.name = FONT_HEADING
    cp.font.size = Pt(9.5)
    cp.font.bold = True
    cp.font.color.rgb = COLOR_BRAND_PRIMARY


def build_slide_5_core_engine(prs):
    """Slide 5: Core Technologies & Security Engine"""
    slide = create_blank_slide(prs)
    add_header(slide, "Proprietary Judged IP: 6 Core Engineering Engines", "Key Technologies", 5)

    engines = [
        ("ATTACK SURFACE MAPPER", COLOR_BRAND_PRIMARY,
         "Parses and dereferences OpenAPI 3.x contracts with circular $ref isolation. Extracts parameters, routes, auth constraints, and calculates preliminary risk prioritization scores."),
        
        ("IDENTITY & EXECUTION ENGINE", COLOR_SECURE,
         "Orchestrates multi-user persona sessions via JWT/Bearer auth. Dispatches probes through token-bucket rate limiter (20 RPS) and immutable host allowlists (assert_in_scope)."),
        
        ("GROUND-TRUTH MATRIX COMPILER", COLOR_BRAND_ACCENT,
         "Queries legitimate profile & collection GET endpoints to dynamically discover resources owned by each persona, constructing an explicit mathematical Allow/Deny expectation matrix."),
        
        ("DIFFERENTIAL ANALYSIS ENGINE", COLOR_MEDIUM,
         "Compares attack vs legitimate baseline responses using weighted Jaccard similarity distance, status-code divergence, and sensitive-field classification."),
        
        ("6 MODULAR SECURITY CHECKS", COLOR_CRITICAL,
         "Extensible check suite testing BOLA/IDOR (API1), Broken Authentication (API2), Excessive Data Exposure (API3), Rate Limiting (API4), BFLA Privileges (API5), and Input Handling (API8)."),
        
        ("EXPLAINABLE RISK & CONFIDENCE", COLOR_PURPLE,
         "Replaces arbitrary CVSS guesswork with a transparent 4-part score: Impact (0-40) + Exploitability (0-25) + Sensitivity (0-30) + Evidence Strength (0-15) plus empirical reproduction.")
    ]

    for idx, (title, color, desc) in enumerate(engines):
        col = idx % 3
        row = idx // 3
        c_left = Inches(0.8 + col * 4.0)
        c_top = Inches(1.6 + row * 2.55)
        c_width = Inches(3.733)
        c_height = Inches(2.35)

        add_card(slide, c_left, c_top, c_width, c_height, COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)

        # Color bar top
        bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, c_top, c_width, Pt(3))
        bar.fill.solid()
        bar.fill.fore_color.rgb = color
        bar.line.color.rgb = color

        tb = slide.shapes.add_textbox(c_left + Inches(0.2), c_top + Inches(0.18), c_width - Inches(0.4), c_height - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(11)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(8)

        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = FONT_BODY
        p1.font.size = Pt(10)
        p1.font.color.rgb = COLOR_TEXT_SECONDARY


def build_slide_6_tech_highlights(prs):
    """Slide 6: Technical Highlights & Safety Design"""
    slide = create_blank_slide(prs)
    add_header(slide, "Production Safety Guardrails & Zero-Trust Design", "Technical Highlights", 6)

    # Left Column: Enforced Safety Guardrails
    left_x = Inches(0.8)
    col_w = Inches(5.766)
    add_card(slide, left_x, Inches(1.6), col_w, Inches(5.1), COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)

    tb_left = slide.shapes.add_textbox(left_x + Inches(0.3), Inches(1.8), col_w - Inches(0.6), Inches(4.7))
    tfl = tb_left.text_frame
    tfl.word_wrap = True

    p_lh = tfl.paragraphs[0]
    p_lh.text = "ENFORCED SAFETY & AUDIT BOUNDARIES"
    p_lh.font.name = FONT_HEADING
    p_lh.font.size = Pt(13)
    p_lh.font.bold = True
    p_lh.font.color.rgb = COLOR_BRAND_PRIMARY
    p_lh.space_after = Pt(10)

    guardrails = [
        ("Scope Guard (assert_in_scope)", "Hardcoded validation against explicit ALLOWED_HOSTS. Any probe dispatch to third-party domains or unauthorized IPs raises ScopeViolationError immediately."),
        ("Token-Bucket Rate Limiter", "Restricts scanning speed to 20 RPS to prevent denial-of-service, API degradation, or accidental infrastructure lockout on target services."),
        ("Strict Request Budget Cap", "Hard maximum of 1,000 requests per scan prevents infinite loops, recursive endpoint traps, and runaway probe generation."),
        ("Defense-in-Depth Redaction", "Tokens, Authorization headers, and passwords are permanently scrubbed before disk storage, API responses, or UI rendering. PoCs use $TOKEN."),
        ("Shielded State Cleanup", "Objects created during tests are deleted in shielded finally blocks, ensuring zero residual artifacts remain on target APIs.")
    ]
    for title, desc in guardrails:
        p_t = tfl.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(10)
        p_t.font.bold = True
        p_t.font.color.rgb = COLOR_TEXT_PRIMARY
        
        # Add desc
        run = p_t.add_run()
        run.text = desc
        run.font.name = FONT_BODY
        run.font.bold = False
        run.font.color.rgb = COLOR_TEXT_SECONDARY
        p_t.space_after = Pt(6)

    # Right Column: AI Egress Boundary & Modern Stack
    right_x = Inches(6.766)
    add_card(slide, right_x, Inches(1.6), col_w, Inches(5.1), COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)

    tb_right = slide.shapes.add_textbox(right_x + Inches(0.3), Inches(1.8), col_w - Inches(0.6), Inches(4.7))
    tfr = tb_right.text_frame
    tfr.word_wrap = True

    p_rh = tfr.paragraphs[0]
    p_rh.text = "ZERO-LEAK AI ANALYST & MODERN TECH STACK"
    p_rh.font.name = FONT_HEADING
    p_rh.font.size = Pt(13)
    p_rh.font.bold = True
    p_rh.font.color.rgb = COLOR_BRAND_ACCENT
    p_rh.space_after = Pt(10)

    ai_stack = [
        ("Evidence-Only AI Analyst", "Optional side-branch (Groq, OpenRouter, Gemini). The LLM NEVER detects vulnerabilities, modifies severity, or influences scan outcomes."),
        ("Pre-Flight Egress Assertion", "assert_payload_safe() runs regex scans on outgoing payloads. Egress is terminated if tokens, SSNs, credit cards, or internal IPs are detected."),
        ("Deterministic Fallback", "If the LLM provider times out, returns malformed JSON, or exceeds rate limits, pre-compiled deterministic remediation templates activate seamlessly."),
        ("High-Performance Backend", "Python 3.11/3.14 with FastAPI async orchestrator, Pydantic v2 schemas, in-memory atomic JSON store (scans.json), and real-time SSE telemetry."),
        ("Tactical Developer UI", "React 19, Vite, Tailwind CSS with tactical design system tokens, WCAG AA contrast standards, and responsive desktop dashboards.")
    ]
    for title, desc in ai_stack:
        p_t = tfr.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(10)
        p_t.font.bold = True
        p_t.font.color.rgb = COLOR_TEXT_PRIMARY
        
        run = p_t.add_run()
        run.text = desc
        run.font.name = FONT_BODY
        run.font.bold = False
        run.font.color.rgb = COLOR_TEXT_SECONDARY
        p_t.space_after = Pt(6)


def build_slide_7_screenshots(prs):
    """Slide 7: Demo Screenshots"""
    slide = create_blank_slide(prs)
    add_header(slide, "Developer-First Tactical Triage & Differential Inspector", "Live Product Demo", 7)

    # Left Screenshot: Triage Workspace
    img1_path = SCREENSHOTS_DIR / "triage-workspace.png"
    img2_path = SCREENSHOTS_DIR / "finding-inspector.png"

    card_w = Inches(5.766)
    card_h = Inches(4.3)
    top_y = Inches(1.6)

    # Frame 1
    add_card(slide, Inches(0.8), top_y, card_w, card_h, COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)
    if img1_path.exists():
        slide.shapes.add_picture(str(img1_path), Inches(0.9), top_y + Inches(0.1), card_w - Inches(0.2), Inches(3.2))
    
    tb1 = slide.shapes.add_textbox(Inches(0.9), top_y + Inches(3.4), card_w - Inches(0.2), Inches(0.8))
    tf1 = tb1.text_frame
    tf1.word_wrap = True
    p1 = tf1.paragraphs[0]
    p1.text = "Results Triage Workspace: Real-Time Findings Stream"
    p1.font.name = FONT_HEADING
    p1.font.size = Pt(11)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_BRAND_PRIMARY
    p1_sub = tf1.add_paragraph()
    p1_sub.text = "Live telemetry HUD with verified control counts, severity badges, and one-click filtering by OWASP category, status, and path."
    p1_sub.font.name = FONT_BODY
    p1_sub.font.size = Pt(9.5)
    p1_sub.font.color.rgb = COLOR_TEXT_SECONDARY

    # Frame 2
    add_card(slide, Inches(6.766), top_y, card_w, card_h, COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)
    if img2_path.exists():
        slide.shapes.add_picture(str(img2_path), Inches(6.866), top_y + Inches(0.1), card_w - Inches(0.2), Inches(3.2))
    
    tb2 = slide.shapes.add_textbox(Inches(6.866), top_y + Inches(3.4), card_w - Inches(0.2), Inches(0.8))
    tf2 = tb2.text_frame
    tf2.word_wrap = True
    p2 = tf2.paragraphs[0]
    p2.text = "Differential Finding Inspector: Mathematical Evidence"
    p2.font.name = FONT_HEADING
    p2.font.size = Pt(11)
    p2.font.bold = True
    p2.font.color.rgb = COLOR_CRITICAL
    p2_sub = tf2.add_paragraph()
    p2_sub.text = "Side-by-side baseline vs attack diff showing BOLA breach (200 OK vs 403), leaked PII fields, 4-factor risk breakdown, and copy-paste cURL PoC."
    p2_sub.font.name = FONT_BODY
    p2_sub.font.size = Pt(9.5)
    p2_sub.font.color.rgb = COLOR_TEXT_SECONDARY

    # Bottom summary callout
    add_card(slide, Inches(0.8), Inches(6.1), Inches(11.733), Inches(0.65), COLOR_SURFACE_ELEV, COLOR_SECURE, Pt(1))
    sum_tb = slide.shapes.add_textbox(Inches(1.0), Inches(6.18), Inches(11.333), Inches(0.5))
    stf = sum_tb.text_frame
    stf.word_wrap = True
    sp = stf.paragraphs[0]
    sp.text = "Zero Guesswork: Every finding includes empirical reproduction status (100% verified), exact response diffs, and reproducible curl PoCs."
    sp.font.name = FONT_HEADING
    sp.font.size = Pt(10)
    sp.font.bold = True
    sp.font.color.rgb = COLOR_TEXT_PRIMARY


def build_slide_8_ci_cd_gate(prs):
    """Slide 8: CI/CD Security Quality Gate"""
    slide = create_blank_slide(prs)
    add_header(slide, "Shift-Left Automated Security Quality Gate for CI/CD", "CI/CD & Integration", 8)

    # 3 Cards Layout
    items = [
        ("HEADLESS CI GATE CLI", COLOR_BRAND_PRIMARY,
         "scripts/ci_gate.py",
         "Runs headlessly in any CI/CD pipeline (GitHub Actions, GitLab CI, CircleCI). Evaluates exported scan findings against configurable policy thresholds (--fail-on CRITICAL,HIGH --min-confidence 0.70) and breaks builds with exit code 1 on policy breaches."),
        
        ("AUTOMATED SARIF & AUDIT EXPORTS", COLOR_SECURE,
         "GitHub Security Tab Integration",
         "Automatically renders and exports deterministic SARIF, Markdown, and JSON audit reports. Findings appear natively in GitHub Security code scanning alerts, enabling instant developer triage inside pull requests."),
        
        ("HERMETIC MULTI-TARGET SANDBOX", COLOR_BRAND_ACCENT,
         "Turnkey Docker Compose Testbed",
         "Ships with realistic vulnerable sandboxes (Retail Store, MedPulse Healthcare, FinTech API) on ports 9000-9003. When SECURE_MODE=true is toggled, SentinelAPI verifies 100% access controls pass with zero false positives.")
    ]

    for idx, (title, color, tag, desc) in enumerate(items):
        c_left = Inches(0.8 + idx * 4.0)
        c_top = Inches(1.6)
        c_width = Inches(3.733)
        c_height = Inches(3.8)

        add_card(slide, c_left, c_top, c_width, c_height, COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)

        # Header tag strip
        bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, c_top, c_width, Pt(3))
        bar.fill.solid()
        bar.fill.fore_color.rgb = color
        bar.line.color.rgb = color

        tb = slide.shapes.add_textbox(c_left + Inches(0.2), c_top + Inches(0.2), c_width - Inches(0.4), c_height - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(12)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(2)

        ptag = tf.add_paragraph()
        ptag.text = tag
        ptag.font.name = FONT_CODE
        ptag.font.size = Pt(9)
        ptag.font.color.rgb = COLOR_TEXT_MUTED
        ptag.space_after = Pt(10)

        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = FONT_BODY
        p1.font.size = Pt(10.5)
        p1.font.color.rgb = COLOR_TEXT_SECONDARY

    # Bottom Code Snippet Card
    add_card(slide, Inches(0.8), Inches(5.6), Inches(11.733), Inches(1.2), COLOR_SURFACE_ELEV, COLOR_BORDER_STRUCT)
    code_tb = slide.shapes.add_textbox(Inches(1.0), Inches(5.68), Inches(11.333), Inches(1.0))
    ctf = code_tb.text_frame
    ctf.word_wrap = True
    
    cp0 = ctf.paragraphs[0]
    cp0.text = "GitHub Actions Workflow Integration (ci.yml):"
    cp0.font.name = FONT_HEADING
    cp0.font.size = Pt(10)
    cp0.font.bold = True
    cp0.font.color.rgb = COLOR_BRAND_PRIMARY
    cp0.space_after = Pt(4)

    cp1 = ctf.add_paragraph()
    cp1.text = "python -m app.cli scan --spec http://api:8000/openapi.json --base-url http://api:8000 --json-out findings.json\npython scripts/ci_gate.py --findings findings.json --fail-on CRITICAL,HIGH --min-confidence 0.70"
    cp1.font.name = FONT_CODE
    cp1.font.size = Pt(9.5)
    cp1.font.color.rgb = COLOR_BRAND_HOVER


def build_slide_9_future_roadmap(prs):
    """Slide 9: Future Scope & SaaS Commercial Roadmap"""
    slide = create_blank_slide(prs)
    add_header(slide, "Commercial Roadmap: Beyond the Hackathon", "Future Scope & SaaS Vision", 9)

    pillars = [
        ("OPEN-SOURCE CLI + PAID CLOUD SAAS", COLOR_BRAND_PRIMARY,
         "Freemium Enterprise Model",
         "Maintain open-source CLI for individual developers and local CI gates. Commercialize a hosted, multi-tenant SaaS dashboard for engineering teams with centralized RBAC, historical risk trending, and vulnerability triage workflows."),
        
        ("ENTERPRISE OAUTH2 & SSO NEGOTIATION", COLOR_SECURE,
         "Automated Identity Orchestration",
         "Extend beyond static JWTs to automated OAuth2 / OIDC PKCE flow negotiation, SAML handshakes, and mTLS client-certificate authentication for complex enterprise banking and healthcare environments."),
        
        ("CUSTOM REGULATORY COMPLIANCE ENGINES", COLOR_MEDIUM,
         "Declarative Compliance Frameworks",
         "Provide declarative YAML policy mappings translating authorization findings directly into HIPAA, PCI-DSS, SOC 2, and ISO 27001 audit deliverables with automated executive PDF sign-off reports."),
        
        ("DISTRIBUTED SCAN MESH & PERSISTENCE", COLOR_PURPLE,
         "Scalable Microservice Architecture",
         "Deploy distributed Kubernetes scanner workers capable of concurrently auditing large microservice meshes, backed by MongoDB and PostgreSQL persistence adapters for multi-year enterprise audit archiving.")
    ]

    for idx, (title, color, tag, desc) in enumerate(pillars):
        col = idx % 2
        row = idx // 2
        c_left = Inches(0.8 + col * 5.966)
        c_top = Inches(1.6 + row * 2.5)
        c_width = Inches(5.766)
        c_height = Inches(2.25)

        add_card(slide, c_left, c_top, c_width, c_height, COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)

        bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, c_top, c_width, Pt(3))
        bar.fill.solid()
        bar.fill.fore_color.rgb = color
        bar.line.color.rgb = color

        tb = slide.shapes.add_textbox(c_left + Inches(0.25), c_top + Inches(0.2), c_width - Inches(0.5), c_height - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(11.5)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(2)

        ptag = tf.add_paragraph()
        ptag.text = tag
        ptag.font.name = FONT_HEADING
        ptag.font.size = Pt(9.5)
        ptag.font.bold = True
        ptag.font.color.rgb = COLOR_TEXT_MUTED
        ptag.space_after = Pt(6)

        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = FONT_BODY
        p1.font.size = Pt(10)
        p1.font.color.rgb = COLOR_TEXT_SECONDARY


def build_slide_10_team_summary(prs):
    """Slide 10: Team, Summary & Q&A"""
    slide = create_blank_slide(prs)
    add_header(slide, "Team & Project Summary — Questions & Live Demo", "Conclusion & Q&A", 10)

    # Left Card: Team Ownership & Contributions
    left_x = Inches(0.8)
    col_w = Inches(5.766)
    add_card(slide, left_x, Inches(1.6), col_w, Inches(5.1), COLOR_SURFACE_PANEL, COLOR_BORDER_STRUCT)

    tb_left = slide.shapes.add_textbox(left_x + Inches(0.3), Inches(1.8), col_w - Inches(0.6), Inches(4.7))
    tfl = tb_left.text_frame
    tfl.word_wrap = True

    p_th = tfl.paragraphs[0]
    p_th.text = "CORE TEAM & CONTRIBUTIONS"
    p_th.font.name = FONT_HEADING
    p_th.font.size = Pt(13)
    p_th.font.bold = True
    p_th.font.color.rgb = COLOR_BRAND_PRIMARY
    p_th.space_after = Pt(10)

    p_lead = tfl.add_paragraph()
    p_lead.text = "Tanuj — Lead Security Architect & Full-Stack Engineer"
    p_lead.font.name = FONT_HEADING
    p_lead.font.size = Pt(11)
    p_lead.font.bold = True
    p_lead.font.color.rgb = COLOR_TEXT_PRIMARY
    p_lead.space_after = Pt(6)

    contribs = [
        "Core Security Engine: Differential response analyzer, ground-truth authorization matrix compiler, and 6 modular OWASP security checks.",
        "Execution & Safety Infrastructure: Token-bucket HTTP executor, strict immutable scope guard, rate/budget caps, and multi-persona JWT orchestrator.",
        "Backend & Storage: FastAPI async orchestrator, real-time SSE telemetry stream, and atomic JSON store with secret leak guards.",
        "Tactical Web UI: React 19/Vite dashboard, Results Triage Workspace, Authorization Heatmap, and Differential Inspector.",
        "CI Quality Gate: Headless ci_gate.py, Docker Compose testbed, live empirical reproduction, and zero-egress AI analyst boundary."
    ]
    for c in contribs:
        pc = tfl.add_paragraph()
        pc.text = f"• {c}"
        pc.font.name = FONT_BODY
        pc.font.size = Pt(9.5)
        pc.font.color.rgb = COLOR_TEXT_SECONDARY
        pc.space_after = Pt(4)

    # Right Card: Conclusion, Links, Q&A
    right_x = Inches(6.766)
    add_card(slide, right_x, Inches(1.6), col_w, Inches(5.1), COLOR_SURFACE_PANEL, COLOR_BRAND_ACCENT, Pt(1))

    tb_right = slide.shapes.add_textbox(right_x + Inches(0.3), Inches(1.8), col_w - Inches(0.6), Inches(4.7))
    tfr = tb_right.text_frame
    tfr.word_wrap = True

    p_qh = tfr.paragraphs[0]
    p_qh.text = "PROJECT SUMMARY & DEMO ACCESS"
    p_qh.font.name = FONT_HEADING
    p_qh.font.size = Pt(13)
    p_qh.font.bold = True
    p_qh.font.color.rgb = COLOR_BRAND_ACCENT
    p_qh.space_after = Pt(14)

    p_quote = tfr.add_paragraph()
    p_quote.text = "“SentinelAPI stops API authorization breaches before code hits production — fully autonomous, mathematically verified, with reproducible evidence and zero secrets leaked.”"
    p_quote.font.name = FONT_HEADING
    p_quote.font.size = Pt(12)
    p_quote.font.bold = True
    p_quote.font.color.rgb = COLOR_TEXT_PRIMARY
    p_quote.space_after = Pt(18)

    links = [
        ("GitHub Repository", "https://github.com/x03tanuj/sentinel-api"),
        ("Live Tactical Dashboard", "http://localhost:8080"),
        ("Interactive Demo Script", "bash scripts/demo.sh"),
        ("Architecture Diagram", "docs/architecture.png (2400x1400)")
    ]
    for label, val in links:
        pl = tfr.add_paragraph()
        pl.text = f"{label}: "
        pl.font.name = FONT_HEADING
        pl.font.size = Pt(10)
        pl.font.bold = True
        pl.font.color.rgb = COLOR_BRAND_PRIMARY
        
        run = pl.add_run()
        run.text = val
        run.font.name = FONT_CODE
        run.font.bold = False
        run.font.color.rgb = COLOR_BRAND_HOVER
        pl.space_after = Pt(6)

    p_ask = tfr.add_paragraph()
    p_ask.text = "\nThank You! We are now open for Q&A."
    p_ask.font.name = FONT_HEADING
    p_ask.font.size = Pt(14)
    p_ask.font.bold = True
    p_ask.font.color.rgb = COLOR_SECURE


# ─────────────────────────────────────────────────────────────────────────────
# MAIN GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def main():
    SLIDES_DIR.mkdir(parents=True, exist_ok=True)
    print("Initializing PowerPoint presentation (16:9 widescreen)...")
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    print("Building Slide 1: Title & Pitch...")
    build_slide_1_title(prs)

    print("Building Slide 2: Problem Statement...")
    build_slide_2_problem(prs)

    print("Building Slide 3: Proposed Solution...")
    build_slide_3_solution(prs)

    print("Building Slide 4: System Architecture...")
    build_slide_4_architecture(prs)

    print("Building Slide 5: Key Technologies & Security Engine...")
    build_slide_5_core_engine(prs)

    print("Building Slide 6: Technical Highlights & Safety...")
    build_slide_6_tech_highlights(prs)

    print("Building Slide 7: Live Product Demo...")
    build_slide_7_screenshots(prs)

    print("Building Slide 8: CI/CD Quality Gate...")
    build_slide_8_ci_cd_gate(prs)

    print("Building Slide 9: Future Scope & SaaS Roadmap...")
    build_slide_9_future_roadmap(prs)

    print("Building Slide 10: Team, Summary & Q&A...")
    build_slide_10_team_summary(prs)

    print(f"Saving PPTX to: {OUTPUT_PPTX}")
    prs.save(str(OUTPUT_PPTX))
    print(f"✅ Successfully generated {len(prs.slides)} slides in {OUTPUT_PPTX}")


if __name__ == "__main__":
    main()
