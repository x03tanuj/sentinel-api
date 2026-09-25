#!/usr/bin/env python3
"""
SentinelAPI — Hackathon Pitch Deck Generator (python-pptx)
Matches Section 6.2 Presentation Deliverables (Max 8-10 slides).
New high-contrast cyber-tech aesthetic with larger, bolder typography.
"""

from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor

ROOT_DIR = Path(__file__).resolve().parent.parent
SLIDES_DIR = ROOT_DIR / "slides"
DOCS_DIR = ROOT_DIR / "docs"
SCREENSHOTS_DIR = DOCS_DIR / "screenshots"
OUTPUT_PPTX = SLIDES_DIR / "SentinelAPI_Pitch.pptx"

# ── High-Contrast Cyber-Tech Design Tokens ─────────────────────────────────
COLOR_CANVAS_BASE    = RGBColor(7, 9, 19)       # #070913 (Deep obsidian)
COLOR_CARD_BG        = RGBColor(14, 19, 38)     # #0E1326 (Card background)
COLOR_CARD_ELEV      = RGBColor(19, 26, 54)     # #131A36 (Raised card)
COLOR_BORDER         = RGBColor(32, 41, 69)     # #202945 (Border)
COLOR_BORDER_CYAN    = RGBColor(56, 189, 248)   # #38BDF8 (Glow border)

COLOR_CYAN           = RGBColor(56, 189, 248)   # #38BDF8 (Electric Cyan)
COLOR_INDIGO         = RGBColor(129, 140, 248)  # #818CF8 (Electric Violet)
COLOR_EMERALD        = RGBColor(52, 211, 153)   # #34D399 (Emerald Green)
COLOR_RED            = RGBColor(248, 113, 113)  # #F87171 (Critical Red)
COLOR_ORANGE         = RGBColor(251, 146, 60)   # #FB923C (High Orange)
COLOR_AMBER          = RGBColor(251, 191, 36)   # #FBBF24 (Medium Amber)
COLOR_PURPLE         = RGBColor(192, 132, 252)  # #C084FC (Purple)

COLOR_WHITE          = RGBColor(255, 255, 255)  # #FFFFFF (Crisp White)
COLOR_TEXT_PRIMARY   = RGBColor(248, 250, 252)  # #F8FAFC
COLOR_TEXT_MUTED     = RGBColor(148, 163, 184)  # #94A3B8 (High-contrast slate)
COLOR_TEXT_DIM       = RGBColor(100, 116, 139)  # #64748B

FONT_HEADING = "Trebuchet MS"  # Highly readable on all projectors/systems
FONT_BODY    = "Calibri"
FONT_CODE    = "Consolas"


def create_blank_slide(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg.fill.solid()
    bg.fill.fore_color.rgb = COLOR_CANVAS_BASE
    bg.line.color.rgb = COLOR_CANVAS_BASE
    bg.line.width = Pt(0)
    return slide


def add_header(slide, title, category, slide_num, total_slides=10):
    # Header text box
    header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.733), Inches(1.1))
    tf = header_box.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    p_cat = tf.paragraphs[0]
    p_cat.text = f"● {category.upper()}"
    p_cat.font.name = FONT_HEADING
    p_cat.font.size = Pt(11)
    p_cat.font.bold = True
    p_cat.font.color.rgb = COLOR_CYAN
    p_cat.space_after = Pt(2)

    p_title = tf.add_paragraph()
    p_title.text = title
    p_title.font.name = FONT_HEADING
    p_title.font.size = Pt(26)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_WHITE

    # Divider bar
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.5), Inches(11.733), Pt(2))
    line.fill.solid()
    line.fill.fore_color.rgb = COLOR_BORDER
    line.line.color.rgb = COLOR_BORDER

    # Footer
    footer_box = slide.shapes.add_textbox(Inches(0.8), Inches(7.0), Inches(11.733), Inches(0.35))
    ftf = footer_box.text_frame
    ftf.margin_left = ftf.margin_top = ftf.margin_right = ftf.margin_bottom = 0
    fp = ftf.paragraphs[0]
    fp.text = f"SentinelAPI · AmiHacks 2026 (Track C: Cybersecurity)                                                           Slide {slide_num} of {total_slides}"
    fp.font.name = FONT_BODY
    fp.font.size = Pt(10)
    fp.font.bold = True
    fp.font.color.rgb = COLOR_TEXT_DIM


def add_card(slide, left, top, width, height, bg_color=COLOR_CARD_BG, border_color=COLOR_BORDER, border_width=Pt(1.5)):
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = bg_color
    card.line.color.rgb = border_color
    card.line.width = border_width
    return card


# ── Slide 1: Track Selection & Cover ─────────────────────────────────────────
def build_slide_1_cover(prs):
    slide = create_blank_slide(prs)

    # Track Badge
    badge = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.6), Inches(5.6), Inches(0.5))
    badge.fill.solid()
    badge.fill.fore_color.rgb = COLOR_CARD_ELEV
    badge.line.color.rgb = COLOR_CYAN
    badge.line.width = Pt(2)
    btf = badge.text_frame
    bp = btf.paragraphs[0]
    bp.text = "★ AMIHACKS 2026 · TRACK C: CYBERSECURITY & API SECURITY"
    bp.font.name = FONT_HEADING
    bp.font.size = Pt(11)
    bp.font.bold = True
    bp.font.color.rgb = COLOR_CYAN

    # Hero Titles
    hero_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.3), Inches(11.733), Inches(3.0))
    tf = hero_box.text_frame
    tf.word_wrap = True

    p1 = tf.paragraphs[0]
    p1.text = "SentinelAPI"
    p1.font.name = FONT_HEADING
    p1.font.size = Pt(56)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_WHITE
    p1.space_after = Pt(4)

    p2 = tf.add_paragraph()
    p2.text = "Autonomous Differential API Security Testing"
    p2.font.name = FONT_HEADING
    p2.font.size = Pt(24)
    p2.font.bold = True
    p2.font.color.rgb = COLOR_INDIGO
    p2.space_after = Pt(16)

    p3 = tf.add_paragraph()
    p3.text = "While 200 teams build generic AI wrappers or test basic SQLi/XSS, SentinelAPI solves the #1 blindspot in modern cloud software: Broken Object Level Authorization (BOLA/IDOR)."
    p3.font.name = FONT_BODY
    p3.font.size = Pt(16)
    p3.font.bold = True
    p3.font.color.rgb = COLOR_TEXT_PRIMARY

    # 3 High-Impact Pillars
    pillars = [
        ("WHAT TRACK C DEMANDS", COLOR_CYAN, "OWASP API #1 Focus", "Automated detection of authorization logic flaws across multi-tenant boundaries that traditional scanners miss completely."),
        ("HOW WE SOLVE IT", COLOR_EMERALD, "Ground-Truth Matrix", "Learns real resource ownership without guessing IDs, then compares cross-user responses using weighted Jaccard differential distance."),
        ("WHY WE WIN", COLOR_PURPLE, "Zero False Positives", "Empirical live re-probes verify 100% reproducibility, generating shell-safe copy-paste cURL PoCs with zero cleartext token leaks.")
    ]
    for i, (tag, color, headline, desc) in enumerate(pillars):
        c_left = Inches(0.8 + i * 4.0)
        c_top = Inches(4.5)
        add_card(slide, c_left, c_top, Inches(3.733), Inches(1.4), COLOR_CARD_BG, color, Pt(1.5))
        tb = slide.shapes.add_textbox(c_left + Inches(0.2), c_top + Inches(0.12), Inches(3.333), Inches(1.15))
        ctf = tb.text_frame
        ctf.word_wrap = True
        cp0 = ctf.paragraphs[0]
        cp0.text = f"{tag} · {headline}"
        cp0.font.name = FONT_HEADING
        cp0.font.size = Pt(11)
        cp0.font.bold = True
        cp0.font.color.rgb = color
        cp0.space_after = Pt(4)

        cp1 = ctf.add_paragraph()
        cp1.text = desc
        cp1.font.name = FONT_BODY
        cp1.font.size = Pt(11)
        cp1.font.color.rgb = COLOR_TEXT_MUTED

    # Footer Card
    add_card(slide, Inches(0.8), Inches(6.1), Inches(11.733), Inches(0.65), COLOR_CARD_ELEV, COLOR_CYAN, Pt(1.5))
    meta_box = slide.shapes.add_textbox(Inches(1.0), Inches(6.18), Inches(11.333), Inches(0.45))
    mtf = meta_box.text_frame
    mp = mtf.paragraphs[0]
    mp.text = "Lead Security Architect: Tanuj  |  Full-Stack & Security Engineering  |  GitHub: https://github.com/x03tanuj/sentinel-api"
    mp.font.name = FONT_HEADING
    mp.font.size = Pt(11)
    mp.font.bold = True
    mp.font.color.rgb = COLOR_WHITE


# ── Slide 2: Problem Statement ───────────────────────────────────────────────
def build_slide_2_problem(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "The Multi-Billion Dollar API Authorization Blindspot", "What It Is Solving (Problem Statement)", 2)

    # Big Alert Banner
    add_card(slide, Inches(0.8), Inches(1.7), Inches(11.733), Inches(0.9), COLOR_CARD_ELEV, COLOR_RED, Pt(2))
    alert_tb = slide.shapes.add_textbox(Inches(1.0), Inches(1.78), Inches(11.333), Inches(0.7))
    atf = alert_tb.text_frame
    atf.word_wrap = True
    ap = atf.paragraphs[0]
    ap.text = "⚠️ OWASP API Security #1 Threat (API1:2023): Over 40% of cloud API breaches stem from Broken Object Level Authorization (BOLA/IDOR) — yet 99% of automated security scanners cannot detect it."
    ap.font.name = FONT_HEADING
    ap.font.size = Pt(13)
    ap.font.bold = True
    ap.font.color.rgb = COLOR_WHITE

    # 3 Large Pillars
    threats = [
        ("THE CORE FLAW", COLOR_RED, "Changing id=101 to id=102",
         "An authenticated user simply changes an ID parameter in an API request and directly reads, modifies, or deletes another customer's private invoices, patient medical charts, or banking records."),
        
        ("TRADITIONAL TOOLS FAIL", COLOR_ORANGE, "DAST & SAST Are Blind to Auth",
         "Conventional scanners only test for syntax injection like SQLi or XSS. Operating in single-user isolation, they have zero understanding of multi-tenant ownership, role privileges, or cross-account access boundaries."),
        
        ("SILENT EXPLOITATION", COLOR_AMBER, "Flaws Evade Firewalls & WAFs",
         "Because BOLA requests use valid JWT tokens and legitimate JSON formats, target APIs respond with standard 200 OK payloads. WAFs see completely normal traffic, leaving breaches undetected for months.")
    ]

    for i, (tag, color, headline, body) in enumerate(threats):
        c_left = Inches(0.8 + i * 4.0)
        c_top = Inches(2.8)
        c_w = Inches(3.733)
        c_h = Inches(3.9)

        add_card(slide, c_left, c_top, c_w, c_h, COLOR_CARD_BG, color, Pt(2))

        tb = slide.shapes.add_textbox(c_left + Inches(0.25), c_top + Inches(0.25), c_w - Inches(0.5), c_h - Inches(0.5))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = tag
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(12)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(4)

        p1 = tf.add_paragraph()
        p1.text = headline
        p1.font.name = FONT_HEADING
        p1.font.size = Pt(18)
        p1.font.bold = True
        p1.font.color.rgb = COLOR_WHITE
        p1.space_after = Pt(14)

        p2 = tf.add_paragraph()
        p2.text = body
        p2.font.name = FONT_BODY
        p2.font.size = Pt(13)
        p2.font.color.rgb = COLOR_TEXT_MUTED


# ── Slide 3: Proposed Solution ───────────────────────────────────────────────
def build_slide_3_solution(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "The 4-Step Autonomous Differential Security Pipeline", "How It Is Solving It (Proposed Solution)", 3)

    steps = [
        ("STEP 1", COLOR_CYAN, "Spec Ingestion & Mapping",
         "Ingests OpenAPI 3.x contracts from URLs or files. Validates schemas, dereferences circular $ref pointers, and prioritizes endpoints by state-changing methods and authorization requirements."),
        
        ("STEP 2", COLOR_EMERALD, "Ownership Discovery",
         "Authenticates multiple distinct personas (userA, userB, admin). Automatically queries legitimate profile & collection endpoints to discover owned resources without guessing IDs."),
        
        ("STEP 3", COLOR_INDIGO, "Differential Analysis",
         "Compiles a ground-truth Allow/Deny expectation matrix. Dispatches rate-limited cross-user probes and mathematically measures response divergence using weighted Jaccard distance and schema shifts."),
        
        ("STEP 4", COLOR_RED, "Empirical Proof & cURL",
         "Actively re-probes live findings to prove reproducibility (boosting confidence to 100%). Generates copy-paste shell-safe cURL PoCs with masked $TOKEN placeholders for instant remediation.")
    ]

    for i, (tag, color, headline, desc) in enumerate(steps):
        c_left = Inches(0.8 + i * 2.983)
        c_top = Inches(1.8)
        c_w = Inches(2.783)
        c_h = Inches(4.2)

        add_card(slide, c_left, c_top, c_w, c_h, COLOR_CARD_BG, color, Pt(2))

        tb = slide.shapes.add_textbox(c_left + Inches(0.2), c_top + Inches(0.2), c_w - Inches(0.4), c_h - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = tag
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(12)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(6)

        p1 = tf.add_paragraph()
        p1.text = headline
        p1.font.name = FONT_HEADING
        p1.font.size = Pt(17)
        p1.font.bold = True
        p1.font.color.rgb = COLOR_WHITE
        p1.space_after = Pt(12)

        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.name = FONT_BODY
        p2.font.size = Pt(12)
        p2.font.color.rgb = COLOR_TEXT_MUTED

    # Bottom summary
    add_card(slide, Inches(0.8), Inches(6.2), Inches(11.733), Inches(0.6), COLOR_CARD_ELEV, COLOR_CYAN, Pt(1))
    sum_tb = slide.shapes.add_textbox(Inches(1.0), Inches(6.25), Inches(11.333), Inches(0.5))
    stf = sum_tb.text_frame
    sp = stf.paragraphs[0]
    sp.text = "Core Advantage: Entirely autonomous from spec to PoC. No manual test scripting, no synthetic dummy payloads, and zero secrets leaked."
    sp.font.name = FONT_HEADING
    sp.font.size = Pt(11)
    sp.font.bold = True
    sp.font.color.rgb = COLOR_WHITE


# ── Slide 4: Unique Differentiator vs 200 Teams ──────────────────────────────
def build_slide_4_unique(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "Why SentinelAPI Wins: Standing Out Against 200 Teams", "What Is Unique About This", 4)

    # Comparison Table
    add_card(slide, Inches(0.8), Inches(1.7), Inches(11.733), Inches(5.0), COLOR_CARD_BG, COLOR_BORDER, Pt(1.5))

    rows_data = [
        ("EVALUATION CRITERIA", "TYPICAL HACKATHON TEAMS (200 TEAMS)", "SENTINELAPI (OUR SOLUTION)"),
        ("Vulnerability Focus", "Generic SQLi, XSS, or syntax input fuzzing", "Complex Multi-User Authorization (BOLA, BFLA, Data Exposure)"),
        ("Detection Engine", "Asks an LLM 'is this vulnerable?' (Hallucinations & Flaky)", "100% Deterministic Differential Engine (Weighted Jaccard Distance)"),
        ("Ownership Knowledge", "Random ID guessing or hardcoded IDs in test scripts", "Autonomous Resource Ownership Discovery from Legitimate APIs"),
        ("Accuracy & Evidence", "Vague warnings with high false positive rates", "Empirically Proven Live Reproduction + Copy-Paste cURL PoCs"),
        ("Safety & Egress", "Unrestricted flood requests; sends raw tokens to AI", "Scope Guard, 20 RPS Rate Cap, Budget Cap, Zero Egress PII Guard"),
        ("Production Readiness", "Mock scripts or static Figma UI concept", "FastAPI Backend + React 19 HUD + Headless CI Gate + Docker Stack")
    ]

    for i, (col1, col2, col3) in enumerate(rows_data):
        y_pos = Inches(1.85 + i * 0.65)
        # Background bar for header
        if i == 0:
            hdr_bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.9), y_pos - Inches(0.05), Inches(11.533), Inches(0.45))
            hdr_bg.fill.solid()
            hdr_bg.fill.fore_color.rgb = COLOR_CARD_ELEV
            hdr_bg.line.width = Pt(0)

        tb1 = slide.shapes.add_textbox(Inches(1.0), y_pos, Inches(2.6), Inches(0.55))
        tf1 = tb1.text_frame
        p1 = tf1.paragraphs[0]
        p1.text = col1
        p1.font.name = FONT_HEADING
        p1.font.size = Pt(11)
        p1.font.bold = True
        p1.font.color.rgb = COLOR_WHITE if i > 0 else COLOR_CYAN

        tb2 = slide.shapes.add_textbox(Inches(3.8), y_pos, Inches(4.3), Inches(0.55))
        tf2 = tb2.text_frame
        p2 = tf2.paragraphs[0]
        p2.text = col2
        p2.font.name = FONT_BODY
        p2.font.size = Pt(11)
        p2.font.bold = (i == 0)
        p2.font.color.rgb = COLOR_TEXT_MUTED if i > 0 else COLOR_RED

        tb3 = slide.shapes.add_textbox(Inches(8.3), y_pos, Inches(4.1), Inches(0.55))
        tf3 = tb3.text_frame
        p3 = tf3.paragraphs[0]
        p3.text = col3
        p3.font.name = FONT_BODY
        p3.font.size = Pt(11)
        p3.font.bold = True
        p3.font.color.rgb = COLOR_CYAN if i > 0 else COLOR_EMERALD


# ── Slide 5: Key Features & Proprietary Security Engine ──────────────────────
def build_slide_5_core_engine(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "The Core Security Engine: 6 Proprietary Deep-Tech Engines", "Key Features (Proprietary IP)", 5)

    engines = [
        ("ENGINE 1", COLOR_CYAN, "Attack Surface Mapper",
         "Parses OpenAPI 3.x specifications with circular $ref resolution. Extracts query/path parameters and scores initial endpoint risk based on state-changing methods."),
        
        ("ENGINE 2", COLOR_EMERALD, "Identity & HTTP Executor",
         "Multi-persona JWT session manager enforcing 20 RPS token-bucket rate limits, 1,000 req budgets, and strict host allowlists (assert_in_scope)."),
        
        ("ENGINE 3", COLOR_INDIGO, "Matrix Compiler",
         "Discovers legitimate resource ownership per user and compiles a mathematical Allow/Deny expectation matrix for every endpoint and object ID."),
        
        ("ENGINE 4", COLOR_AMBER, "Differential Analyzer",
         "Computes weighted Jaccard payload similarity, HTTP status divergence, and detects leaked sensitive PII fields outside the documented schema."),
        
        ("ENGINE 5", COLOR_RED, "6 Security Checks",
         "Dedicated detection suites for BOLA/IDOR (API1), Broken Auth (API2), Data Exposure (API3), Rate Limiting (API4), BFLA Privileges (API5), and Input Anomalies (API8)."),
        
        ("ENGINE 6", COLOR_PURPLE, "Explainable Risk Scorer",
         "Replaces CVSS guesswork with a 4-part score: Impact (40) + Exploitability (25) + Sensitivity (30) + Evidence (15) with live empirical reproduction.")
    ]

    for idx, (tag, color, title, desc) in enumerate(engines):
        col = idx % 3
        row = idx // 3
        c_left = Inches(0.8 + col * 4.0)
        c_top = Inches(1.8 + row * 2.5)
        c_w = Inches(3.733)
        c_h = Inches(2.25)

        add_card(slide, c_left, c_top, c_w, c_h, COLOR_CARD_BG, color, Pt(2))

        tb = slide.shapes.add_textbox(c_left + Inches(0.2), c_top + Inches(0.18), c_w - Inches(0.4), c_h - Inches(0.36))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = f"{tag} · {title}"
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(13)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(8)

        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = FONT_BODY
        p1.font.size = Pt(11)
        p1.font.color.rgb = COLOR_TEXT_MUTED


# ── Slide 6: System Architecture ─────────────────────────────────────────────
def build_slide_6_architecture(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "Decoupled Architecture & Enforced Safety Boundaries", "System Architecture", 6)

    arch_png = DOCS_DIR / "architecture.png"
    if arch_png.exists():
        img_left = Inches(0.8)
        img_top = Inches(1.65)
        img_w = Inches(11.733)
        img_h = Inches(4.45)
        add_card(slide, img_left - Inches(0.03), img_top - Inches(0.03), img_w + Inches(0.06), img_h + Inches(0.06), COLOR_CANVAS_BASE, COLOR_BORDER, Pt(1))
        slide.shapes.add_picture(str(arch_png), img_left, img_top, img_w, img_h)

    # Invariant Caption
    add_card(slide, Inches(0.8), Inches(6.25), Inches(11.733), Inches(0.55), COLOR_CARD_ELEV, COLOR_CYAN, Pt(1.5))
    cap_tb = slide.shapes.add_textbox(Inches(1.0), Inches(6.3), Inches(11.333), Inches(0.45))
    ctf = cap_tb.text_frame
    cp = ctf.paragraphs[0]
    cp.text = "Core Safety Invariant: The deterministic security engine runs 100% offline. Zero credentials or tokens are ever persisted or exposed. The AI Analyst is strictly an evidence-only side-branch with zero raw data egress."
    cp.font.name = FONT_HEADING
    cp.font.size = Pt(10)
    cp.font.bold = True
    cp.font.color.rgb = COLOR_WHITE


# ── Slide 7: Shift-Left CI/CD Quality Gate ───────────────────────────────────
def build_slide_7_ci_cd(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "Shift-Left Automated Security Quality Gate for CI/CD", "Key Features (DevSecOps Integration)", 7)

    features = [
        ("HEADLESS CI GATE CLI", COLOR_CYAN, "Fails Builds on Violations",
         "Integrates directly into GitHub Actions or GitLab CI. Breaks pull request builds with exit code 1 when CRITICAL or HIGH authorization vulnerabilities are detected."),
        
        ("SARIF CODE SCANNING", COLOR_EMERALD, "Native GitHub Security Alerts",
         "Exports deterministic SARIF, Markdown, and JSON audit reports. Findings appear directly inside GitHub PR code review diffs with line-level remediation hints."),
        
        ("HERMETIC TEST SANDBOX", COLOR_INDIGO, "Verified Zero-Trust Baseline",
         "Ships with realistic vulnerable sandboxes (Retail Store, Healthcare, FinTech). When SECURE_MODE=true is enabled, SentinelAPI verifies 100% controls pass.")
    ]

    for i, (tag, color, headline, desc) in enumerate(features):
        c_left = Inches(0.8 + i * 4.0)
        c_top = Inches(1.8)
        c_w = Inches(3.733)
        c_h = Inches(2.6)

        add_card(slide, c_left, c_top, c_w, c_h, COLOR_CARD_BG, color, Pt(2))

        tb = slide.shapes.add_textbox(c_left + Inches(0.2), c_top + Inches(0.18), c_w - Inches(0.4), c_h - Inches(0.36))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = tag
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(11)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(4)

        p1 = tf.add_paragraph()
        p1.text = headline
        p1.font.name = FONT_HEADING
        p1.font.size = Pt(17)
        p1.font.bold = True
        p1.font.color.rgb = COLOR_WHITE
        p1.space_after = Pt(10)

        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.name = FONT_BODY
        p2.font.size = Pt(11)
        p2.font.color.rgb = COLOR_TEXT_MUTED

    # Real CI Command Card
    add_card(slide, Inches(0.8), Inches(4.7), Inches(11.733), Inches(2.0), COLOR_CARD_ELEV, COLOR_CYAN, Pt(1.5))
    code_tb = slide.shapes.add_textbox(Inches(1.1), Inches(4.85), Inches(11.133), Inches(1.7))
    ctf = code_tb.text_frame
    ctf.word_wrap = True

    cp0 = ctf.paragraphs[0]
    cp0.text = "GITHUB ACTIONS WORKFLOW INTEGRATION (.github/workflows/ci.yml):"
    cp0.font.name = FONT_HEADING
    cp0.font.size = Pt(11)
    cp0.font.bold = True
    cp0.font.color.rgb = COLOR_CYAN
    cp0.space_after = Pt(6)

    cp1 = ctf.add_paragraph()
    cp1.text = "# 1. Trigger automated security scan against PR environment\npython -m app.cli scan --spec http://api:8000/openapi.json --base-url http://api:8000 --json-out findings.json\n\n# 2. Enforce quality gate (fails build on CRITICAL / HIGH findings with confidence >= 0.70)\npython scripts/ci_gate.py --findings findings.json --fail-on CRITICAL,HIGH --min-confidence 0.70"
    cp1.font.name = FONT_CODE
    cp1.font.size = Pt(11)
    cp1.font.color.rgb = COLOR_WHITE


# ── Slide 8: Demo Screenshots & Prototype ────────────────────────────────────
def build_slide_8_screenshots(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "Live Tactical Dashboard & Mathematical Differential Inspector", "Demo Screenshots (Working Prototype)", 8)

    img1_path = SCREENSHOTS_DIR / "triage-workspace.png"
    img2_path = SCREENSHOTS_DIR / "finding-inspector.png"

    card_w = Inches(5.766)
    card_h = Inches(4.4)
    top_y = Inches(1.7)

    # Frame 1: Triage Workspace
    add_card(slide, Inches(0.8), top_y, card_w, card_h, COLOR_CARD_BG, COLOR_BORDER, Pt(1.5))
    if img1_path.exists():
        slide.shapes.add_picture(str(img1_path), Inches(0.9), top_y + Inches(0.1), card_w - Inches(0.2), Inches(3.3))
    
    tb1 = slide.shapes.add_textbox(Inches(0.9), top_y + Inches(3.45), card_w - Inches(0.2), Inches(0.85))
    tf1 = tb1.text_frame
    tf1.word_wrap = True
    p1 = tf1.paragraphs[0]
    p1.text = "Results Triage Workspace: Real-Time Stream"
    p1.font.name = FONT_HEADING
    p1.font.size = Pt(13)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_CYAN
    p1_sub = tf1.add_paragraph()
    p1_sub.text = "Live telemetry HUD with verified control counts, severity badges, and one-click filtering across OWASP categories, status codes, and paths."
    p1_sub.font.name = FONT_BODY
    p1_sub.font.size = Pt(10)
    p1_sub.font.color.rgb = COLOR_TEXT_MUTED

    # Frame 2: Finding Inspector
    add_card(slide, Inches(6.766), top_y, card_w, card_h, COLOR_CARD_BG, COLOR_BORDER, Pt(1.5))
    if img2_path.exists():
        slide.shapes.add_picture(str(img2_path), Inches(6.866), top_y + Inches(0.1), card_w - Inches(0.2), Inches(3.3))
    
    tb2 = slide.shapes.add_textbox(Inches(6.866), top_y + Inches(3.45), card_w - Inches(0.2), Inches(0.85))
    tf2 = tb2.text_frame
    tf2.word_wrap = True
    p2 = tf2.paragraphs[0]
    p2.text = "Differential Inspector: Side-by-Side Proof"
    p2.font.name = FONT_HEADING
    p2.font.size = Pt(13)
    p2.font.bold = True
    p2.font.color.rgb = COLOR_RED
    p2_sub = tf2.add_paragraph()
    p2_sub.text = "Side-by-side baseline vs attack diff showing BOLA breach (200 OK vs 403), leaked PII fields, 4-factor risk breakdown, and copy-paste cURL PoC."
    p2_sub.font.name = FONT_BODY
    p2_sub.font.size = Pt(10)
    p2_sub.font.color.rgb = COLOR_TEXT_MUTED

    # Bottom summary callout
    add_card(slide, Inches(0.8), Inches(6.25), Inches(11.733), Inches(0.55), COLOR_CARD_ELEV, COLOR_EMERALD, Pt(1.5))
    sum_tb = slide.shapes.add_textbox(Inches(1.0), Inches(6.3), Inches(11.333), Inches(0.45))
    stf = sum_tb.text_frame
    sp = stf.paragraphs[0]
    sp.text = "Empirical Evidence: Zero guesswork. Developers receive exact response diffs, 100% verified reproduction badges, and copy-paste shell commands."
    sp.font.name = FONT_HEADING
    sp.font.size = Pt(11)
    sp.font.bold = True
    sp.font.color.rgb = COLOR_WHITE


# ── Slide 9: Future Scope & SaaS Roadmap ─────────────────────────────────────
def build_slide_9_future_roadmap(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "Beyond the Hackathon: Path to an Enterprise SaaS Platform", "Future Scope (Commercial Roadmap)", 9)

    pillars = [
        ("PHASE A · COMMERCIAL SAAS", COLOR_CYAN, "Open-Source CLI + Paid Cloud Dashboard",
         "Maintain open-source CLI runner for individual developers and CI gates. Commercialize a hosted, multi-tenant SaaS dashboard for engineering organizations with centralized RBAC, historical risk trending, team collaboration, and vulnerability triage workflows."),
        
        ("PHASE B · ENTERPRISE AUTH", COLOR_EMERALD, "Enterprise OAuth2 & SSO Negotiation",
         "Extend beyond static JWTs to automated OAuth2 / OIDC PKCE flow negotiation, SAML handshakes, and mTLS client-certificate authentication for complex enterprise banking, fintech, and healthcare environments."),
        
        ("PHASE C · COMPLIANCE MAPPINGS", COLOR_AMBER, "Custom Regulatory Policy Engines",
         "Provide declarative YAML policy mappings translating authorization findings directly into HIPAA, PCI-DSS, SOC 2, and ISO 27001 audit deliverables with automated executive PDF sign-off reports."),
        
        ("PHASE D · DISTRIBUTED MESH", COLOR_PURPLE, "Distributed Scanner Mesh & Persistence",
         "Deploy distributed Kubernetes scanner workers capable of concurrently auditing large microservice meshes, backed by MongoDB and PostgreSQL persistence adapters for multi-year enterprise audit archiving.")
    ]

    for idx, (tag, color, title, desc) in enumerate(pillars):
        col = idx % 2
        row = idx // 2
        c_left = Inches(0.8 + col * 5.966)
        c_top = Inches(1.8 + row * 2.45)
        c_w = Inches(5.766)
        c_h = Inches(2.25)

        add_card(slide, c_left, c_top, c_w, c_h, COLOR_CARD_BG, color, Pt(2))

        tb = slide.shapes.add_textbox(c_left + Inches(0.25), c_top + Inches(0.2), c_w - Inches(0.5), c_h - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = tag
        p0.font.name = FONT_HEADING
        p0.font.size = Pt(11)
        p0.font.bold = True
        p0.font.color.rgb = color
        p0.space_after = Pt(2)

        p1 = tf.add_paragraph()
        p1.text = title
        p1.font.name = FONT_HEADING
        p1.font.size = Pt(16)
        p1.font.bold = True
        p1.font.color.rgb = COLOR_WHITE
        p1.space_after = Pt(8)

        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.name = FONT_BODY
        p2.font.size = Pt(11.5)
        p2.font.color.rgb = COLOR_TEXT_MUTED


# ── Slide 10: Team, Summary & Live Demo ──────────────────────────────────────
def build_slide_10_team(prs):
    slide = create_blank_slide(prs)
    add_header(slide, "Team & Project Summary — Questions & Live Demo", "Conclusion & Q&A", 10)

    # Left: Team Ownership
    left_x = Inches(0.8)
    col_w = Inches(5.766)
    add_card(slide, left_x, Inches(1.8), col_w, Inches(4.9), COLOR_CARD_BG, COLOR_CYAN, Pt(2))

    tb_left = slide.shapes.add_textbox(left_x + Inches(0.3), Inches(2.0), col_w - Inches(0.6), Inches(4.5))
    tfl = tb_left.text_frame
    tfl.word_wrap = True

    p_th = tfl.paragraphs[0]
    p_th.text = "CORE TEAM & ARCHITECTURAL CONTRIBUTIONS"
    p_th.font.name = FONT_HEADING
    p_th.font.size = Pt(14)
    p_th.font.bold = True
    p_th.font.color.rgb = COLOR_CYAN
    p_th.space_after = Pt(6)

    p_lead = tfl.add_paragraph()
    p_lead.text = "Tanuj — Lead Security Architect & Full-Stack Engineer"
    p_lead.font.name = FONT_HEADING
    p_lead.font.size = Pt(13)
    p_lead.font.bold = True
    p_lead.font.color.rgb = COLOR_WHITE
    p_lead.space_after = Pt(12)

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
        pc.font.size = Pt(11)
        pc.font.color.rgb = COLOR_TEXT_MUTED
        pc.space_after = Pt(6)

    # Right: Summary & Links
    right_x = Inches(6.766)
    add_card(slide, right_x, Inches(1.8), col_w, Inches(4.9), COLOR_CARD_BG, COLOR_INDIGO, Pt(2))

    tb_right = slide.shapes.add_textbox(right_x + Inches(0.3), Inches(2.0), col_w - Inches(0.6), Inches(4.5))
    tfr = tb_right.text_frame
    tfr.word_wrap = True

    p_qh = tfr.paragraphs[0]
    p_qh.text = "PROJECT SUMMARY & LIVE ACCESS"
    p_qh.font.name = FONT_HEADING
    p_qh.font.size = Pt(14)
    p_qh.font.bold = True
    p_qh.font.color.rgb = COLOR_INDIGO
    p_qh.space_after = Pt(10)

    p_quote = tfr.add_paragraph()
    p_quote.text = "“SentinelAPI stops API authorization breaches before code hits production — fully autonomous, mathematically verified, with reproducible evidence and zero secrets leaked.”"
    p_quote.font.name = FONT_HEADING
    p_quote.font.size = Pt(13)
    p_quote.font.bold = True
    p_quote.font.color.rgb = COLOR_WHITE
    p_quote.space_after = Pt(16)

    links = [
        ("GitHub Repository", "https://github.com/x03tanuj/sentinel-api"),
        ("Live Web Dashboard", "http://localhost:8080"),
        ("Automated Demo Script", "bash scripts/demo.sh"),
        ("Architecture Diagram", "docs/architecture.png (2400×1400)")
    ]
    for label, val in links:
        pl = tfr.add_paragraph()
        pl.text = f"{label}: "
        pl.font.name = FONT_HEADING
        pl.font.size = Pt(11)
        pl.font.bold = True
        pl.font.color.rgb = COLOR_CYAN
        
        run = pl.add_run()
        run.text = val
        run.font.name = FONT_CODE
        run.font.bold = False
        run.font.color.rgb = COLOR_WHITE
        pl.space_after = Pt(6)

    p_ask = tfr.add_paragraph()
    p_ask.text = "\nThank You! We are now open for Q&A and Live Demo."
    p_ask.font.name = FONT_HEADING
    p_ask.font.size = Pt(15)
    p_ask.font.bold = True
    p_ask.font.color.rgb = COLOR_EMERALD


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    SLIDES_DIR.mkdir(parents=True, exist_ok=True)
    print("Generating PPTX pitch deck matching Section 6.2 deliverables...")
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    build_slide_1_cover(prs)
    build_slide_2_problem(prs)
    build_slide_3_solution(prs)
    build_slide_4_unique(prs)
    build_slide_5_core_engine(prs)
    build_slide_6_architecture(prs)
    build_slide_7_ci_cd(prs)
    build_slide_8_screenshots(prs)
    build_slide_9_future_roadmap(prs)
    build_slide_10_team(prs)

    prs.save(str(OUTPUT_PPTX))
    print(f"✅ Generated {len(prs.slides)} slides in {OUTPUT_PPTX}")


if __name__ == "__main__":
    main()
