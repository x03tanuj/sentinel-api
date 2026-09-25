/**
 * SentinelAPI — Flowchart PDF Generator
 *
 * Renders scripts/flowchart_pdf.html via Playwright and exports
 * docs/architecture_flowchart.pdf  (A3 landscape, print-ready).
 *
 * Usage:  node scripts/generate_flowchart_pdf.js
 */

const path = require('path');
const fs   = require('fs');

// ── Resolve Playwright from frontend node_modules ──────────────
const frontendModules = path.resolve(__dirname, '../frontend/node_modules');
if (fs.existsSync(frontendModules)) {
  module.paths.push(frontendModules);
}

const { chromium } = require('@playwright/test');

async function main() {
  const htmlPath = path.resolve(__dirname, 'flowchart_pdf.html');
  if (!fs.existsSync(htmlPath)) {
    throw new Error(`HTML template not found: ${htmlPath}`);
  }

  console.log('Launching Chromium...');
  const browser = await chromium.launch();
  const page    = await browser.newPage();

  // A3 landscape: 1587 × 1123 px  (at 96 dpi, 420 × 297 mm)
  await page.setViewportSize({ width: 1587, height: 1123 });

  console.log(`Loading: ${htmlPath}`);
  await page.goto(`file://${htmlPath}`);
  await page.waitForLoadState('networkidle');

  // Wait for web fonts
  await page.evaluate(async () => { await document.fonts.ready; });
  // Extra settle time for layout
  await page.waitForTimeout(800);

  const outputPath = path.resolve(__dirname, '../docs/architecture_flowchart.pdf');

  await page.pdf({
    path:        outputPath,
    format:      'A3',
    landscape:   true,
    printBackground: true,
    margin:      { top: '0', right: '0', bottom: '0', left: '0' },
  });

  console.log(`✅  PDF saved: ${outputPath}`);
  await browser.close();
}

main().catch(err => {
  console.error('PDF generation failed:', err);
  process.exit(1);
});
