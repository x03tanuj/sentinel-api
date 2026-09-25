/**
 * SentinelAPI — Pitch Deck PDF & Slide Preview Generator
 *
 * Uses Playwright to render scripts/deck_slides.html into:
 *   1. slides/SentinelAPI_Pitch.pdf (multi-page 16:9 widescreen PDF)
 *   2. slides/preview_slide_1.png (Title & Pitch)
 *   3. slides/preview_slide_4.png (System Architecture)
 *   4. slides/preview_slide_7.png (Live Product Demo)
 */

const path = require('path');
const fs = require('fs');

const frontendModules = path.resolve(__dirname, '../frontend/node_modules');
if (fs.existsSync(frontendModules)) {
  module.paths.push(frontendModules);
}

const { chromium } = require('@playwright/test');

async function main() {
  const htmlPath = path.resolve(__dirname, 'deck_slides.html');
  if (!fs.existsSync(htmlPath)) {
    throw new Error(`Template not found: ${htmlPath}`);
  }

  console.log('Launching headless browser...');
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();

  console.log(`Loading slides: file://${htmlPath}`);
  await page.goto(`file://${htmlPath}`);
  await page.waitForLoadState('networkidle');

  // Ensure fonts and images are completely loaded
  await page.evaluate(async () => {
    await document.fonts.ready;
    const images = Array.from(document.querySelectorAll('img'));
    await Promise.all(
      images.map((img) => {
        if (img.complete) return Promise.resolve();
        return new Promise((resolve) => {
          img.onload = img.onerror = resolve;
        });
      })
    );
  });

  await page.waitForTimeout(1000);

  // 1. Export Multi-Page Widescreen 16:9 PDF
  const pdfPath = path.resolve(__dirname, '../slides/SentinelAPI_Pitch.pdf');
  console.log('Rendering 16:9 widescreen PDF...');
  await page.pdf({
    path: pdfPath,
    width: '1920px',
    height: '1080px',
    printBackground: true,
    margin: { top: '0px', right: '0px', bottom: '0px', left: '0px' },
  });
  console.log(`✅ PDF successfully generated: ${pdfPath}`);

  // 2. Capture preview screenshots of key slides for visual inspection
  const preview1 = path.resolve(__dirname, '../slides/preview_slide_1.png');
  const preview4 = path.resolve(__dirname, '../slides/preview_slide_4.png');
  const preview7 = path.resolve(__dirname, '../slides/preview_slide_7.png');

  const s1 = page.locator('#slide-1');
  await s1.screenshot({ path: preview1 });
  console.log(`📸 Preview captured: ${preview1}`);

  const s4 = page.locator('#slide-4');
  await s4.screenshot({ path: preview4 });
  console.log(`📸 Preview captured: ${preview4}`);

  const s7 = page.locator('#slide-7');
  await s7.screenshot({ path: preview7 });
  console.log(`📸 Preview captured: ${preview7}`);

  await browser.close();
  console.log('Export complete.');
}

main().catch((err) => {
  console.error('Error generating pitch deck PDF/previews:', err);
  process.exit(1);
});
