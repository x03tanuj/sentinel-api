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

  // 1. Export PDF
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

  // 2. Previews of key requested slides
  const slidesToCapture = [1, 2, 3, 4, 8];
  for (const num of slidesToCapture) {
    const pPath = path.resolve(__dirname, `../slides/preview_slide_${num}.png`);
    const loc = page.locator(`#slide-${num}`);
    await loc.screenshot({ path: pPath });
    console.log(`📸 Preview captured: ${pPath}`);
  }

  await browser.close();
  console.log('Export complete.');
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
