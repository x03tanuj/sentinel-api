/**
 * SentinelAPI Architecture Diagram Generator
 * 
 * Uses Playwright to render scripts/architecture_diagram.html into docs/architecture.png
 * at 2400x1400 high resolution for slide decks, README, and presentation deliverables.
 */

const path = require('path');
const fs = require('fs');

// Ensure frontend/node_modules is in search path
const frontendModules = path.resolve(__dirname, '../frontend/node_modules');
if (fs.existsSync(frontendModules)) {
  module.paths.push(frontendModules);
}

const { chromium } = require('@playwright/test');

async function main() {
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 2400, height: 1400 },
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();

  const htmlPath = path.resolve(__dirname, 'architecture_diagram.html');
  if (!fs.existsSync(htmlPath)) {
    throw new Error(`HTML template not found at: ${htmlPath}`);
  }

  console.log(`Loading diagram template: ${htmlPath}`);
  await page.goto(`file://${htmlPath}`);
  await page.waitForLoadState('networkidle');

  // Ensure web fonts (Inter, JetBrains Mono) are completely rendered
  await page.evaluate(async () => {
    await document.fonts.ready;
  });

  const outputPath = path.resolve(__dirname, '../docs/architecture.png');
  await page.screenshot({ path: outputPath, fullPage: false });

  console.log(`Successfully generated high-resolution diagram: ${outputPath}`);
  await browser.close();
}

main().catch((err) => {
  console.error('Error generating architecture diagram:', err);
  process.exit(1);
});
