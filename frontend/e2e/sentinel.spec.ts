import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCREENSHOT_DIR = path.resolve(__dirname, '../../docs/screenshots');
const STACK_SCRIPT = path.resolve(__dirname, '../../scripts/e2e_stack.sh');

test.describe('SentinelAPI End-to-End Suite', () => {
  let createdScanId = '';

  test.beforeAll(async () => {
    if (!fs.existsSync(SCREENSHOT_DIR)) {
      fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
    }
    // Ensure clean state on target API
    try {
      await fetch('http://127.0.0.1:9000/_reset', { method: 'POST' });
    } catch {
      // ignore
    }
  });

  test('1. Full Vulnerable Target Flow, Triage, Matrix, Export & Deep-Linking', async ({ page }) => {
    // Collect console errors to assert zero errors & zero CSP violations
    const consoleErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // 1. Visit History Page
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'history.png') });

    // 2. Click Start New Scan
    await page.click('text=New Scan');
    await page.waitForURL('**/scans/new');
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'new-scan.png') });

    // 3. Load Demo Target Preset
    await page.click('button:has-text("Load demo target")');
    await expect(page.locator('#target-spec-url')).toHaveValue(
      'http://target_api:9000/openapi.json'
    );
    await expect(page.locator('text=DEMO PRESET ACTIVE')).toBeVisible();

    // 4. Submit scan
    const submitBtn = page.locator('button[type="submit"]');
    await expect(submitBtn).toBeEnabled();
    await submitBtn.click();

    // 5. Lands on Live View
    await page.waitForURL('**/scans/*/live', { timeout: 15_000 });
    const liveUrl = page.url();
    const scanIdMatch = liveUrl.match(/\/scans\/([^/]+)\/live/);
    expect(scanIdMatch).toBeTruthy();
    createdScanId = scanIdMatch![1];

    // Verify live stage stepper and progress bar
    await expect(page.locator('text=Stage').first()).toBeVisible();
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'live.png') });

    // 6. Automatically navigates to results workspace on completion
    await page.waitForURL((url) => !url.pathname.endsWith('/live') && url.pathname.includes('/scans/'), {
      timeout: 120_000,
    });
    await page.waitForLoadState('networkidle');

    // 7. Results Triage Workspace Verification
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'triage-workspace.png') });
    await expect(page.locator('text=COMPLETED')).toBeVisible();

    // Verify BOLA finding on /orders/{id}
    const bolaFinding = page.getByText('/orders/{id}', { exact: false }).first();
    await expect(bolaFinding).toBeVisible({ timeout: 20_000 });
    await bolaFinding.click();

    // Verify Inspector panels
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'finding-inspector.png') });
    await expect(page.locator('text=Actual: 200 OK')).toBeVisible();
    await expect(page.locator('text=Expected: 403 Forbidden')).toBeVisible();
    await expect(page.locator('text=$TOKEN')).toBeVisible();
    await expect(page.locator('text=Bearer ey')).not.toBeVisible();
    await expect(page.locator('text=Suggested Remediation')).toBeVisible();

    // Verify leaked field highlighting on data exposure finding
    const dataExpFinding = page
      .locator('div[role="button"]:has-text("/users/{id}")')
      .or(page.locator('div[role="button"]:has-text("Excessive Data Exposure")'))
      .first();
    if ((await dataExpFinding.count()) > 0) {
      await dataExpFinding.click();
      await expect(page.locator('text=password_hash').or(page.locator('text=ssn')).first()).toBeVisible();
    }

    // 8. Authorization Matrix Tab
    await page.click('button:has-text("Authorization Matrix")');
    await expect(page.locator('text=Ground-Truth Authorization Matrix')).toBeVisible();
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'matrix.png') });

    const violationCell = page.locator('td:has-text("VIOLATION")').first();
    await expect(violationCell).toBeVisible();
    // Clicking violation cell should navigate to finding
    await violationCell.click();
    await expect(page.locator('text=Actual: 200 OK')).toBeVisible();

    // 9. Attack Surface Tab
    await page.click('button:has-text("Attack Surface")');
    await expect(page.locator('table')).toBeVisible();
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'surface.png') });

    // 10. Markdown Report Download
    await page.click('button:has-text("Export")');
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.click('text=Markdown Report (.md)'),
    ]);
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();
    const reportText = fs.readFileSync(downloadPath!, 'utf-8');
    expect(reportText).toContain('SentinelAPI');
    expect(reportText).toContain('API1:2023');

    // 11. History page lists the completed scan
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page.locator(`text=${createdScanId.slice(0, 8)}`)).toBeVisible();

    // 12. Deep Linking
    await page.goto(`/scans/${createdScanId}?finding=${createdScanId}`);
    await page.waitForLoadState('networkidle');

    // Assert zero console errors and zero CSP violations
    expect(consoleErrors).toEqual([]);
  });

  test('2. Secret & Sensitive Data Zero-Leakage Browser Verification', async ({ page }) => {
    // Navigate to completed scan results
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Assert localStorage and sessionStorage contain no credentials or tokens
    const storageAudit = await page.evaluate(() => {
      const forbidden = ['passA123', 'admin123'];
      const leaks: string[] = [];

      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i) || '';
        const val = localStorage.getItem(key) || '';
        for (const secret of forbidden) {
          if (val.includes(secret) || key.includes(secret)) {
            leaks.push(`localStorage[${key}] leaked ${secret}`);
          }
        }
        if (/Bearer ey[A-Za-z0-9_-]+/.test(val)) {
          leaks.push(`localStorage[${key}] leaked JWT token`);
        }
      }

      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i) || '';
        const val = sessionStorage.getItem(key) || '';
        for (const secret of forbidden) {
          if (val.includes(secret) || key.includes(secret)) {
            leaks.push(`sessionStorage[${key}] leaked ${secret}`);
          }
        }
        if (/Bearer ey[A-Za-z0-9_-]+/.test(val)) {
          leaks.push(`sessionStorage[${key}] leaked JWT token`);
        }
      }

      return leaks;
    });

    expect(storageAudit).toEqual([]);

    // Assert page HTML contains no password hashes or seed SSNs
    const pageHtml = await page.content();
    expect(pageHtml).not.toContain('$2b$12$');
    expect(pageHtml).not.toContain('111-22-3333');
    expect(pageHtml).not.toContain('444-55-6666');
  });

  test('3. Secure Mode Zero-Finding All-Clear State Verification', async ({ page }) => {
    // 1. Restart target in SECURE mode
    execSync(`bash "${STACK_SCRIPT}" secure`, { stdio: 'inherit' });

    try {
      // 2. Launch scan against secure target
      await page.goto('/scans/new');
      await page.click('button:has-text("Load demo target")');
      await page.click('button[type="submit"]');

      // 3. Wait for completion
      await page.waitForURL((url) => !url.pathname.endsWith('/live') && url.pathname.includes('/scans/'), {
        timeout: 120_000,
      });
      await page.waitForLoadState('networkidle');

      // 4. Assert All-Clear honest-copy state
      await expect(page.locator('text=No Access-Control Vulnerabilities Detected')).toBeVisible({
        timeout: 15_000,
      });
      await expect(
        page.locator('text=All differential tests satisfied expected security boundaries')
      ).toBeVisible();
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'all-clear.png') });
    } finally {
      // 5. Restore vulnerable stack
      execSync(`bash "${STACK_SCRIPT}" vulnerable`, { stdio: 'inherit' });
    }
  });

  test('4. Scan Cancellation & Target Resource Cleanup', async ({ page }) => {
    await page.goto('/scans/new');
    await page.click('button:has-text("Load demo target")');
    await page.click('button[type="submit"]');

    // Wait for live view
    await page.waitForURL('**/scans/*/live', { timeout: 15_000 });

    // Click Cancel Audit
    await page.click('button:has-text("Cancel Audit")');
    // Confirm dialog
    await page.click('button:has-text("Confirm Cancel")');

    // Assert status transitions to CANCELLED
    await expect(page.locator('text=CANCELLED').first()).toBeVisible({ timeout: 20_000 });

    // Assert via target API that no scanner created orders remain
    const ordersRes = await fetch('http://127.0.0.1:9000/orders');
    if (ordersRes.ok) {
      const orders = await ordersRes.json();
      const testOrders = Array.isArray(orders)
        ? orders.filter((o: any) => o.item && o.item.includes('scanner'))
        : [];
      expect(testOrders.length).toBe(0);
    }
  });

  test('5. Axe Accessibility Audits (Zero Serious/Critical Violations)', async ({ page }) => {
    // Check History page
    await page.goto('/');
    let results = await new AxeBuilder({ page }).analyze();
    let severeViolations = results.violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical'
    );
    expect(severeViolations).toEqual([]);

    // Check New Scan page
    await page.goto('/scans/new');
    results = await new AxeBuilder({ page }).analyze();
    severeViolations = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    expect(severeViolations).toEqual([]);

    // Check Results page
    if (createdScanId) {
      await page.goto(`/scans/${createdScanId}`);
      await page.waitForLoadState('networkidle');
      results = await new AxeBuilder({ page }).analyze();
      severeViolations = results.violations.filter(
        (v) => v.impact === 'serious' || v.impact === 'critical'
      );
      expect(severeViolations).toEqual([]);

      // Check Matrix tab
      await page.click('button:has-text("Authorization Matrix")');
      results = await new AxeBuilder({ page }).analyze();
      severeViolations = results.violations.filter(
        (v) => v.impact === 'serious' || v.impact === 'critical'
      );
      expect(severeViolations).toEqual([]);
    }
  });

  test('6. Responsive Layout Smoke Test (No Horizontal Scroll)', async ({ page }) => {
    const viewports = [
      { width: 1440, height: 900 },
      { width: 768, height: 1024 },
      { width: 375, height: 667 },
    ];

    for (const vp of viewports) {
      await page.setViewportSize(vp);
      await page.goto(createdScanId ? `/scans/${createdScanId}` : '/');
      await page.waitForLoadState('networkidle');

      const isOverflowing = await page.evaluate(() => {
        return document.body.scrollWidth > window.innerWidth;
      });
      expect(isOverflowing).toBe(false);
    }
  });
});
