import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SeverityChip } from '../components/ui/SeverityChip';
import { CurlConsole } from '../components/triage/CurlConsole';
import { FilterBar } from '../components/triage/FilterBar';
import { MatrixGrid } from '../components/triage/MatrixGrid';
import { NewScanPage } from '../pages/NewScanPage';
import { setApiKey, getApiKey } from '../api/auth';
import type { MergedMatrixCell } from '../lib/adapters';

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>{children}</BrowserRouter>
    </QueryClientProvider>
  );
};

describe('Component & UI Forensics Tests', () => {
  describe('SeverityChip', () => {
    it('renders icon and uppercase text label with accessible aria-label', () => {
      render(<SeverityChip severity="CRITICAL" />);
      const chip = screen.getByRole('status', { name: /severity: critical/i });
      expect(chip).toBeInTheDocument();
      expect(chip).toHaveTextContent('CRITICAL');
    });

    it('renders all five severity levels and SECURE level', () => {
      const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'SECURE'] as const;
      severities.forEach((sev) => {
        const { unmount } = render(<SeverityChip severity={sev} />);
        expect(screen.getByRole('status', { name: new RegExp(`severity: ${sev}`, 'i') })).toBeInTheDocument();
        unmount();
      });
    });
  });

  describe('CurlConsole', () => {
    const poc = 'curl -X GET "http://target_api:9000/orders/101" -H "Authorization: Bearer $TOKEN"';

    it('renders curl command containing $TOKEN and never raw JWT credentials', () => {
      render(<CurlConsole curlPoc={poc} />);
      expect(screen.getByText(/Bearer \$TOKEN/)).toBeInTheDocument();
      expect(screen.queryByText(/Bearer ey/)).toBeNull();
    });

    it('triggers clipboard copy and displays 2-second micro-interaction', async () => {
      render(<CurlConsole curlPoc={poc} />);
      const copyBtn = screen.getByRole('button', { name: /copy curl command/i });
      fireEvent.click(copyBtn);

      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(poc);
      expect(screen.getByText('Copied!')).toBeInTheDocument();

      // Screen reader live notification
      expect(screen.getByText(/cURL command copied to clipboard/i)).toBeInTheDocument();
    });
  });

  describe('FilterBar', () => {
    it('fires callback events on severity pill click and search query changes', () => {
      const onSelectSeverity = vi.fn();
      const onSearchChange = vi.fn();
      const onMinConfidenceChange = vi.fn();
      const onSelectCheck = vi.fn();

      render(
        <FilterBar
          selectedSeverity="CRITICAL"
          onSelectSeverity={onSelectSeverity}
          counts={{ CRITICAL: 2, HIGH: 1 }}
          searchQuery=""
          onSearchChange={onSearchChange}
          minConfidence={0.5}
          onMinConfidenceChange={onMinConfidenceChange}
          selectedCheck=""
          onSelectCheck={onSelectCheck}
          totalFindings={3}
        />
      );

      const highPill = screen.getByRole('button', { name: /high/i });
      fireEvent.click(highPill);
      expect(onSelectSeverity).toHaveBeenCalledWith('HIGH');

      const searchInput = screen.getByPlaceholderText(/search findings/i);
      fireEvent.change(searchInput, { target: { value: '/orders' } });
      expect(onSearchChange).toHaveBeenCalledWith('/orders');
    });
  });

  describe('MatrixGrid', () => {
    const mockCells: MergedMatrixCell[] = [
      {
        resource: 'orders',
        objectId: '101',
        owner: 'userA',
        identity: 'userA',
        state: 'owns',
        expectedOutcome: 'ALLOW',
      },
      {
        resource: 'orders',
        objectId: '101',
        owner: 'userA',
        identity: 'userB',
        state: 'violation',
        expectedOutcome: 'DENY',
        actualStatus: 200,
        findingId: 'finding-101',
      },
    ];

    it('assigns accessible aria-labels and triggers finding navigation on violation click', () => {
      const onSelectFinding = vi.fn();
      render(<MatrixGrid cells={mockCells} onSelectFinding={onSelectFinding} />);

      const violationCell = screen.getByRole('button', {
        name: /userB on orders 101: violation/i,
      });
      expect(violationCell).toBeInTheDocument();

      fireEvent.click(violationCell);
      expect(onSelectFinding).toHaveBeenCalledWith('finding-101');
    });
  });

  describe('NewScanPage Client Validation & Secret Security', () => {
    it('blocks submission when authorization confirmation is unchecked', async () => {
      render(<NewScanPage />, { wrapper: createWrapper() });

      const submitBtn = screen.getByRole('button', { name: /launch security audit/i });
      expect(submitBtn).toBeDisabled();
    });

    it('clears password fields from DOM state and never leaks credentials to localStorage or sessionStorage', async () => {
      const user = userEvent.setup();
      render(<NewScanPage />, { wrapper: createWrapper() });

      // Click "Load demo target preset"
      const demoBtn = screen.getByRole('button', { name: /load demo target/i });
      await user.click(demoBtn);

      // Confirm auth checkbox is checked
      const authCheckbox = screen.getByRole('checkbox', {
        name: /i confirm that i am authorized/i,
      });
      expect(authCheckbox).toBeChecked();

      // Submit form
      const submitBtn = screen.getByRole('button', { name: /launch security audit/i });
      expect(submitBtn).toBeEnabled();

      await user.click(submitBtn);

      // Verify passwords never exist in localStorage or sessionStorage
      const localDump = JSON.stringify(localStorage);
      const sessionDump = JSON.stringify(sessionStorage);

      expect(localDump).not.toContain('passA123');
      expect(localDump).not.toContain('passB123');
      expect(localDump).not.toContain('admin123');
      expect(sessionDump).not.toContain('passA123');
      expect(sessionDump).not.toContain('passB123');
      expect(sessionDump).not.toContain('admin123');
    });

    it('stores API keys exclusively in sessionStorage and memory', () => {
      setApiKey('test_secret_api_key_123');
      expect(getApiKey()).toBe('test_secret_api_key_123');
      expect(sessionStorage.getItem('sentinel_api_key')).toBe('test_secret_api_key_123');
      expect(localStorage.getItem('sentinel_api_key')).toBeNull();
    });

    it('allows user to select sample target via radio buttons one at a time and auto-fills target details', async () => {
      const user = userEvent.setup();
      render(<NewScanPage />, { wrapper: createWrapper() });

      const ecomRadio = screen.getByRole('radio', { name: /ShopSentinel/i });
      const healthRadio = screen.getByRole('radio', { name: /MedPulse/i });
      const fintechRadio = screen.getByRole('radio', { name: /ApexBank/i });
      const secureRadio = screen.getByRole('radio', { name: /Aegis Zero-Trust/i });

      expect(ecomRadio).toBeInTheDocument();
      expect(healthRadio).toBeInTheDocument();
      expect(fintechRadio).toBeInTheDocument();
      expect(secureRadio).toBeInTheDocument();

      // Click Healthcare radio
      await user.click(healthRadio);
      expect(healthRadio).toBeChecked();
      expect(ecomRadio).not.toBeChecked();
      expect(fintechRadio).not.toBeChecked();
      expect(secureRadio).not.toBeChecked();

      const urlInput = screen.getByLabelText(/Base Target URL/i) as HTMLInputElement;
      expect(urlInput.value).toBe('http://health_api:9001');

      // Click FinTech radio (one at a time)
      await user.click(fintechRadio);
      expect(fintechRadio).toBeChecked();
      expect(healthRadio).not.toBeChecked();
      expect(ecomRadio).not.toBeChecked();
      expect(secureRadio).not.toBeChecked();
      expect(urlInput.value).toBe('http://fintech_api:9002');

      // Click Aegis Zero-Trust radio (one at a time)
      await user.click(secureRadio);
      expect(secureRadio).toBeChecked();
      expect(fintechRadio).not.toBeChecked();
      expect(healthRadio).not.toBeChecked();
      expect(ecomRadio).not.toBeChecked();
      expect(urlInput.value).toBe('http://secure_api:9003');
    });
  });
});
