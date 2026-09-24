import React from 'react';
import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

import { AiAnalysisPanel } from '../components/triage/AiAnalysisPanel';
import { AiSummaryPanel } from '../components/triage/AiSummaryPanel';
import { NewScanPage } from '../pages/NewScanPage';
import { BrowserRouter } from 'react-router-dom';
import type { Finding, AiAnalysisData } from '../types';

const mockFinding: Finding = {
  id: 'finding-123',
  check: 'bola',
  endpoint: '/orders/{id}',
  method: 'GET',
  title: 'BOLA on GET /orders/{id}',
  severity: 'CRITICAL',
  confidence: 0.95,
  explanation: 'Unauthorized access to other users orders.',
  curl_poc: 'curl -X GET http://target_api:9000/orders/104',
  fix_hint: 'Verify caller owns order ID',
  owasp_id: 'API1:2023',
};

const server = setupServer(
  http.get('/api/ai/status', () => {
    return HttpResponse.json({
      enabled: true,
      provider: 'groq',
      model: 'llama-3.3-70b-versatile',
      max_calls_per_scan: 15,
    });
  }),
  http.post('/api/scans/:scanId/findings/:findingId/explain', () => {
    return HttpResponse.json({
      plain_explanation: 'Object level authorization is missing on order lookup.',
      business_impact: 'Confidential order information exposed.',
      attacker_scenario: 'Attacker queries order IDs sequentially.',
      remediation_steps: [
        'Enforce tenant boundary checks',
        'Verify current user owns requested resource',
        'Return 403 on authorization failure',
      ],
      code_fix_example: 'if order.user_id != user.id:\n    raise HTTPException(403)',
      code_language: 'python',
      verification_steps: [
        'Run SentinelAPI scan',
        'Expect 403 Forbidden',
      ],
      source: 'llm',
      model: 'llama-3.3-70b-versatile',
      prompt_version: 'v1',
      generated_at: new Date().toISOString(),
      warning: null,
    });
  }),
  http.post('/api/scans/:scanId/ai-summary', () => {
    return HttpResponse.json({
      text: 'Scan summary: 1 critical BOLA vulnerability detected on order endpoints.',
      source: 'llm',
      model: 'llama-3.3-70b-versatile',
      generated_at: new Date().toISOString(),
      calls_used: 1,
    });
  }),
  http.get('/api/scope', () => {
    return HttpResponse.json({ allowed_hosts: ['target_api', 'localhost'] });
  })
);

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>{children}</BrowserRouter>
    </QueryClientProvider>
  );
}

describe('AI Analyst Frontend Forensic Tests', () => {
  beforeAll(() => {
    server.listen({ onUnhandledRequest: 'error' });
  });

  beforeEach(() => {
    sessionStorage.clear();
  });

  afterEach(() => {
    server.resetHandlers();
  });

  afterAll(() => {
    server.close();
  });

  it('renders disabled state with docs link when AI is unconfigured', async () => {
    server.use(
      http.get('/api/ai/status', () => {
        return HttpResponse.json({
          enabled: false,
          provider: null,
          model: null,
          max_calls_per_scan: 15,
        });
      })
    );

    render(<AiAnalysisPanel scanId="scan-1" finding={mockFinding} />, {
      wrapper: createWrapper(),
    });

    expect(
      await screen.findByText(/AI analysis is not configured on this server/i)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/View AI Setup Documentation/i)
    ).toBeInTheDocument();
    expect(screen.queryByTestId('explain-ai-button')).not.toBeInTheDocument();
  });

  it('enforces first-use session consent dialog gating before making explain call', async () => {
    const user = userEvent.setup();
    let explainCalled = false;
    server.use(
      http.post('/api/scans/:scanId/findings/:findingId/explain', () => {
        explainCalled = true;
        return HttpResponse.json({
          plain_explanation: 'Authorization flaw.',
          business_impact: 'Data leak.',
          attacker_scenario: 'Attacker probes IDs.',
          remediation_steps: ['Check user ownership'],
          code_fix_example: 'if order.user_id != user.id: raise 403',
          code_language: 'python',
          verification_steps: ['Scan again'],
          source: 'llm',
          model: 'llama-3.3-70b-versatile',
        });
      })
    );

    render(<AiAnalysisPanel scanId="scan-1" finding={mockFinding} />, {
      wrapper: createWrapper(),
    });

    const explainBtn = await screen.findByTestId('explain-ai-button');
    await user.click(explainBtn);

    // Consent modal must appear
    expect(
      screen.getByRole('heading', { name: /AI Security & Data Egress Notice/i })
    ).toBeInTheDocument();
    expect(
      screen.getByText(/AI analysis sends redacted finding metadata/i)
    ).toBeInTheDocument();
    expect(explainCalled).toBe(false);

    // Cancel leaves consent ungranted
    const cancelBtn = screen.getByRole('button', { name: /Cancel/i });
    await user.click(cancelBtn);
    expect(explainCalled).toBe(false);
    expect(sessionStorage.getItem('sentinel_ai_consent')).toBeNull();

    // Click again and accept
    await user.click(explainBtn);
    const acceptBtn = screen.getByRole('button', { name: /Accept & Continue/i });
    await user.click(acceptBtn);

    expect(sessionStorage.getItem('sentinel_ai_consent')).toBe('true');
    await waitFor(() => {
      expect(explainCalled).toBe(true);
    });
  });

  it('renders each field strictly as plain text (XSS defense)', async () => {
    const maliciousPayload: AiAnalysisData = {
      plain_explanation: '<img src=x onerror=alert(1)> Malicious explanation',
      business_impact: '<script>alert("xss")</script> Business impact',
      attacker_scenario: '<svg onload=alert(2)> Attacker scenario',
      remediation_steps: ['<iframe src=javascript:alert(3)> Step 1'],
      code_fix_example: '<img src=x onerror=alert(4)> code example',
      code_language: 'python',
      verification_steps: ['<body onload=alert(5)> Verify step'],
      source: 'llm',
      model: 'llama-3.3-70b-versatile',
    };

    const findingWithMaliciousAi: Finding = {
      ...mockFinding,
      ai_analysis: maliciousPayload,
    };

    render(
      <AiAnalysisPanel scanId="scan-1" finding={findingWithMaliciousAi} />,
      { wrapper: createWrapper() }
    );

    // Assert that the raw strings are rendered as literal text
    expect(
      await screen.findByText(/<img src=x onerror=alert\(1\)> Malicious explanation/)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/<script>alert\("xss"\)<\/script> Business impact/)
    ).toBeInTheDocument();

    // Crucial security check: NO <img>, <script>, <svg>, <iframe> elements created in DOM
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector('iframe')).toBeNull();
    expect(document.querySelector('svg[onload]')).toBeNull();
  });

  it('displays template fallback badge and warning message when provider fails', async () => {
    const fallbackAnalysis: AiAnalysisData = {
      plain_explanation: 'Standard deterministic explanation.',
      business_impact: 'Potential data disclosure.',
      attacker_scenario: 'Unauthorized access.',
      remediation_steps: ['Apply authorization check'],
      code_fix_example: '# Verify caller ownership',
      code_language: 'generic',
      verification_steps: ['Test endpoint'],
      source: 'template',
      model: null,
      warning: 'LLM provider unavailable; deterministic template analysis attached.',
    };

    const findingWithFallback: Finding = {
      ...mockFinding,
      ai_analysis: fallbackAnalysis,
    };

    render(
      <AiAnalysisPanel scanId="scan-1" finding={findingWithFallback} />,
      { wrapper: createWrapper() }
    );

    const fallbackBadge = await screen.findByTestId('template-fallback-badge');
    expect(fallbackBadge).toBeInTheDocument();
    expect(fallbackBadge).toHaveTextContent(/Template fallback/i);
    expect(
      screen.getByText(/LLM provider unavailable; deterministic template analysis attached/i)
    ).toBeInTheDocument();
  });

  it('displays friendly message when call cap (429) is reached', async () => {
    sessionStorage.setItem('sentinel_ai_consent', 'true');
    server.use(
      http.post('/api/scans/:scanId/findings/:findingId/explain', () => {
        return HttpResponse.json(
          { detail: "AI call cap reached for scan 'scan-1' (15/15)." },
          { status: 429 }
        );
      })
    );

    const user = userEvent.setup();
    render(<AiAnalysisPanel scanId="scan-1" finding={mockFinding} />, {
      wrapper: createWrapper(),
    });

    const explainBtn = await screen.findByTestId('explain-ai-button');
    await user.click(explainBtn);

    expect(
      await screen.findByText(/AI call cap reached for scan 'scan-1' \(15\/15\)/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/Retry analysis/i)).toBeInTheDocument();
  });

  it('renders AiSummaryPanel and triggers executive summary generation', async () => {
    const user = userEvent.setup();
    render(<AiSummaryPanel scanId="scan-1" />, {
      wrapper: createWrapper(),
    });

    const generateBtn = await screen.findByTestId('generate-ai-summary-btn');
    expect(generateBtn).toBeInTheDocument();
    await user.click(generateBtn);

    expect(
      await screen.findByText(/1 critical BOLA vulnerability detected on order endpoints/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/Source: LLM/i)).toBeInTheDocument();
  });

  it('renders NewScanPage AI checkbox disabled when AI is unconfigured and enabled when configured', async () => {
    // When configured (default in beforeEach):
    const { unmount } = render(<NewScanPage />, { wrapper: createWrapper() });
    const checkbox = (await screen.findByLabelText(
      /Use AI to suggest extra tests/i
    )) as HTMLInputElement;
    expect(checkbox).toBeInTheDocument();
    await waitFor(() => expect(checkbox).not.toBeDisabled());
    unmount();

    // When unconfigured:
    server.use(
      http.get('/api/ai/status', () => {
        return HttpResponse.json({
          enabled: false,
          provider: null,
          model: null,
          max_calls_per_scan: 15,
        });
      })
    );

    render(<NewScanPage />, { wrapper: createWrapper() });
    const disabledCheckbox = (await screen.findByLabelText(
      /Use AI to suggest extra tests/i
    )) as HTMLInputElement;
    expect(disabledCheckbox).toBeDisabled();
    expect(
      screen.getByText(/Disabled: AI is not configured on this server/i)
    ).toBeInTheDocument();
  });
});
