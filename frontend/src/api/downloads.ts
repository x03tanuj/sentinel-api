import { getApiKey } from './auth';
import type { Finding } from '../types';

export async function downloadReport(scanId: string, format: 'json' | 'md'): Promise<void> {
  const url = `/api/scans/${encodeURIComponent(scanId)}/report.${format}`;
  const headers: Record<string, string> = {};
  const key = getApiKey();
  if (key) {
    headers['X-API-Key'] = key;
  }

  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`Failed to download report: ${response.statusText}`);
  }

  let filename = `sentinelapi-scan-${scanId}.${format}`;
  const disposition = response.headers.get('Content-Disposition');
  if (disposition) {
    const match = /filename\*?=['"]?(?:UTF-\d['"]*)?([^;\r\n"']*)['"]?/i.exec(disposition);
    if (match && match[1]) {
      filename = decodeURIComponent(match[1]);
    }
  }

  const blob = await response.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = blobUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.URL.revokeObjectURL(blobUrl);
}

export function exportCurlSuite(findings: Finding[], scanId = 'scan'): void {
  const lines: string[] = [
    '#!/usr/bin/env bash',
    '# =============================================================================',
    `# SentinelAPI Reproducible Exploit Suite for Scan: ${scanId}`,
    '# Generated automatically by SentinelAPI Forensics Engine',
    '# WARNING: Intended solely for authorized penetration testing and verification.',
    '# =============================================================================',
    '',
    '# IMPORTANT: Set your target authorization token before running:',
    '# export TOKEN="<your-attacker-token>"',
    'if [ -z "$TOKEN" ]; then',
    '  echo "[-] ERROR: \\$TOKEN environment variable is not set."',
    '  echo "[-] Please run: export TOKEN=<attacker-token> and retry."',
    '  exit 1',
    'fi',
    '',
    'echo "[+] Executing SentinelAPI Reproduction Suite against target..."',
    '',
  ];

  findings.forEach((finding, idx) => {
    lines.push(`# -----------------------------------------------------------------------------`);
    lines.push(`# Finding #${idx + 1}: [${finding.severity}] ${finding.title}`);
    lines.push(`# Endpoint: ${finding.method} ${finding.endpoint} | OWASP: ${finding.owasp_id || 'N/A'}`);
    lines.push(`# -----------------------------------------------------------------------------`);
    if (finding.curl_poc) {
      lines.push(finding.curl_poc);
    } else {
      lines.push(`echo "[-] No curl PoC recorded for finding ${finding.id}"`);
    }
    lines.push('echo ""');
    lines.push('');
  });

  lines.push('echo "[+] Reproduction suite execution completed."');

  const content = lines.join('\n');
  const blob = new Blob([content], { type: 'application/x-sh' });
  const blobUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = blobUrl;
  anchor.download = `sentinelapi-curl-suite-${scanId}.sh`;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.URL.revokeObjectURL(blobUrl);
}
