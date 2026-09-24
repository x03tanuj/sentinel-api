import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { downloadReport, exportCurlSuite } from '../api/downloads';
import { setApiKey, clearApiKey } from '../api/auth';
import type { Finding } from '../types';

describe('Downloads & cURL Suite Exports', () => {
  let createdAnchors: HTMLAnchorElement[] = [];
  let clickedAnchors: HTMLAnchorElement[] = [];

  beforeEach(() => {
    createdAnchors = [];
    clickedAnchors = [];
    clearApiKey();

    window.URL.createObjectURL = vi.fn().mockReturnValue('blob:mock-url');
    window.URL.revokeObjectURL = vi.fn();

    const origCreateElement = document.createElement.bind(document);
    vi.spyOn(document, 'createElement').mockImplementation((tagName: string) => {
      const el = origCreateElement(tagName);
      if (tagName === 'a') {
        const anchor = el as HTMLAnchorElement;
        vi.spyOn(anchor, 'click').mockImplementation(() => {
          clickedAnchors.push(anchor);
        });
        createdAnchors.push(anchor);
      }
      return el;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    clearApiKey();
  });

  describe('downloadReport', () => {
    it('downloads report and extracts filename from Content-Disposition header', async () => {
      const mockBlob = new Blob(['# SentinelAPI Scan Report'], { type: 'text/markdown' });
      const mockResponse = {
        ok: true,
        headers: new Headers({
          'Content-Disposition': 'attachment; filename="sentinel-production-report.md"',
        }),
        blob: async () => mockBlob,
      };

      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockResponse as unknown as Response);

      await downloadReport('scan-abc-123', 'md');

      expect(fetch).toHaveBeenCalledWith('/api/scans/scan-abc-123/report.md', {
        headers: {},
      });
      expect(clickedAnchors.length).toBe(1);
      expect(clickedAnchors[0].download).toBe('sentinel-production-report.md');
      expect(clickedAnchors[0].href).toBe('blob:mock-url');
    });

    it('attaches X-API-Key header when user is authenticated with API key', async () => {
      setApiKey('test-secret-key-999');

      const mockResponse = {
        ok: true,
        headers: new Headers(),
        blob: async () => new Blob(['{}'], { type: 'application/json' }),
      };

      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockResponse as unknown as Response);

      await downloadReport('scan-xyz', 'json');

      expect(fetch).toHaveBeenCalledWith('/api/scans/scan-xyz/report.json', {
        headers: {
          'X-API-Key': 'test-secret-key-999',
        },
      });
      expect(clickedAnchors.length).toBe(1);
      expect(clickedAnchors[0].download).toBe('sentinelapi-scan-scan-xyz.json');
    });

    it('throws error when server responds with non-ok status', async () => {
      const mockResponse = {
        ok: false,
        statusText: 'Internal Server Error',
      };
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockResponse as unknown as Response);

      await expect(downloadReport('bad-scan', 'json')).rejects.toThrow(
        'Failed to download report: Internal Server Error'
      );
    });
  });

  describe('exportCurlSuite', () => {
    it('builds shell script suite with one command per finding, $TOKEN instructions and no credentials', () => {
      const sampleFindings: Finding[] = [
        {
          id: 'find-1',
          check: 'bola',
          severity: 'CRITICAL',
          confidence: 0.95,
          title: 'BOLA on Order API',
          explanation: 'Access without authorization',
          endpoint: '/orders/{id}',
          method: 'GET',
          curl_poc: 'curl -s -H "Authorization: Bearer $TOKEN" http://target:9000/orders/104',
          fix_hint: 'Verify resource ownership',
        },
        {
          id: 'find-2',
          check: 'data_exposure',
          severity: 'HIGH',
          confidence: 0.85,
          title: 'PII Exposure on Users API',
          explanation: 'Exposes ssn and password hash',
          endpoint: '/users/{id}',
          method: 'GET',
          curl_poc: 'curl -s -H "Authorization: Bearer $TOKEN" http://target:9000/users/2',
          fix_hint: 'Filter response fields using DTO',
        },
      ];

      let generatedBlobContent = '';
      vi.spyOn(globalThis, 'Blob').mockImplementation(function (
        this: unknown,
        blobParts?: BlobPart[],
        options?: BlobPropertyBag
      ) {
        if (blobParts && blobParts[0]) {
          generatedBlobContent = String(blobParts[0]);
        }
        return new (class extends EventTarget {
          size = generatedBlobContent.length;
          type = options?.type || '';
          arrayBuffer = async () => new ArrayBuffer(0);
          slice = () => this as unknown as Blob;
          stream = () => new ReadableStream();
          text = async () => generatedBlobContent;
        })() as unknown as Blob;
      });

      exportCurlSuite(sampleFindings, 'test-scan');

      expect(clickedAnchors.length).toBe(1);
      expect(clickedAnchors[0].download).toBe('sentinelapi-curl-suite-test-scan.sh');

      // Assert shell script header and instructions
      expect(generatedBlobContent).toContain('#!/usr/bin/env bash');
      expect(generatedBlobContent).toContain('export TOKEN=');
      expect(generatedBlobContent).toContain('if [ -z "$TOKEN" ]; then');

      // Assert commands for both findings are present
      expect(generatedBlobContent).toContain('curl -s -H "Authorization: Bearer $TOKEN" http://target:9000/orders/104');
      expect(generatedBlobContent).toContain('curl -s -H "Authorization: Bearer $TOKEN" http://target:9000/users/2');

      // Assert security: no hardcoded JWT tokens in the suite
      expect(generatedBlobContent).not.toMatch(/Bearer ey[A-Za-z0-9_-]+/);
      expect(generatedBlobContent).not.toContain('passA123');
      expect(generatedBlobContent).not.toContain('admin123');
    });
  });
});
