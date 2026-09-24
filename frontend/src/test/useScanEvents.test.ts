import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { useScanEvents } from '../api/hooks';
import { rawClient } from '../api/client';

describe('useScanEvents SSE Hook', () => {
  beforeEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function createSSEStream(chunks: string[]): ReadableStream<Uint8Array> {
    const encoder = new TextEncoder();
    return new ReadableStream({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(encoder.encode(chunk));
        }
        controller.close();
      },
    });
  }

  it('parses SSE stream, filters keep-alive comments, deduplicates seq, and marks terminal state', async () => {
    const streamData = [
      ': keep-alive\n\n',
      'event: progress\ndata: {"seq": 1, "stage": "DISCOVERY", "percent": 25, "is_terminal": false}\n\n',
      ': keep-alive\n\n',
      // Duplicate seq 1
      'event: progress\ndata: {"seq": 1, "stage": "DISCOVERY", "percent": 25, "is_terminal": false}\n\n',
      'event: progress\ndata: {"seq": 2, "stage": "EXECUTION", "percent": 60, "is_terminal": false}\n\n',
      'event: complete\ndata: {"seq": 3, "stage": "FINALIZING", "percent": 100, "is_terminal": true}\n\n',
    ];

    const mockStream = createSSEStream(streamData);
    const mockResponse = {
      ok: true,
      status: 200,
      body: mockStream,
    };

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockResponse as unknown as Response);

    const { result } = renderHook(() => useScanEvents('scan-test-123'));

    await waitFor(() => {
      expect(result.current.isFinished).toBe(true);
    });

    expect(result.current.events.length).toBe(3); // Seq 1, 2, 3 (duplicate 1 omitted)
    expect(result.current.events[0].seq).toBe(1);
    expect(result.current.events[1].seq).toBe(2);
    expect(result.current.events[2].seq).toBe(3);
    expect(result.current.latestEvent?.stage).toBe('FINALIZING');
    expect(result.current.latestEvent?.percent).toBe(100);
  });

  it('falls back to polling when SSE stream fails after maximum retry attempts', async () => {
    // Mock failing fetch for SSE attempts
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));

    // Mock rawClient.GET for fallback polling
    const mockScanData = {
      id: 'scan-fallback-test',
      status: 'COMPLETED',
      progress: {
        seq: 99,
        stage: 'FINALIZING',
        percent: 100,
        is_terminal: true,
      },
    };

    const getSpy = vi.spyOn(rawClient, 'GET').mockResolvedValue({
      data: mockScanData as any,
      error: undefined,
      response: new Response(),
    });

    vi.useFakeTimers();

    const { result } = renderHook(() => useScanEvents('scan-fallback-test'));

    // Fast-forward through the 5 retry attempts (1s, 2s, 4s, 8s, 8s)
    await act(async () => {
      for (let i = 0; i < 6; i++) {
        await vi.advanceTimersByTimeAsync(8000);
      }
      // Now fallback polling should be active, advance 2 seconds for polling interval
      await vi.advanceTimersByTimeAsync(2500);
    });

    expect(getSpy).toHaveBeenCalled();
    expect(result.current.isFinished).toBe(true);
    expect(result.current.latestEvent?.seq).toBe(99);
    expect(result.current.latestEvent?.percent).toBe(100);
  });
});
