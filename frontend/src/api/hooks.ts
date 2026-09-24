import { useState, useEffect, useRef, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import rawClient, { ApiError, sanitizeErrorMessage } from './client';
import { getApiKey } from './auth';
import type {
  Finding,
  ScanSummary,
  ProgressEvent,
  MatrixResponse,
  SurfaceResponse,
  ScanConfigInput,
  ScanDetailResponse,
  AiStatus,
  AiAnalysisData,
  AiSummaryData,
} from '../types';

export function useScans(limit = 50) {
  return useQuery({
    queryKey: ['scans', limit],
    queryFn: async () => {
      const { data, error, response } = await rawClient.GET('/scans', {
        params: { query: { limit } },
      });
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return (data as any[]).map((s) => ({
        scan_id: s.id,
        id: s.id,
        status: s.status,
        target_url: s.target_url || (s.config_public?.base_url as string) || 'http://target_api:9000',
        spec_source: s.spec_source || (s.config_public?.spec_source as string) || 'openapi.json',
        started_at: s.started_at || s.created_at,
        duration_seconds: s.duration_seconds || 0,
        total_findings: s.total_findings || 0,
        critical: s.by_severity?.CRITICAL ?? s.by_severity?.critical ?? 0,
        high: s.by_severity?.HIGH ?? s.by_severity?.high ?? 0,
        medium: s.by_severity?.MEDIUM ?? s.by_severity?.medium ?? 0,
        low: s.by_severity?.LOW ?? s.by_severity?.low ?? 0,
        info: s.by_severity?.INFO ?? s.by_severity?.info ?? 0,
      })) as ScanSummary[];
    },
  });
}

export function useScan(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: async () => {
      if (!scanId) throw new Error('Scan ID required');
      const { data, error, response } = await rawClient.GET('/scans/{scan_id}', {
        params: { path: { scan_id: scanId } },
      });
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data as unknown as ScanDetailResponse;
    },
    enabled: !!scanId,
    refetchInterval: (query) => {
      const status = (query.state.data?.status || '').toUpperCase();
      if (status === 'QUEUED' || status === 'RUNNING') {
        return 2000;
      }
      return false;
    },
  });
}

export interface FindingsFilters {
  severity?: string;
  check?: string;
  min_confidence?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

export function useFindings(scanId: string | undefined, filters: FindingsFilters = {}) {
  return useQuery({
    queryKey: ['findings', scanId, filters],
    queryFn: async () => {
      if (!scanId) return { findings: [], total: 0 };
      const { data, error, response } = await rawClient.GET('/scans/{scan_id}/findings', {
        params: {
          path: { scan_id: scanId },
          query: {
            severity: filters.severity || undefined,
            check: filters.check || undefined,
            min_confidence: filters.min_confidence,
            sort: filters.sort || undefined,
            order: filters.order || undefined,
          },
        },
      });
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return {
        findings: data.findings as unknown as Finding[],
        total: data.total,
      };
    },
    enabled: !!scanId,
  });
}

export function useFinding(scanId: string | undefined, findingId: string | undefined) {
  return useQuery({
    queryKey: ['finding', scanId, findingId],
    queryFn: async () => {
      if (!scanId || !findingId) return null;
      const { data, error, response } = await rawClient.GET('/scans/{scan_id}/findings/{finding_id}', {
        params: {
          path: { scan_id: scanId, finding_id: findingId },
        },
      });
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data as unknown as Finding;
    },
    enabled: !!scanId && !!findingId,
  });
}

export function useSurface(scanId: string | undefined) {
  return useQuery({
    queryKey: ['surface', scanId],
    queryFn: async () => {
      if (!scanId) return null;
      const { data, error, response } = await rawClient.GET('/scans/{scan_id}/surface', {
        params: { path: { scan_id: scanId } },
      });
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data as unknown as SurfaceResponse;
    },
    enabled: !!scanId,
  });
}

export function useMatrix(scanId: string | undefined) {
  return useQuery({
    queryKey: ['matrix', scanId],
    queryFn: async () => {
      if (!scanId) return null;
      const { data, error, response } = await rawClient.GET('/scans/{scan_id}/matrix', {
        params: { path: { scan_id: scanId } },
      });
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data as unknown as MatrixResponse;
    },
    enabled: !!scanId,
  });
}

export function useNotes(scanId: string | undefined) {
  return useQuery({
    queryKey: ['notes', scanId],
    queryFn: async () => {
      if (!scanId) return [];
      const { data, error, response } = await rawClient.GET('/scans/{scan_id}/notes', {
        params: { path: { scan_id: scanId } },
      });
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data.notes;
    },
    enabled: !!scanId,
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (config: ScanConfigInput) => {
      const { data, error, response } = await rawClient.POST('/scans', {
        body: config as any,
      });
      if (error || !data) {
        let retryAfter: number | undefined;
        const retryHeader = response.headers.get('Retry-After');
        if (retryHeader) {
          const parsed = parseInt(retryHeader, 10);
          if (!isNaN(parsed)) retryAfter = parsed;
        }
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error), retryAfter);
      }
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (scanId: string) => {
      const { data, error, response } = await rawClient.POST('/scans/{scan_id}/cancel', {
        params: { path: { scan_id: scanId } },
      });
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data;
    },
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

export function useDeleteScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (scanId: string) => {
      const { error, response } = await rawClient.DELETE('/scans/{scan_id}', {
        params: { path: { scan_id: scanId } },
      });
      if (error) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return true;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

export function useAiStatus() {
  return useQuery({
    queryKey: ['ai-status'],
    queryFn: async () => {
      const { data, error, response } = await rawClient.GET('/ai/status');
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data as AiStatus;
    },
    staleTime: 60_000,
  });
}

export function useExplainFinding(scanId: string | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      findingId,
      frameworkHint = 'generic',
      forceRefresh = false,
    }: {
      findingId: string;
      frameworkHint?: string;
      forceRefresh?: boolean;
    }) => {
      if (!scanId) throw new Error('Scan ID required');
      const { data, error, response } = await rawClient.POST(
        '/scans/{scan_id}/findings/{finding_id}/explain',
        {
          params: { path: { scan_id: scanId, finding_id: findingId } },
          body: { framework_hint: frameworkHint, force_refresh: forceRefresh },
        }
      );
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data as unknown as AiAnalysisData;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['findings', scanId] });
      queryClient.invalidateQueries({ queryKey: ['finding', scanId, variables.findingId] });
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
    },
  });
}

export function useExplainTop(scanId: string | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ n = 5 }: { n?: number } = {}) => {
      if (!scanId) throw new Error('Scan ID required');
      const { data, error, response } = await rawClient.POST(
        '/scans/{scan_id}/explain-top',
        {
          params: { path: { scan_id: scanId }, query: { n } },
        }
      );
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data as unknown as {
        analyses: AiAnalysisData[];
        skipped_count: number;
        calls_used: number;
        calls_remaining: number;
      };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings', scanId] });
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
    },
  });
}

export function useAiSummary(scanId: string | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      if (!scanId) throw new Error('Scan ID required');
      const { data, error, response } = await rawClient.POST(
        '/scans/{scan_id}/ai-summary',
        {
          params: { path: { scan_id: scanId } },
        }
      );
      if (error || !data) {
        throw new ApiError(response.status, sanitizeErrorMessage(response.status, error));
      }
      return data as unknown as AiSummaryData;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
    },
  });
}

export function useScanEvents(scanId: string | undefined) {
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [latestEvent, setLatestEvent] = useState<ProgressEvent | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isFinished, setIsFinished] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const seenSeqs = useRef<Set<number>>(new Set());
  const abortControllerRef = useRef<AbortController | null>(null);
  const reconnectAttempts = useRef(0);
  const fallbackPollingTimer = useRef<number | null>(null);

  const handleNewEvent = useCallback((event: ProgressEvent) => {
    if (seenSeqs.current.has(event.seq)) {
      return;
    }
    seenSeqs.current.add(event.seq);
    setEvents((prev) => [...prev, event]);
    setLatestEvent(event);
    const statusUpper = (event.status || '').toUpperCase();
    if (
      event.is_terminal ||
      ['COMPLETED', 'FAILED', 'CANCELLED', 'INTERRUPTED'].includes(statusUpper) ||
      event.percent === 100
    ) {
      setIsFinished(true);
      setIsConnected(false);
    }
  }, []);

  const startFallbackPolling = useCallback(() => {
    if (fallbackPollingTimer.current !== null) return;
    fallbackPollingTimer.current = window.setInterval(async () => {
      if (!scanId) return;
      try {
        const { data } = await rawClient.GET('/scans/{scan_id}', {
          params: { path: { scan_id: scanId } },
        });
        if (data && data.progress) {
          const prog = data.progress as unknown as ProgressEvent;
          handleNewEvent(prog);
          const sUpper = (data.status || '').toUpperCase();
          if (
            sUpper === 'COMPLETED' ||
            sUpper === 'FAILED' ||
            sUpper === 'CANCELLED' ||
            sUpper === 'INTERRUPTED'
          ) {
            setIsFinished(true);
            if (fallbackPollingTimer.current) {
              clearInterval(fallbackPollingTimer.current);
              fallbackPollingTimer.current = null;
            }
          }
        }
      } catch {
        // Polling failure
      }
    }, 2000);
  }, [scanId, handleNewEvent]);

  useEffect(() => {
    if (!scanId || isFinished) {
      return;
    }

    let isCancelled = false;

    async function connectStream() {
      if (isCancelled || isFinished) return;

      abortControllerRef.current = new AbortController();
      const headers: Record<string, string> = {
        Accept: 'text/event-stream',
      };
      const key = getApiKey();
      if (key) {
        headers['X-API-Key'] = key;
      }

      try {
        const response = await fetch(`/api/scans/${encodeURIComponent(scanId!)}/events`, {
          headers,
          signal: abortControllerRef.current.signal,
        });

        if (!response.ok || !response.body) {
          throw new Error(`SSE stream failed with status ${response.status}`);
        }

        setIsConnected(true);
        reconnectAttempts.current = 0;

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (!isCancelled) {
          const { value, done } = await reader.read();
          if (done) {
            setIsFinished(true);
            setIsConnected(false);
            break;
          }

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith(':')) {
              continue;
            }
            if (trimmed.startsWith('data:')) {
              const dataStr = trimmed.slice(5).trim();
              try {
                const parsed = JSON.parse(dataStr);
                handleNewEvent(parsed);
                const sUpper = (parsed.status || '').toUpperCase();
                if (
                  parsed.is_terminal ||
                  ['COMPLETED', 'FAILED', 'CANCELLED', 'INTERRUPTED'].includes(sUpper) ||
                  parsed.percent === 100
                ) {
                  setIsFinished(true);
                  setIsConnected(false);
                  isCancelled = true;
                  break;
                }
              } catch {
                // Ignore parse errors on partial data
              }
            }
          }
        }
      } catch (err: unknown) {
        if (isCancelled) return;
        setIsConnected(false);
        const errObj = err as Error;
        if (errObj.name !== 'AbortError') {
          reconnectAttempts.current += 1;
          if (reconnectAttempts.current <= 5) {
            const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current - 1), 8000);
            setTimeout(() => {
              if (!isCancelled && !isFinished) {
                connectStream();
              }
            }, delay);
          } else {
            setError('Real-time connection lost. Falling back to background polling.');
            startFallbackPolling();
          }
        }
      }
    }

    connectStream();

    return () => {
      isCancelled = true;
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (fallbackPollingTimer.current) {
        clearInterval(fallbackPollingTimer.current);
        fallbackPollingTimer.current = null;
      }
    };
  }, [scanId, isFinished, handleNewEvent, startFallbackPolling]);

  return {
    events,
    latestEvent,
    isConnected,
    isFinished,
    error,
  };
}
