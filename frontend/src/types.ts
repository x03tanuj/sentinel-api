export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'INTERRUPTED';

export interface RequestRecord {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
  timestamp?: string;
}

export interface ResponseRecord {
  status_code: number;
  headers: Record<string, string>;
  body: unknown;
  elapsed_ms?: number;
  timestamp?: string;
}

export interface RiskBreakdownData {
  impact?: number;
  exploitability?: number;
  data_sensitivity?: number;
  evidence_strength?: number;
}

export interface ReproductionData {
  reproduced?: boolean;
  attempts?: number;
  downgraded?: boolean;
}

export interface ResponseDiffData {
  status_divergence?: boolean;
  body_similarity?: number;
  masked_sensitive_values?: Record<string, string>;
  sensitive_fields_exposed?: Record<string, string[]>;
  reproduction?: ReproductionData;
  downgraded?: boolean;
  risk_breakdown?: RiskBreakdownData;
  risk_score?: number;
  affected_objects?: string[];
  [key: string]: unknown;
}

export interface EvidenceData {
  identity: string;
  object_id?: string | null;
  expected_status?: number | null;
  actual_status: number;
  request: RequestRecord;
  baseline_response?: ResponseRecord | null;
  attack_response: ResponseRecord;
  response_diff?: ResponseDiffData;
  timestamp?: string;
}

export interface Finding {
  id: string;
  check: string;
  endpoint: string;
  method: string;
  title: string;
  severity: Severity;
  confidence: number;
  explanation: string;
  evidence?: EvidenceData | null;
  curl_poc: string;
  fix_hint: string;
  owasp_id?: string | null;
  timestamp?: string;
  ai_analysis?: {
    suggested_fix?: string;
    explanation?: string;
  } | null;
}

export interface ScanSummary {
  scan_id: string;
  id?: string;
  status: ScanStatus;
  target_url: string;
  spec_source: string;
  started_at: string;
  duration_seconds: number;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  endpoints_audited?: number;
  by_severity?: Record<string, number>;
  // Feature-detected backend gaps
  verified_controls?: number;
  verified_endpoints?: string[];
}

export interface ProgressEvent {
  seq: number;
  scan_id: string;
  stage: string;
  status?: string;
  percent: number;
  message: string;
  timestamp: string;
  requests_sent?: number;
  request_budget?: number;
  findings_count?: number;
  is_terminal?: boolean;
  check?: string | null;
}

export interface ScanDetailResponse {
  id: string;
  status: string;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  progress: Record<string, unknown>;
  config_public: Record<string, unknown>;
  summary?: Record<string, unknown> | null;
  error?: string | null;
  notes_count: number;
}

export interface MatrixCellData {
  resource: string;
  object_id: string;
  owner: string;
  identity: string;
  expected_outcome: 'ALLOW' | 'DENY';
  actual_status?: number | null;
  outcome_status?: string;
  finding_id?: string | null;
}

export interface MatrixResponse {
  cells: MatrixCellData[];
  summary: {
    total_cells: number;
    expected_denials: number;
    authorized_access: number;
    violations: number;
  };
}

export interface EndpointData {
  path: string;
  method: string;
  summary?: string | null;
  operation_id?: string | null;
  auth_required: boolean;
  is_object_level: boolean;
  is_privileged: boolean;
  resource?: string | null;
  risk_score?: number;
  priority_score?: number;
}

export interface SurfaceResponse {
  endpoints: EndpointData[];
  total: number;
}

export interface ScanConfigInput {
  base_url: string;
  spec_url?: string | null;
  spec_inline?: Record<string, unknown> | null;
  identities: {
    name: string;
    role: string;
    username: string;
    password?: string;
  }[];
  enabled_checks?: string[] | null;
  test_case_budget?: number;
  max_requests?: number;
  sample_bodies?: Record<string, Record<string, unknown>>;
}

export interface DiffModel {
  mode: 'full_bodies' | 'field_list';
  ownerIdentity: string;
  attackerIdentity: string;
  ownerStatus?: number;
  attackerStatus: number;
  expectedStatus?: number;
  statusDivergence: boolean;
  ownerBodyFormatted?: string;
  attackerBodyFormatted?: string;
  maskedFields: Record<string, string>;
  leakedFieldNames: string[];
}
