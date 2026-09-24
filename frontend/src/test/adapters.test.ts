import { describe, it, expect } from 'vitest';
import {
  evidenceToDiffModel,
  riskBreakdown,
  reproductionInfo,
  matrixCells,
  summaryCards,
} from '../lib/adapters';
import {
  compareSeverity,
  formatDuration,
  hostFromUrl,
  maskDisplay,
} from '../lib/formatters';
import {
  sampleFindingFullBodies,
  sampleFindingFieldListOnly,
} from './fixtures/sampleFinding';
import type { MatrixResponse, ScanSummary } from '../types';

describe('Adapters & Forensics Selectors', () => {
  describe('evidenceToDiffModel', () => {
    it('normalizes finding with full JSON bodies into full_bodies DiffModel', () => {
      const model = evidenceToDiffModel(sampleFindingFullBodies);
      expect(model).not.toBeNull();
      expect(model?.mode).toBe('full_bodies');
      expect(model?.ownerIdentity).toBe('userA');
      expect(model?.attackerIdentity).toBe('userB');
      expect(model?.ownerStatus).toBe(200);
      expect(model?.attackerStatus).toBe(200);
      expect(model?.expectedStatus).toBe(403);
      expect(model?.statusDivergence).toBe(true);
      expect(model?.ownerBodyFormatted).toContain('"Standard Package"');
      expect(model?.attackerBodyFormatted).toContain('"ssn": "44*******66"');
      expect(model?.maskedFields['ssn']).toBe('44*******66');
      expect(model?.leakedFieldNames).toContain('ssn');
      expect(model?.leakedFieldNames).toContain('credit_card');
    });

    it('normalizes finding with only field names into field_list DiffModel', () => {
      const model = evidenceToDiffModel(sampleFindingFieldListOnly);
      expect(model).not.toBeNull();
      expect(model?.mode).toBe('field_list');
      expect(model?.attackerIdentity).toBe('userB');
      expect(model?.ownerBodyFormatted).toBeUndefined();
      expect(model?.maskedFields['email']).toBe('us*******om');
      expect(model?.leakedFieldNames).toContain('email');
      expect(model?.leakedFieldNames).toContain('phone');
    });

    it('returns null if finding has no evidence', () => {
      const emptyFinding = { ...sampleFindingFullBodies, evidence: null };
      expect(evidenceToDiffModel(emptyFinding)).toBeNull();
    });
  });

  describe('riskBreakdown', () => {
    it('extracts all four component risk bars when present', () => {
      const result = riskBreakdown(sampleFindingFullBodies);
      expect(result.hasBreakdown).toBe(true);
      expect(result.score).toBe(88);
      expect(result.breakdown?.impact).toBe(35);
      expect(result.breakdown?.exploitability).toBe(22);
      expect(result.breakdown?.data_sensitivity).toBe(21);
      expect(result.breakdown?.evidence_strength).toBe(10);
    });

    it('falls back gracefully without inventing bars when breakdown is absent', () => {
      const result = riskBreakdown(sampleFindingFieldListOnly);
      expect(result.hasBreakdown).toBe(false);
      expect(result.score).toBe(45);
      expect(result.breakdown).toBeUndefined();
    });
  });

  describe('reproductionInfo', () => {
    it('extracts reproduction status and affected objects', () => {
      const repro = reproductionInfo(sampleFindingFullBodies);
      expect(repro.reproduced).toBe(true);
      expect(repro.attempts).toBe(2);
      expect(repro.downgraded).toBe(false);
      expect(repro.affectedObjects).toEqual(['101', '102', '103', '104']);
    });
  });

  describe('matrixCells', () => {
    const mockMatrix: MatrixResponse = {
      cells: [
        {
          resource: 'orders',
          object_id: '101',
          owner: 'userA',
          identity: 'userA',
          expected_outcome: 'ALLOW',
          actual_status: 200,
        },
        {
          resource: 'orders',
          object_id: '101',
          owner: 'userA',
          identity: 'userB',
          expected_outcome: 'DENY',
          actual_status: 200,
        },
        {
          resource: 'orders',
          object_id: '101',
          owner: 'userA',
          identity: 'admin',
          expected_outcome: 'ALLOW',
          actual_status: 200,
        },
        {
          resource: 'orders',
          object_id: '101',
          owner: 'userA',
          identity: 'anonymous',
          expected_outcome: 'DENY',
          actual_status: 401,
        },
      ],
      summary: {
        total_cells: 4,
        expected_denials: 2,
        authorized_access: 1,
        violations: 1,
      },
    };

    it('produces VIOLATION state when a finding proves unauthorized access', () => {
      const merged = matrixCells(mockMatrix, [sampleFindingFullBodies]);
      expect(merged).toHaveLength(4);

      const ownerCell = merged.find((c) => c.identity === 'userA');
      expect(ownerCell?.state).toBe('owns');

      const adminCell = merged.find((c) => c.identity === 'admin');
      expect(adminCell?.state).toBe('allowed-by-role');

      const attackerCell = merged.find((c) => c.identity === 'userB');
      expect(attackerCell?.state).toBe('violation');
      expect(attackerCell?.findingId).toBe('finding-bola-101');

      const anonCell = merged.find((c) => c.identity === 'anonymous');
      expect(anonCell?.state).toBe('denied-as-expected');
    });
  });

  describe('summaryCards', () => {
    it('detects verified_controls when provided by backend', () => {
      const summary: ScanSummary = {
        scan_id: 'scan-1',
        status: 'COMPLETED',
        target_url: 'http://target_api:9000',
        spec_source: 'openapi.json',
        started_at: '2026-09-24T18:00:00Z',
        duration_seconds: 45,
        total_findings: 3,
        critical: 1,
        high: 1,
        medium: 1,
        low: 0,
        info: 0,
        endpoints_audited: 12,
        verified_controls: 14,
      };

      const hud = summaryCards(summary);
      expect(hud.endpointsAudited).toBe(12);
      expect(hud.critical).toBe(1);
      expect(hud.hasVerifiedControls).toBe(true);
      expect(hud.verifiedControls).toBe(14);
    });

    it('gracefully marks verified_controls as missing gap when absent', () => {
      const summaryWithoutGap: ScanSummary = {
        scan_id: 'scan-2',
        status: 'COMPLETED',
        target_url: 'http://target_api:9000',
        spec_source: 'openapi.json',
        started_at: '2026-09-24T18:00:00Z',
        duration_seconds: 30,
        total_findings: 1,
        critical: 0,
        high: 0,
        medium: 1,
        low: 0,
        info: 0,
      };

      const hud = summaryCards(summaryWithoutGap);
      expect(hud.hasVerifiedControls).toBe(false);
      expect(hud.verifiedControls).toBeUndefined();
    });
  });

  describe('Severity and Formatters', () => {
    it('correctly ranks severity levels in descending threat order', () => {
      expect(compareSeverity('CRITICAL', 'HIGH')).toBeLessThan(0);
      expect(compareSeverity('HIGH', 'MEDIUM')).toBeLessThan(0);
      expect(compareSeverity('MEDIUM', 'LOW')).toBeLessThan(0);
      expect(compareSeverity('LOW', 'INFO')).toBeLessThan(0);
    });

    it('formats duration cleanly', () => {
      expect(formatDuration(45)).toBe('45s');
      expect(formatDuration(125)).toBe('2m 5s');
      expect(formatDuration(3665)).toBe('1h 1m');
    });

    it('extracts host from url', () => {
      expect(hostFromUrl('http://target_api:9000/api/v1')).toBe('target_api:9000');
      expect(hostFromUrl('https://example.com/spec.json')).toBe('example.com');
    });

    it('displays masked values as provided by the API without attempting re-masking', () => {
      expect(maskDisplay('44*******66')).toBe('44*******66');
      expect(maskDisplay(123)).toBe('123');
    });
  });
});
