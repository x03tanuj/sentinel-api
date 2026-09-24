import type { Finding } from '../../types';

export const sampleFindingFullBodies: Finding = {
  id: 'finding-bola-101',
  check: 'bola',
  endpoint: '/orders/{id}',
  method: 'GET',
  title: 'BOLA in Order Resource Access',
  severity: 'CRITICAL',
  confidence: 0.95,
  explanation: "Endpoint /orders/{id} fails to validate caller ownership. Attacker 'userB' successfully retrieved order 101 owned by 'userA'.",
  curl_poc: 'curl -X GET "http://target_api:9000/orders/101" -H "Authorization: Bearer $TOKEN"',
  fix_hint: 'Enforce object ownership verification: check req.user_id == order.owner_id before returning data.',
  owasp_id: 'API1:2023',
  evidence: {
    identity: 'userB',
    object_id: '101',
    expected_status: 403,
    actual_status: 200,
    request: {
      method: 'GET',
      url: 'http://target_api:9000/orders/101',
      headers: { 'X-Requested-By': 'userB' },
      body: null,
    },
    baseline_response: {
      status_code: 200,
      headers: { 'Content-Type': 'application/json', 'x-persona': 'userA' },
      body: {
        id: 101,
        owner: 'userA',
        item: 'Standard Package',
        amount: 49.99,
      },
    },
    attack_response: {
      status_code: 200,
      headers: { 'Content-Type': 'application/json' },
      body: {
        id: 101,
        owner: 'userA',
        item: 'Standard Package',
        ssn: '44*******66',
        credit_card: '44*******66',
      },
    },
    response_diff: {
      status_divergence: true,
      masked_sensitive_values: {
        ssn: '44*******66',
        credit_card: '44*******66',
      },
      sensitive_fields_exposed: {
        CRITICAL: ['ssn', 'credit_card'],
      },
      risk_score: 88,
      risk_breakdown: {
        impact: 35,
        exploitability: 22,
        data_sensitivity: 21,
        evidence_strength: 10,
      },
      reproduction: {
        reproduced: true,
        attempts: 2,
        downgraded: false,
      },
      affected_objects: ['101', '102', '103', '104'],
    },
  },
};

export const sampleFindingFieldListOnly: Finding = {
  id: 'finding-data-exposure-1',
  check: 'data_exposure',
  endpoint: '/users/{id}',
  method: 'GET',
  title: 'Excessive Data Exposure in User Profile',
  severity: 'MEDIUM',
  confidence: 0.85,
  explanation: 'User profile endpoint exposes masked sensitive attributes.',
  curl_poc: 'curl -X GET "http://target_api:9000/users/1" -H "Authorization: Bearer $TOKEN"',
  fix_hint: 'Filter outgoing fields through a schema DTO.',
  owasp_id: 'API3:2023',
  evidence: {
    identity: 'userB',
    object_id: '1',
    expected_status: 200,
    actual_status: 200,
    request: {
      method: 'GET',
      url: 'http://target_api:9000/users/1',
      headers: {},
      body: null,
    },
    // No baseline or attack bodies stored
    baseline_response: null,
    attack_response: {
      status_code: 200,
      headers: {},
      body: null,
    },
    response_diff: {
      status_divergence: false,
      masked_sensitive_values: {
        email: 'us*******om',
        phone: '11*******99',
      },
      sensitive_fields_exposed: {
        MEDIUM: ['email', 'phone'],
      },
      risk_score: 45,
      // No risk breakdown components provided
    },
  },
};
