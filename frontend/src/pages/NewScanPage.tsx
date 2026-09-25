import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useCreateScan, useAiStatus } from '../api/hooks';
import { Header } from '../components/common/Header';
import { ApiError } from '../api/client';
import {
  Shield,
  Play,
  Plus,
  Trash2,
  AlertTriangle,
  Lock,
  Sparkles,
} from 'lucide-react';

interface IdentityFormState {
  id: string;
  name: string;
  role: string;
  username: string;
  password?: string;
}

const STORAGE_KEY_NON_SECRET = 'sentinelapi_new_scan_config';

export const NewScanPage: React.FC = () => {
  const navigate = useNavigate();
  const createScanMutation = useCreateScan();
  const { data: aiStatus } = useAiStatus();
  const [useAiHints, setUseAiHints] = useState(false);

  // Mode: 'url' | 'json'
  const [specMode, setSpecMode] = useState<'url' | 'json'>('url');
  const [specUrl, setSpecUrl] = useState('http://target_api:9000/openapi.json');
  const [specJson, setSpecJson] = useState('');
  const [baseUrl, setBaseUrl] = useState('http://target_api:9000');

  // Identities (1 to 5)
  const [identities, setIdentities] = useState<IdentityFormState[]>([
    { id: '1', name: 'userA', role: 'user', username: 'user_a', password: '' },
    { id: '2', name: 'userB', role: 'user', username: 'user_b', password: '' },
    { id: '3', name: 'admin', role: 'admin', username: 'admin_user', password: '' },
  ]);

  // Check Suites
  const [enabledChecks, setEnabledChecks] = useState<Record<string, boolean>>({
    bola: true,
    bfla: true,
    data_exposure: true,
    rate_limit: true,
    unauth_access: true,
    input_handling: true,
  });

  // Budgets
  const [testCaseBudget, setTestCaseBudget] = useState(150);
  const [maxRequests, setMaxRequests] = useState(300);

  // Sample body
  const [sampleBodyJson, setSampleBodyJson] = useState('');

  // Authorization gate
  const [isAuthorized, setIsAuthorized] = useState(false);

  // Demo preset active
  const [isDemoPresetActive, setIsDemoPresetActive] = useState(false);

  // Errors & Feedback
  const [validationError, setValidationError] = useState<string | null>(null);
  const [serverError, setServerError] = useState<string | null>(null);
  const [retryAfterSeconds, setRetryAfterSeconds] = useState<number | null>(null);

  // Load non-secret settings on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY_NON_SECRET);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.baseUrl) setBaseUrl(parsed.baseUrl);
        if (parsed.specUrl) setSpecUrl(parsed.specUrl);
        if (parsed.testCaseBudget) setTestCaseBudget(parsed.testCaseBudget);
        if (parsed.maxRequests) setMaxRequests(parsed.maxRequests);
        if (parsed.enabledChecks) setEnabledChecks(parsed.enabledChecks);
        if (Array.isArray(parsed.identityMeta)) {
          setIdentities(
            parsed.identityMeta.map((im: { name: string; role: string }, idx: number) => ({
              id: String(idx + 1),
              name: im.name,
              role: im.role,
              username: '',
              password: '',
            }))
          );
        }
      }
    } catch {
      // Ignore localStorage errors
    }
  }, []);

  // Save non-secret settings on change
  const saveNonSecretConfig = () => {
    try {
      const toSave = {
        baseUrl,
        specUrl: specMode === 'url' ? specUrl : undefined,
        testCaseBudget,
        maxRequests,
        enabledChecks,
        identityMeta: identities.map((i) => ({ name: i.name, role: i.role })),
      };
      localStorage.setItem(STORAGE_KEY_NON_SECRET, JSON.stringify(toSave));
    } catch {
      // Ignore
    }
  };

  const [activePreset, setActivePreset] = useState<'ecommerce' | 'healthcare' | 'fintech' | 'secure' | null>(null);

  // Load target presets (e-commerce, healthcare, fintech, secure)
  const handleSelectPreset = (preset: 'ecommerce' | 'healthcare' | 'fintech' | 'secure') => {
    setActivePreset(preset);
    setSpecMode('url');
    setIsAuthorized(true);
    setIsDemoPresetActive(true);
    setValidationError(null);
    setServerError(null);

    if (preset === 'ecommerce') {
      setSpecUrl('http://target_api:9000/openapi.json');
      setBaseUrl('http://target_api:9000');
      setIdentities([
        { id: '1', name: 'userA', role: 'user', username: 'userA', password: 'passA123' },
        { id: '2', name: 'userB', role: 'user', username: 'userB', password: 'passB123' },
        { id: '3', name: 'admin', role: 'admin', username: 'admin', password: 'admin123' },
      ]);
      setSampleBodyJson('{\n  "item": "Standard Package",\n  "amount": 49.99\n}');
    } else if (preset === 'healthcare') {
      setSpecUrl('http://health_api:9001/openapi.json');
      setBaseUrl('http://health_api:9001');
      setIdentities([
        { id: '1', name: 'patientA', role: 'patient', username: 'patientA', password: 'passA123' },
        { id: '2', name: 'patientB', role: 'patient', username: 'patientB', password: 'passB123' },
        { id: '3', name: 'dr_smith', role: 'admin', username: 'dr_smith', password: 'doctor123' },
      ]);
      setSampleBodyJson('{\n  "notes": "Follow-up consultation notes",\n  "diagnosis": "Sinus Bradycardia"\n}');
    } else if (preset === 'fintech') {
      setSpecUrl('http://fintech_api:9002/openapi.json');
      setBaseUrl('http://fintech_api:9002');
      setIdentities([
        { id: '1', name: 'clientA', role: 'user', username: 'clientA', password: 'passA123' },
        { id: '2', name: 'clientB', role: 'user', username: 'clientB', password: 'passB123' },
        { id: '3', name: 'auditor', role: 'admin', username: 'auditor', password: 'audit123' },
      ]);
      setSampleBodyJson('{\n  "recipient_name": "Cloud Infrastructure LLC",\n  "amount": 1250.00\n}');
    } else if (preset === 'secure') {
      setSpecUrl('http://secure_api:9003/openapi.json');
      setBaseUrl('http://secure_api:9003');
      setIdentities([
        { id: '1', name: 'userA', role: 'user', username: 'userA', password: 'passA123' },
        { id: '2', name: 'userB', role: 'user', username: 'userB', password: 'passB123' },
        { id: '3', name: 'secadmin', role: 'admin', username: 'secadmin', password: 'admin123' },
      ]);
      setSampleBodyJson('{\n  "title": "Encrypted Security Policy",\n  "content": "Zero-trust verification strictly active."\n}');
    }
  };

  const handleLoadDemoTarget = () => handleSelectPreset('ecommerce');

  // Identity management
  const handleAddIdentity = () => {
    if (identities.length >= 5) return;
    const newIdx = identities.length + 1;
    setIdentities([
      ...identities,
      {
        id: String(Date.now()),
        name: `user${newIdx}`,
        role: 'user',
        username: `user_${newIdx}`,
        password: '',
      },
    ]);
  };

  const handleRemoveIdentity = (id: string) => {
    if (identities.length <= 1) return;
    setIdentities(identities.filter((i) => i.id !== id));
  };

  const handleUpdateIdentity = (id: string, field: keyof IdentityFormState, value: string) => {
    setIdentities(
      identities.map((item) => (item.id === id ? { ...item, [field]: value } : item))
    );
  };

  // Form Validation
  const validateForm = (): boolean => {
    setValidationError(null);

    if (!baseUrl.trim()) {
      setValidationError('Base Target URL is required.');
      return false;
    }

    if (specMode === 'url' && !specUrl.trim()) {
      setValidationError('Target Specification URL is required.');
      return false;
    }

    if (specMode === 'json' && !specJson.trim()) {
      setValidationError('Pasted OpenAPI JSON schema is required.');
      return false;
    }

    // Validate identity names
    const names = new Set<string>();
    const nameRegex = /^[A-Za-z0-9_-]{1,32}$/;
    for (const id of identities) {
      if (!nameRegex.test(id.name)) {
        setValidationError(
          `Identity name "${id.name}" is invalid. Must be alphanumeric (1-32 chars).`
        );
        return false;
      }
      if (id.name.toLowerCase() === 'anonymous') {
        setValidationError('Identity name "anonymous" is reserved by the engine.');
        return false;
      }
      if (names.has(id.name)) {
        setValidationError(`Duplicate identity name "${id.name}" detected.`);
        return false;
      }
      names.add(id.name);

      if (!id.username.trim()) {
        setValidationError(`Username required for identity "${id.name}".`);
        return false;
      }
      if (!id.password?.trim()) {
        setValidationError(`Password required for identity "${id.name}".`);
        return false;
      }
    }

    // Validate sample body if provided
    if (sampleBodyJson.trim()) {
      if (sampleBodyJson.length > 20480) {
        setValidationError('Sample body exceeds maximum allowed size of 20 KB.');
        return false;
      }
      try {
        JSON.parse(sampleBodyJson);
      } catch {
        setValidationError('Sample body is not valid JSON.');
        return false;
      }
    }

    if (!isAuthorized) {
      setValidationError('You must confirm authorization before initiating a scan.');
      return false;
    }

    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;

    setServerError(null);
    setRetryAfterSeconds(null);

    // Save non-secret items to localStorage
    saveNonSecretConfig();

    let sampleBodiesPayload: Record<string, unknown> | undefined;
    if (sampleBodyJson.trim()) {
      try {
        sampleBodiesPayload = { default: JSON.parse(sampleBodyJson) };
      } catch {
        // Handled in validation
      }
    }

    let specInlinePayload: Record<string, unknown> | null = null;
    if (specMode === 'json' && specJson.trim()) {
      try {
        specInlinePayload = JSON.parse(specJson.trim());
      } catch {
        // Handled in validation
      }
    }

    const payload = {
      base_url: baseUrl.trim(),
      spec_url: specMode === 'url' && specUrl.trim() ? specUrl.trim() : null,
      spec_inline: specInlinePayload,
      identities: identities.map((i) => ({
        name: i.name.trim(),
        role: i.role.trim(),
        username: i.username.trim(),
        password: i.password?.trim(),
      })),
      enabled_checks: Object.entries(enabledChecks)
        .filter(([_, active]) => active)
        .map(([name]) => name),
      test_case_budget: testCaseBudget,
      max_requests: maxRequests,
      use_ai_hints: useAiHints,
      sample_bodies: sampleBodiesPayload,
    };

    try {
      const result = await createScanMutation.mutateAsync(payload as any);

      // SECURITY RULE: Clear passwords from component state immediately after submit
      setIdentities((prev) =>
        prev.map((i) => ({
          ...i,
          password: '',
        }))
      );

      const scanId = (result as any).scan_id;
      navigate(`/scans/${scanId}/live`);
    } catch (err: unknown) {
      const apiErr = err as ApiError;
      setServerError(apiErr.message || 'Failed to submit scan');
      if (apiErr.retryAfter) {
        setRetryAfterSeconds(apiErr.retryAfter);
      }
    }
  };

  return (
    <div className="min-h-screen bg-canvas-base flex flex-col">
      <Header />

      <main className="flex-1 max-w-4xl w-full mx-auto p-4 sm:p-6 space-y-6">
        {/* Title & Scope Guard */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs uppercase tracking-wider text-slate-400">
                  Audit Setup // Target Orchestration
                </span>
                <span className="px-1.5 py-0.5 rounded bg-brand/10 border border-brand/30 text-brand font-mono text-[10px]">
                  v2.4
                </span>
              </div>
              <h1 className="font-sans text-2xl font-bold text-slate-100 tracking-tight mt-1">
                Configure &amp; Launch Security Audit
              </h1>
              <p className="font-sans text-xs text-slate-400">
                Set target schema, multi-persona authorization matrix, test suites, and execution limits
              </p>
            </div>

            {/* Target Presets Bar */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleLoadDemoTarget}
                aria-label="Load demo target"
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical font-mono text-xs font-semibold transition-all ${
                  activePreset === 'ecommerce' || (!activePreset && isDemoPresetActive)
                    ? 'bg-brand/30 border border-brand text-brand ring-1 ring-brand'
                    : 'bg-brand/10 border border-brand/40 text-brand hover:bg-brand/20'
                }`}
              >
                <Sparkles size={14} />
                <span>🛒 Target 1: E-Commerce (:9000)</span>
              </button>

              <button
                type="button"
                onClick={() => handleSelectPreset('healthcare')}
                aria-label="Load Healthcare target"
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical font-mono text-xs font-semibold transition-all ${
                  activePreset === 'healthcare'
                    ? 'bg-teal-500/30 border border-teal-400 text-teal-300 ring-1 ring-teal-400'
                    : 'bg-teal-500/10 border border-teal-500/40 text-teal-300 hover:bg-teal-500/20'
                }`}
              >
                <span>🏥 Target 2: Healthcare (:9001)</span>
              </button>

              <button
                type="button"
                onClick={() => handleSelectPreset('fintech')}
                aria-label="Load FinTech target"
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical font-mono text-xs font-semibold transition-all ${
                  activePreset === 'fintech'
                    ? 'bg-emerald-500/30 border border-emerald-400 text-emerald-300 ring-1 ring-emerald-400'
                    : 'bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/20'
                }`}
              >
                <span>💳 Target 3: FinTech Banking (:9002)</span>
              </button>

              <button
                type="button"
                onClick={() => handleSelectPreset('secure')}
                aria-label="Load Zero-Trust target"
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical font-mono text-xs font-semibold transition-all ${
                  activePreset === 'secure'
                    ? 'bg-indigo-500/30 border border-indigo-400 text-indigo-300 ring-1 ring-indigo-400'
                    : 'bg-indigo-500/10 border border-indigo-500/40 text-indigo-300 hover:bg-indigo-500/20'
                }`}
              >
                <span>🛡️ Target 4: Zero-Trust (:9003 - Clean)</span>
              </button>
            </div>
          </div>

          {/* Scope Guard Alert */}
          <div className="p-3 rounded-panel bg-amber-500/10 border border-amber-500/30 flex items-start gap-2.5">
            <Shield size={16} className="text-amber-400 shrink-0 mt-0.5" />
            <div className="font-mono text-xs text-amber-200">
              <strong className="text-amber-300">LIVE LOCAL TESTING TARGETS:</strong> Audit ready on isolated sandbox ports:
              <span className="text-brand"> :9000 (E-Commerce)</span>,{' '}
              <span className="text-teal-300">:9001 (Healthcare)</span>,{' '}
              <span className="text-emerald-300">:9002 (FinTech)</span>, and{' '}
              <span className="text-indigo-300">:9003 (Hardened Zero-Trust)</span>.
            </div>
          </div>
        </div>

        {/* Form Container */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* SECTION 01: Target Specification */}
          <div className="p-5 rounded-panel bg-canvas-panel border border-border-structural space-y-4">
            <div className="flex items-center justify-between border-b border-border-subdued pb-2.5">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-brand font-semibold">01 //</span>
                <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Target Specification
                </h2>
              </div>

              <div className="flex items-center gap-1 p-0.5 rounded-tactical bg-canvas-base border border-border-structural text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setSpecMode('url')}
                  className={`px-2 py-0.5 rounded transition-colors ${
                    specMode === 'url' ? 'bg-canvas-elevated text-brand font-semibold' : 'text-slate-400'
                  }`}
                >
                  OpenAPI Spec URL
                </button>
                <button
                  type="button"
                  onClick={() => setSpecMode('json')}
                  className={`px-2 py-0.5 rounded transition-colors ${
                    specMode === 'json' ? 'bg-canvas-elevated text-brand font-semibold' : 'text-slate-400'
                  }`}
                >
                  Paste OpenAPI JSON
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {specMode === 'url' ? (
                <div className="space-y-1">
                  <label htmlFor="target-spec-url" className="font-mono text-xs text-slate-300">
                    Target Spec URL:
                  </label>
                  <input
                    id="target-spec-url"
                    type="text"
                    value={specUrl}
                    onChange={(e) => setSpecUrl(e.target.value)}
                    placeholder="http://target_api:9000/openapi.json"
                    className="w-full px-3 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-100 font-mono text-xs focus:outline-none focus:border-brand"
                  />
                </div>
              ) : (
                <div className="md:col-span-2 space-y-1">
                  <label htmlFor="target-spec-json" className="font-mono text-xs text-slate-300">
                    Paste OpenAPI JSON Schema:
                  </label>
                  <textarea
                    id="target-spec-json"
                    rows={4}
                    value={specJson}
                    onChange={(e) => setSpecJson(e.target.value)}
                    placeholder='{"openapi": "3.0.0", "info": ...}'
                    className="w-full px-3 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-100 font-mono text-xs focus:outline-none focus:border-brand"
                  />
                </div>
              )}

              <div className="space-y-1">
                <label htmlFor="base-target-url" className="font-mono text-xs text-slate-300">
                  Base Target URL:
                </label>
                <input
                  id="base-target-url"
                  type="text"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder="http://target_api:9000"
                  className="w-full px-3 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-100 font-mono text-xs focus:outline-none focus:border-brand"
                />
              </div>
            </div>
          </div>

          {/* SECTION 02: Multi-Tenant & Persona Auth Matrix */}
          <div className="p-5 rounded-panel bg-canvas-panel border border-border-structural space-y-4">
            <div className="flex items-center justify-between border-b border-border-subdued pb-2.5">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-brand font-semibold">02 //</span>
                <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Multi-Tenant &amp; Persona Auth Matrix
                </h2>
              </div>
              <span className="font-mono text-[11px] text-slate-400">
                {identities.length} of 5 personas configured
              </span>
            </div>

            <div className="text-xs text-slate-400 font-mono flex items-center gap-2">
              <Lock size={12} className="text-brand shrink-0" />
              <span>
                Passwords are never stored on disk or logged; enter credentials per scan session.
              </span>
            </div>

            <div className="space-y-3">
              {identities.map((item) => (
                <div
                  key={item.id}
                  className="grid grid-cols-1 sm:grid-cols-12 gap-2 p-2.5 rounded-tactical bg-canvas-base border border-border-structural items-center"
                >
                  <div className="sm:col-span-3">
                    <label className="sr-only" htmlFor={`persona-name-${item.id}`}>Persona Name</label>
                    <input
                      id={`persona-name-${item.id}`}
                      type="text"
                      aria-label={`Persona name ${item.name}`}
                      value={item.name}
                      onChange={(e) => handleUpdateIdentity(item.id, 'name', e.target.value)}
                      placeholder="Name (e.g. userA)"
                      className="w-full px-2.5 py-1 rounded bg-canvas-elevated border border-border-subdued text-slate-100 font-mono text-xs focus:outline-none focus:border-brand"
                    />
                  </div>

                  <div className="sm:col-span-2">
                    <label className="sr-only" htmlFor={`persona-role-${item.id}`}>Role</label>
                    <select
                      id={`persona-role-${item.id}`}
                      aria-label={`Role for persona ${item.name}`}
                      value={item.role}
                      onChange={(e) => handleUpdateIdentity(item.id, 'role', e.target.value)}
                      className="w-full px-2 py-1 rounded bg-canvas-elevated border border-border-subdued text-slate-200 font-mono text-xs focus:outline-none focus:border-brand"
                    >
                      <option value="user">USER</option>
                      <option value="admin">ADMIN</option>
                    </select>
                  </div>

                  <div className="sm:col-span-3">
                    <label className="sr-only" htmlFor={`persona-username-${item.id}`}>Username</label>
                    <input
                      id={`persona-username-${item.id}`}
                      type="text"
                      aria-label={`Username for persona ${item.name}`}
                      value={item.username}
                      onChange={(e) => handleUpdateIdentity(item.id, 'username', e.target.value)}
                      placeholder="Username"
                      className="w-full px-2.5 py-1 rounded bg-canvas-elevated border border-border-subdued text-slate-100 font-mono text-xs focus:outline-none focus:border-brand"
                    />
                  </div>

                  <div className="sm:col-span-3">
                    <label className="sr-only" htmlFor={`persona-password-${item.id}`}>Password</label>
                    <input
                      id={`persona-password-${item.id}`}
                      type="password"
                      autoComplete="off"
                      aria-label={`Password for persona ${item.name}`}
                      value={item.password || ''}
                      onChange={(e) => handleUpdateIdentity(item.id, 'password', e.target.value)}
                      placeholder="Password"
                      className="w-full px-2.5 py-1 rounded bg-canvas-elevated border border-border-subdued text-slate-100 font-mono text-xs focus:outline-none focus:border-brand"
                    />
                  </div>

                  <div className="sm:col-span-1 flex justify-end">
                    {identities.length > 1 && (
                      <button
                        type="button"
                        onClick={() => handleRemoveIdentity(item.id)}
                        className="p-1 text-slate-400 hover:text-severity-critical"
                        aria-label={`Remove identity ${item.name}`}
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                </div>
              ))}

              {identities.length < 5 && (
                <button
                  type="button"
                  onClick={handleAddIdentity}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical border border-border-structural bg-canvas-base text-slate-300 font-mono text-xs hover:bg-canvas-elevated"
                >
                  <Plus size={13} />
                  <span>Add Identity Row</span>
                </button>
              )}
            </div>
          </div>

          {/* SECTION 03: Check Suite Selection */}
          <div className="p-5 rounded-panel bg-canvas-panel border border-border-structural space-y-4">
            <div className="flex items-center justify-between border-b border-border-subdued pb-2.5">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-brand font-semibold">03 //</span>
                <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Check Suite Selection
                </h2>
              </div>
              <span className="font-mono text-[11px] text-slate-400">
                {Object.values(enabledChecks).filter(Boolean).length} of 6 active
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {[
                { id: 'bola', name: 'BOLA (Broken Object Level Auth)', desc: 'Validates unauthorized cross-user object access' },
                { id: 'bfla', name: 'Function-Level Auth (BFLA)', desc: 'Tests unauthorized access to administrative endpoints' },
                { id: 'data_exposure', name: 'Data Exposure', desc: 'Detects PII, secrets, and excessive object attributes' },
                { id: 'rate_limit', name: 'Rate Limiting', desc: 'Validates burst protection and 429 throttling headers' },
                { id: 'unauth_access', name: 'Unauthenticated Access', desc: 'Probes protected routes without bearer tokens' },
                { id: 'input_handling', name: 'Input Handling', desc: 'Boundary fuzzing and type coercion on parameters' },
              ].map((chk) => (
                <label
                  key={chk.id}
                  className={`p-3 rounded-tactical border flex items-start gap-3 cursor-pointer transition-colors ${
                    enabledChecks[chk.id]
                      ? 'bg-canvas-elevated border-brand/50 text-slate-200'
                      : 'bg-canvas-base border-border-structural text-slate-400'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={!!enabledChecks[chk.id]}
                    onChange={(e) =>
                      setEnabledChecks({ ...enabledChecks, [chk.id]: e.target.checked })
                    }
                    className="mt-0.5 accent-brand"
                  />
                  <div className="space-y-0.5">
                    <span className="font-mono text-xs font-semibold block">{chk.name}</span>
                    <span className="font-sans text-[11px] text-slate-400 block">{chk.desc}</span>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* SECTION 04: Budget & Constraints */}
          <div className="p-5 rounded-panel bg-canvas-panel border border-border-structural space-y-4">
            <div className="flex items-center gap-2 border-b border-border-subdued pb-2.5">
              <span className="font-mono text-xs text-brand font-semibold">04 //</span>
              <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
                Budget &amp; Execution Constraints
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-2">
                <div className="flex justify-between font-mono text-xs">
                  <span className="text-slate-300">Test-Case Budget:</span>
                  <span className="text-brand font-semibold">{testCaseBudget} cases</span>
                </div>
                <input
                  id="test-case-budget-range"
                  aria-label="Test-Case Budget"
                  type="range"
                  min="20"
                  max="300"
                  step="10"
                  value={testCaseBudget}
                  onChange={(e) => setTestCaseBudget(parseInt(e.target.value, 10))}
                  className="w-full accent-brand cursor-pointer"
                />
                <span className="text-[10px] text-slate-400 font-mono block">
                  Capped test plan generated by discovery prioritization
                </span>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between font-mono text-xs">
                  <span className="text-slate-300">Request Ceiling:</span>
                  <span className="text-brand font-semibold">{maxRequests} requests max</span>
                </div>
                <input
                  id="request-ceiling-range"
                  aria-label="Request Ceiling"
                  type="range"
                  min="50"
                  max="600"
                  step="25"
                  value={maxRequests}
                  onChange={(e) => setMaxRequests(parseInt(e.target.value, 10))}
                  className="w-full accent-brand cursor-pointer"
                />
                <span className="text-[10px] text-slate-400 font-mono block">
                  Hard execution engine budget guard
                </span>
              </div>

              {/* Sample Body Editor */}
              <div className="md:col-span-2 space-y-1 pt-2 border-t border-border-subdued">
                <label htmlFor="sample-body-json" className="font-mono text-xs text-slate-300 flex items-center justify-between">
                  <span>Optional Sample Body JSON (used for resource creation tests):</span>
                  <span className="text-[10px] text-slate-400">Max 20 KB</span>
                </label>
                <textarea
                  id="sample-body-json"
                  rows={3}
                  value={sampleBodyJson}
                  onChange={(e) => setSampleBodyJson(e.target.value)}
                  placeholder='{"item": "Sample Item", "amount": 99.99}'
                  className="w-full px-3 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-100 font-mono text-xs focus:outline-none focus:border-brand"
                />
              </div>

              {/* AI Test Hinting (Task 5) */}
              <div className="md:col-span-2 pt-3 border-t border-border-subdued">
                <label
                  className={`flex items-start gap-3 p-3 rounded-tactical border transition-colors ${
                    !aiStatus?.enabled
                      ? 'bg-canvas-base border-border-structural opacity-60 cursor-not-allowed'
                      : useAiHints
                      ? 'bg-canvas-elevated border-purple-500/50 text-slate-200 cursor-pointer'
                      : 'bg-canvas-base border-border-structural text-slate-400 cursor-pointer'
                  }`}
                  title={
                    !aiStatus?.enabled
                      ? 'AI analysis is not configured on this server (requires AI_ENABLED=true and LLM_API_KEY)'
                      : 'Ask the LLM to inspect endpoint metadata and suggest extra boundary test cases'
                  }
                >
                  <input
                    type="checkbox"
                    id="use-ai-hints-checkbox"
                    disabled={!aiStatus?.enabled}
                    checked={useAiHints && !!aiStatus?.enabled}
                    onChange={(e) => setUseAiHints(e.target.checked)}
                    className="mt-0.5 accent-purple-500"
                  />
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-slate-200">
                        Use AI to suggest extra tests (experimental)
                      </span>
                      <span className="px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 text-[10px] font-mono">
                        AI
                      </span>
                    </div>
                    <span className="font-sans text-[11px] text-slate-400 block">
                      Inspects endpoint path templates and metadata to add targeted boundary tests for BOLA and privileged endpoints.
                      {!aiStatus?.enabled && (
                        <span className="text-amber-400 block pt-0.5">
                          (Disabled: AI is not configured on this server)
                        </span>
                      )}
                    </span>
                  </div>
                </label>
              </div>
            </div>
          </div>

          {/* Validation & Server Error Feedback */}
          {validationError && (
            <div className="p-3 rounded-tactical bg-severity-critical/10 border border-severity-critical/40 text-severity-critical text-xs font-mono flex items-center gap-2">
              <AlertTriangle size={14} className="shrink-0" />
              <span>{validationError}</span>
            </div>
          )}

          {serverError && (
            <div className="p-3 rounded-tactical bg-severity-critical/10 border border-severity-critical/40 text-severity-critical text-xs font-mono space-y-1">
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle size={14} className="shrink-0" />
                <span>{serverError}</span>
              </div>
              {retryAfterSeconds && (
                <div className="text-[11px] text-amber-300 pl-6">
                  Retry recommended after: {retryAfterSeconds} seconds
                </div>
              )}
            </div>
          )}

          {/* Authorization Checkbox & Submit */}
          <div className="p-4 rounded-panel bg-canvas-panel border border-border-structural space-y-4">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={isAuthorized}
                onChange={(e) => setIsAuthorized(e.target.checked)}
                className="mt-0.5 accent-brand"
              />
              <span className="font-mono text-xs text-slate-200">
                I confirm that I am authorized to conduct security assessments against this target host.
              </span>
            </label>

            <div className="flex items-center justify-between pt-2 border-t border-border-subdued">
              <Link
                to="/"
                className="px-4 py-2 rounded-tactical border border-border-structural text-slate-400 hover:text-slate-200 font-mono text-xs"
              >
                Cancel
              </Link>

              <button
                type="submit"
                disabled={!isAuthorized || createScanMutation.isPending}
                className={`inline-flex items-center gap-2 px-5 py-2 rounded-tactical font-sans font-semibold text-xs transition-all ${
                  isAuthorized && !createScanMutation.isPending
                    ? 'bg-brand text-canvas-base hover:bg-brand-hover shadow-glow-primary'
                    : 'bg-slate-800 text-slate-400 cursor-not-allowed border border-border-structural'
                }`}
              >
                <Play size={14} fill="currentColor" />
                <span>{createScanMutation.isPending ? 'Launching Audit...' : 'Launch Security Audit'}</span>
              </button>
            </div>
          </div>
        </form>
      </main>
    </div>
  );
};
