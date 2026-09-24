import React, { useState, useEffect } from 'react';
import { getApiKey, setApiKey } from '../../api/auth';
import { Key, Shield, X, Check } from 'lucide-react';

interface SettingsDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SettingsDialog: React.FC<SettingsDialogProps> = ({ isOpen, onClose }) => {
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [savedSuccess, setSavedSuccess] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setApiKeyInput(getApiKey() || '');
      setSavedSuccess(false);
    }
  }, [isOpen]);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setApiKey(apiKeyInput.trim() || null);
    setSavedSuccess(true);
    setTimeout(() => {
      onClose();
    }, 800);
  };

  const handleClear = () => {
    setApiKey(null);
    setApiKeyInput('');
    setSavedSuccess(true);
    setTimeout(() => {
      onClose();
    }, 800);
  };

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="settings-dialog-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4"
    >
      <div className="relative w-full max-w-md p-6 rounded-modal bg-canvas-panel border border-border-structural shadow-2xl space-y-4">
        <button
          onClick={onClose}
          aria-label="Close settings dialog"
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-100 transition-colors"
        >
          <X size={18} />
        </button>

        <div className="flex items-center gap-3">
          <div className="p-2 rounded-tactical bg-brand/10 text-brand border border-brand/30">
            <Key size={18} />
          </div>
          <div>
            <h2 id="settings-dialog-title" className="font-sans text-base font-semibold text-slate-100">
              API Security Settings
            </h2>
            <p className="font-sans text-xs text-slate-400">
              Configure scanner access credentials (X-API-Key)
            </p>
          </div>
        </div>

        <div className="p-3 rounded-tactical bg-canvas-base border border-border-subdued text-xs text-slate-400 flex items-start gap-2">
          <Shield size={14} className="text-brand shrink-0 mt-0.5" />
          <span>
            If the backend was launched with <code className="font-mono text-brand">SENTINEL_API_KEY</code>, enter it below.
            Stored securely in <strong className="text-slate-300">memory and sessionStorage only</strong> (never localStorage).
          </span>
        </div>

        <form onSubmit={handleSave} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="api-key-input" className="font-mono text-xs text-slate-300">
              Sentinel API Key:
            </label>
            <input
              id="api-key-input"
              type="password"
              autoComplete="off"
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              placeholder="e.g. sk_live_..."
              className="w-full px-3 py-2 rounded-tactical bg-canvas-base border border-border-structural text-slate-100 font-mono text-xs focus:outline-none focus:border-brand focus:ring-1 focus:ring-brand"
            />
          </div>

          {savedSuccess && (
            <div className="flex items-center gap-1.5 text-xs font-mono text-severity-secure">
              <Check size={14} />
              <span>API key configuration updated successfully!</span>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <button
              type="button"
              onClick={handleClear}
              className="px-3 py-1.5 rounded-tactical border border-border-structural text-slate-400 hover:text-slate-200 text-xs font-mono"
            >
              Clear Key
            </button>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 rounded-tactical border border-border-structural text-slate-300 hover:bg-canvas-elevated text-xs font-mono"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-tactical bg-brand text-canvas-base font-semibold text-xs font-sans hover:bg-brand-hover shadow-glow-primary"
              >
                Save Settings
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
