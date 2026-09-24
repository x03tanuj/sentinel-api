import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertCircle, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(_error: Error, _errorInfo: ErrorInfo) {
    // In production or tests, do not log sensitive data
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-canvas-base flex items-center justify-center p-6 text-center">
          <div className="p-8 rounded-panel bg-canvas-panel border border-severity-critical/50 max-w-lg w-full space-y-4">
            <div className="w-12 h-12 rounded-full bg-severity-critical/10 border border-severity-critical/30 flex items-center justify-center text-severity-critical mx-auto">
              <AlertCircle size={24} />
            </div>

            <h1 className="font-sans text-xl font-bold text-slate-100">
              Application Error Encountered
            </h1>

            <p className="font-mono text-xs text-slate-400 bg-canvas-base p-3 rounded border border-border-structural break-words text-left">
              {this.state.error?.message || 'An unexpected client error occurred.'}
            </p>

            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.href = '/';
              }}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-tactical bg-brand text-canvas-base font-semibold text-xs hover:bg-brand-hover transition-all"
            >
              <RotateCcw size={14} />
              <span>Reload Application</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
