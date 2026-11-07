import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Copy, Check, ShieldAlert } from 'lucide-react';
import { copyText } from '../utils/clipboard';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  copied: boolean;
  copyFailed: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      copied: false,
      copyFailed: false,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });
    // In production, send to remote telemetry endpoint
    console.error('[BA Threat Intel Enterprise ErrorBoundary]', error, errorInfo);
  }

  handleCopyDiagnostics = async () => {
    const diagnosticPayload = {
      timestamp: new Date().toISOString(),
      error: this.state.error?.toString(),
      stack: this.state.error?.stack,
      componentStack: this.state.errorInfo?.componentStack,
      userAgent: navigator.userAgent,
    };

    const copied = await copyText(JSON.stringify(diagnosticPayload, null, 2));
    this.setState({ copied, copyFailed: !copied });
    setTimeout(() => this.setState({ copied: false, copyFailed: false }), 2500);
  };

  handleResetState = () => {
    try {
      localStorage.removeItem('vulnstream_watchlist');
      localStorage.removeItem('vulnstream_feeds');
      localStorage.removeItem('vulnstream_recipients');
      localStorage.removeItem('vulnstream_settings');
      localStorage.removeItem('vulnstream_template_custom');
    } catch {
      // ignore
    }
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center p-6 selection:bg-red-900/50">
          <div className="max-w-xl w-full bg-zinc-900/90 border border-zinc-800 rounded-2xl p-6 shadow-2xl backdrop-blur-sm">
            <div className="flex items-center space-x-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-zinc-100">Platform Runtime Exception Guard</h2>
                <p className="text-xs text-zinc-400 font-mono">Autonomous Execution Fail-Safe Triggered</p>
              </div>
            </div>

            <p className="text-xs text-zinc-300 leading-relaxed mb-4">
              An unexpected component error occurred. BA Threat Intel isolated the execution tree to prevent state
              corruption. You can copy diagnostics for SecOps engineering or reload the runtime.
            </p>

            {this.state.error && (
              <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-3 mb-4 font-mono text-xs text-red-400 overflow-x-auto max-h-36">
                <div className="font-bold mb-1">
                  {this.state.error.name}: {this.state.error.message}
                </div>
                {this.state.errorInfo?.componentStack && (
                  <pre className="text-[10px] text-zinc-500 whitespace-pre-wrap">
                    {this.state.errorInfo.componentStack}
                  </pre>
                )}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 rounded-xl bg-zinc-100 hover:bg-white text-zinc-900 font-medium text-xs flex items-center space-x-1.5 transition shadow-sm"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reload Application</span>
              </button>

              <button
                onClick={this.handleCopyDiagnostics}
                className="px-4 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 text-xs flex items-center space-x-1.5 transition"
              >
                {this.state.copied ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>
                  {this.state.copied
                    ? 'Diagnostics Copied'
                    : this.state.copyFailed
                      ? 'Copy failed; select details above'
                      : 'Copy Diagnostics'}
                </span>
              </button>

              <button
                onClick={this.handleResetState}
                className="px-3 py-2 rounded-xl bg-red-950/40 hover:bg-red-900/50 text-red-300 border border-red-800/40 text-xs transition ml-auto"
              >
                Reset Local Cache
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
