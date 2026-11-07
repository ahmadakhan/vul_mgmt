import React, { useState } from 'react';
import { ArrowRight, KeyRound, LoaderCircle, Moon, ShieldCheck, Sun, Mail } from 'lucide-react';
import { useApp } from '../context/AppContext';

type ResetStep = 'username' | 'code' | 'newPassword';

interface LoginViewProps {
  sessionExpired?: boolean;
}

export function LoginView({ sessionExpired = false }: LoginViewProps) {
  const {
    login,
    error,
    pending,
    loading,
    theme,
    toggleTheme,
    requestPasswordReset,
    verifyPasswordReset,
    completePasswordReset,
    clearError,
  } = useApp();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showReset, setShowReset] = useState(false);
  const [resetStep, setResetStep] = useState<ResetStep>('username');
  const [resetUsername, setResetUsername] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [resetError, setResetError] = useState<string | null>(null);
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);

  const startReset = () => {
    setResetError(null);
    setOtpCode('');
    setNewPassword('');
    setDevOtp(null);
    setResetStep('username');
    setShowReset(true);
    clearError();
  };

  const submitResetRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setResetting(true);
    setResetError(null);
    try {
      const result = await requestPasswordReset(resetUsername.trim().toLowerCase());
      if (result?.success) {
        if (result.code) setDevOtp(result.code);
        setResetStep('code');
      } else if (result === undefined) {
        setResetError('Failed to send reset code. Try again.');
      }
    } catch (e) {
      setResetError(e instanceof Error ? e.message : 'Failed to send reset code.');
    } finally {
      setResetting(false);
    }
  };

  const submitOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setResetting(true);
    setResetError(null);
    try {
      const result = await verifyPasswordReset(resetUsername.trim().toLowerCase(), otpCode);
      if (result?.success) {
        setResetStep('newPassword');
      } else if (result === undefined) {
        setResetError('Failed to verify code.');
      }
    } catch (e) {
      setResetError(e instanceof Error ? e.message : 'Invalid or expired code.');
    } finally {
      setResetting(false);
    }
  };

  const submitNewPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setResetting(true);
    setResetError(null);
    try {
      const result = await completePasswordReset(resetUsername.trim().toLowerCase(), otpCode, newPassword);
      if (result?.success) {
        setShowReset(false);
        setResetStep('username');
        setResetUsername('');
        setOtpCode('');
        setNewPassword('');
        setDevOtp(null);
      } else if (result === undefined) {
        setResetError('Failed to reset password.');
      }
    } catch (e) {
      setResetError(e instanceof Error ? e.message : 'Failed to reset password.');
    } finally {
      setResetting(false);
    }
  };

  return (
    <main className={`login-screen ${theme}`}>
      <div className="login-grid" aria-hidden="true" />
      <button
        type="button"
        onClick={toggleTheme}
        className="login-theme-toggle"
        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      >
        {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
      </button>

      <section className="login-card" aria-labelledby="login-heading">
        <div className="login-brand-row">
          <div className="login-brand-mark">
            <ShieldCheck size={23} strokeWidth={1.8} />
          </div>
          <div>
            <div className="login-brand-name">BA Threat Intel</div>
            <div className="login-brand-caption">THREAT INTELLIGENCE OPERATIONS</div>
          </div>
          <span className="login-edition">ENTERPRISE</span>
        </div>

        {!showReset && (
          <>
            <div className="login-heading-block">
              <p className="login-eyebrow">SECURE OPERATOR ACCESS</p>
              <h1 id="login-heading">Welcome back</h1>
              <p className="login-subtitle">
                Sign in to monitor vulnerabilities and manage your response workflow.
              </p>
            </div>

            <form
              className="login-form"
              onSubmit={async (event) => {
                event.preventDefault();
                const success = await login(username.trim(), password);
                if (success) setPassword('');
              }}
            >
              {loading ? (
                <div className="login-connecting" role="status">
                  <LoaderCircle className="animate-spin" size={18} />
                  <span>Connecting to your secure workspace…</span>
                </div>
              ) : (
                <>
                  <label className="login-field">
                    <span>Username</span>
                    <input
                      autoComplete="username"
                      autoCapitalize="none"
                      spellCheck={false}
                      value={username}
                      onChange={(event) => setUsername(event.target.value)}
                      required
                      maxLength={100}
                      placeholder="Enter your username"
                      disabled={pending > 0}
                    />
                  </label>

                  <label className="login-field">
                    <span>Password</span>
                    <input
                      autoComplete="current-password"
                      type="password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      required
                      maxLength={128}
                      placeholder="Enter your password"
                      disabled={pending > 0}
                    />
                  </label>

                  <button className="login-submit" disabled={pending > 0}>
                    <span>{pending ? 'Signing in…' : 'Sign in securely'}</span>
                    {pending ? <LoaderCircle className="animate-spin" size={17} /> : <ArrowRight size={17} />}
                  </button>
                </>
              )}

              {error && (
                <p role="alert" className="login-error">
                  {error}
                </p>
              )}
              {sessionExpired && (
                <p role="status" className="login-error">
                  Your session has expired. Please sign in again.
                </p>
              )}
            </form>

            <div className="login-forgot-row">
              <button type="button" className="login-forgot-link" onClick={startReset} disabled={pending > 0}>
                <KeyRound size={13} /> Forgot password?
              </button>
            </div>

            <div className="login-card-footer">
              <span>
                <KeyRound size={14} /> Protected operator session
              </span>
              <span className="login-status">
                <i /> Protected sign-in
              </span>
            </div>
          </>
        )}

        {showReset && (
          <>
            <div className="login-heading-block">
              <p className="login-eyebrow">RESET PASSWORD</p>
              <h1 id="login-heading">
                {resetStep === 'username'
                  ? 'Forgot your password?'
                  : resetStep === 'code'
                    ? 'Verify your code'
                    : 'Set a new password'}
              </h1>
              <p className="login-subtitle">
                {resetStep === 'username'
                  ? 'Enter your username and we’ll send a one-time code to your email.'
                  : resetStep === 'code'
                    ? `Enter the 6-digit code we sent to your email.`
                    : 'Enter a new password. Your existing sessions will be revoked.'}
              </p>
            </div>

            {resetError && (
              <p role="alert" className="login-error">
                {resetError}
              </p>
            )}

            {resetStep === 'username' && (
              <form className="login-form" onSubmit={submitResetRequest}>
                <label className="login-field">
                  <span>Username</span>
                  <input
                    autoComplete="username"
                    autoCapitalize="none"
                    spellCheck={false}
                    value={resetUsername}
                    onChange={(event) => setResetUsername(event.target.value)}
                    required
                    maxLength={100}
                    placeholder="Enter your username"
                    disabled={resetting}
                  />
                </label>

                <button className="login-submit" disabled={resetting || pending > 0}>
                  <span>{resetting ? 'Sending…' : 'Send reset code'}</span>
                  {resetting ? <LoaderCircle className="animate-spin" size={17} /> : <Mail size={17} />}
                </button>
              </form>
            )}

            {resetStep === 'code' && (
              <form className="login-form" onSubmit={submitOtp}>
                <label className="login-field">
                  <span>Reset code</span>
                  <input
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    value={otpCode}
                    onChange={(event) => setOtpCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                    required
                    maxLength={6}
                    placeholder="6-digit code"
                    disabled={resetting}
                  />
                </label>

                {devOtp && (
                  <p className="login-dev-otp">
                    Development code: <code>{devOtp}</code>
                  </p>
                )}

                <button className="login-submit" disabled={resetting || otpCode.length !== 6}>
                  <span>{resetting ? 'Verifying…' : 'Verify code'}</span>
                  {resetting ? <LoaderCircle className="animate-spin" size={17} /> : <ArrowRight size={17} />}
                </button>
              </form>
            )}

            {resetStep === 'newPassword' && (
              <form className="login-form" onSubmit={submitNewPassword}>
                <label className="login-field">
                  <span>New password</span>
                  <input
                    autoComplete="new-password"
                    type="password"
                    value={newPassword}
                    onChange={(event) => setNewPassword(event.target.value)}
                    required
                    minLength={14}
                    maxLength={128}
                    placeholder="At least 14 characters"
                    disabled={resetting}
                  />
                </label>

                <button className="login-submit" disabled={resetting || newPassword.length < 14}>
                  <span>{resetting ? 'Resetting…' : 'Reset password'}</span>
                  {resetting ? <LoaderCircle className="animate-spin" size={17} /> : <ArrowRight size={17} />}
                </button>
              </form>
            )}

            <div className="login-forgot-row">
              <button
                type="button"
                className="login-forgot-link"
                onClick={() => {
                  setShowReset(false);
                  setResetStep('username');
                  setResetError(null);
                  setDevOtp(null);
                }}
                disabled={resetting}
              >
                Back to sign in
              </button>
            </div>
          </>
        )}

        <footer className="login-page-footer">
          BA Threat Intel Enterprise <span>·</span> Vulnerability intelligence and response
        </footer>
      </section>
    </main>
  );
}
