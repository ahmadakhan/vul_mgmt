import { PageHeading } from './PageHeading';
import React, { useEffect, useState } from 'react';
import {
  Check,
  Mail,
  ChevronRight,
  RotateCcw,
  Save,
  AlertCircle,
  LoaderCircle,
  KeyRound,
  LockKeyhole,
  Pencil,
  Plus,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  Clock,
  Trash2,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { EmailProviderSettings } from './EmailProviderSettings';
import type { AppSettings } from '../types';
import './settings.css';
import { useDialogFocus } from '../hooks/useDialogFocus';
import { DEFAULT_TIMEZONE } from '../../shared/state';

const field = 'ui-field';

/** Older persisted settings may predate processing defaults. */
const withProcessingDefaults = (value: AppSettings): AppSettings => ({
  ...value,
  digestBatchingEnabled: value.digestBatchingEnabled ?? true,
  digestWindowMinutes: value.digestWindowMinutes ?? 5,
  emailEnabled: value.emailEnabled ?? true,
  emailRetryEnabled: value.emailRetryEnabled ?? true,
  emailRetryMaxAttempts: value.emailRetryMaxAttempts ?? 6,
  emailRetryInitialDelayMinutes: value.emailRetryInitialDelayMinutes ?? 1,
  emailRetryMaxDelayMinutes: value.emailRetryMaxDelayMinutes ?? 60,
  selfHealing: value.selfHealing ?? {
    enabled: true,
    cooldownMinutes: 30,
    emailNotifications: true,
  },
});

const findingDispatchSettings = (value: AppSettings) => ({
  autoDispatchEnabled: value.autoDispatchEnabled,
  autoDispatchConfidenceThreshold: value.autoDispatchConfidenceThreshold ?? 90,
  reviewConfidenceThreshold: value.reviewConfidenceThreshold ?? 0,
  autoDispatchUnverifiableMatches: value.autoDispatchUnverifiableMatches ?? false,
  reviewUnverifiableMatches: value.reviewUnverifiableMatches ?? false,
});

const confidenceInputError = (value: string): string => {
  if (!value.trim()) return 'Enter a whole number from 0 to 100.';
  const confidence = Number(value);
  return Number.isInteger(confidence) && confidence >= 0 && confidence <= 100
    ? ''
    : 'Enter a whole number from 0 to 100.';
};

export const TIMEZONES: string[] = [...new Set([
  ...(DEFAULT_TIMEZONE === 'UTC' ? [] : [DEFAULT_TIMEZONE]),
  'UTC',
  'Europe/London',
  'Europe/Paris',
  'Europe/Berlin',
  'Europe/Moscow',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/Sao_Paulo',
  'America/Argentina/Buenos_Aires',
  'America/Mexico_City',
  'America/Toronto',
  'Asia/Tokyo',
  'Asia/Shanghai',
  'Asia/Kolkata',
  'Asia/Dubai',
  'Asia/Singapore',
  'Australia/Sydney',
  'Australia/Melbourne',
  'Pacific/Auckland',
  'Pacific/Honolulu',
])];

function SectionHeading({
  icon: Icon,
  title,
  description,
  id,
}: {
  icon: typeof Settings2;
  title: string;
  description: string;
  id?: string;
}) {
  return (
    <div className="settings-section-heading flex items-start gap-3.5">
      <span className="ui-section-icon">
        <Icon className="h-4 w-4" aria-hidden="true" />
      </span>
      <div>
        <h2 id={id} className="ui-card-title">
          {title}
        </h2>
        <p className="ui-description mt-1">{description}</p>
      </div>
    </div>
  );
}

function SettingsDialog({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const ref = useDialogFocus(onClose);
  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabIndex={-1}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
      className="settings-dialog fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
    >
      {children}
    </div>
  );
}

function ProcessingSection({
  number,
  id,
  title,
  description,
  children,
}: {
  number: string;
  id: string;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <section className="processing-section" aria-labelledby={id}>
      <header>
        <span className="processing-step" aria-hidden="true">
          {number}
        </span>
        <div>
          <h3 id={id}>{title}</h3>
          <p>{description}</p>
        </div>
      </header>
      <div className="processing-section-body">{children}</div>
    </section>
  );
}

function ProcessingToggle({
  id,
  title,
  description,
  checked,
  disabled,
  onChange,
}: {
  id: string;
  title: string;
  description: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className={`processing-toggle ${disabled ? 'is-disabled' : ''}`} htmlFor={id}>
      <span>
        <strong>{title}</strong>
        <span id={`${id}-hint`}>{description}</span>
      </span>
      <input
        id={id}
        type="checkbox"
        role="switch"
        checked={checked}
        disabled={disabled}
        aria-describedby={`${id}-hint`}
        onChange={(event) => onChange(event.target.checked)}
      />
    </label>
  );
}

function ProcessingField({
  id,
  label,
  hint,
  error,
  unit,
  children,
}: {
  id: string;
  label: string;
  hint: string;
  error?: string;
  unit?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="processing-field">
      <label htmlFor={id}>{label}</label>
      <div className={`processing-control ${unit ? 'has-unit' : ''}`}>
        {children}
        {unit && (
          <span className="processing-unit" aria-hidden="true">
            {unit}
          </span>
        )}
      </div>
      <p id={`${id}-hint`}>{hint}</p>
      {error && <p id={`${id}-error`} role="alert" className="processing-save-error">{error}</p>}
    </div>
  );
}

export function SettingsView() {
  const {
    settings,
    updateSettings,
    changePassword,
    session,
    listUsers,
    createUser,
    updateUser,
    deleteUser,
    resetUserPassword,
    pending,
  } = useApp();
  const [form, setForm] = useState<AppSettings>(() => withProcessingDefaults(settings));
  const [securityForm, setSecurityForm] = useState<AppSettings['securityPolicy']>(settings.securityPolicy);
  const [message, setMessage] = useState('');
  const [processingSaveError, setProcessingSaveError] = useState(false);
  const [securityMessage, setSecurityMessage] = useState('');
  const [findingForm, setFindingForm] = useState(() => findingDispatchSettings(settings));
  const [confidenceDrafts, setConfidenceDrafts] = useState(() => ({
    queued: String(settings.autoDispatchConfidenceThreshold ?? 90),
    review: String(settings.reviewConfidenceThreshold ?? 0),
  }));
  const [findingMessage, setFindingMessage] = useState('');
  const [findingSaveError, setFindingSaveError] = useState(false);
  const [selfHealingForm, setSelfHealingForm] = useState<AppSettings['selfHealing']>(settings.selfHealing ?? {
    enabled: true,
    cooldownMinutes: 30,
    emailNotifications: true,
  });
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [users, setUsers] = useState<any[]>([]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('VIEWER');
  const [accountMessage, setAccountMessage] = useState('');
  const [usersLoading, setUsersLoading] = useState(true);
  const [usersError, setUsersError] = useState('');
  const [resetUserId, setResetUserId] = useState<string | null>(null);
  const [disablingUserId, setDisablingUserId] = useState<string | null>(null);
  const [deleteUserId, setDeleteUserId] = useState<string | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const [email, setEmail] = useState('');
  // The account being edited in the popup form, or null when the form is closed.
  const [editingUser, setEditingUser] = useState<any | null>(null);
  const [editForm, setEditForm] = useState({ username: '', role: 'VIEWER', email: '', disabled: false });
  const [editMessage, setEditMessage] = useState('');
  // Confirmation dialogs for mutating actions
  const [confirmProcessingToggle, setConfirmProcessingToggle] = useState<{ id: string; action: 'enable' | 'disable'; label: string } | null>(null);
  const [confirmProcessingSave, setConfirmProcessingSave] = useState<{ id: string; action: string; label: string } | null>(null);
  const [confirmFindingToggle, setConfirmFindingToggle] = useState<{ id: string; action: 'enable' | 'disable'; label: string } | null>(null);
  const [confirmFindingSave, setConfirmFindingSave] = useState<{ id: string; action: string; label: string } | null>(null);
  const [confirmSecuritySave, setConfirmSecuritySave] = useState<{ id: string; action: string; label: string } | null>(null);
  const [confirmChangePassword, setConfirmChangePassword] = useState<{ id: string; action: string; label: string } | null>(null);
  const [confirmCreateUser, setConfirmCreateUser] = useState<{ id: string; action: string; label: string } | null>(null);
  const [confirmEditUser, setConfirmEditUser] = useState<{ id: string; action: string; label: string } | null>(null);
  const [confirmEnableUser, setConfirmEnableUser] = useState<{ id: string; action: string; label: string } | null>(null);
  const admin = session?.role === 'ADMIN';
  const [activeSection, setActiveSection] = useState(admin ? 'processing' : 'security');
  const processingConfirmPending = confirmProcessingToggle !== null || confirmProcessingSave !== null;
  const findingConfirmPending = confirmFindingToggle !== null || confirmFindingSave !== null;
  const processingDirty =
    form.scopeHours !== settings.scopeHours ||
    form.schedulerIntervalMinutes !== settings.schedulerIntervalMinutes ||
    form.advisoryPrefix !== settings.advisoryPrefix ||
    (form.logVerbosity ?? 'standard') !== (settings.logVerbosity ?? 'standard') ||
    form.schedulerEnabled !== settings.schedulerEnabled ||
    form.digestBatchingEnabled !== (settings.digestBatchingEnabled ?? true) ||
    (form.digestWindowMinutes ?? 5) !== (settings.digestWindowMinutes ?? 5) ||
    (form.autoDispatchNewsToSecurityTeam ?? false) !== (settings.autoDispatchNewsToSecurityTeam ?? false) ||
    (form.deferEveryoneUntilSecurityDelivered ?? false) !==
      (settings.deferEveryoneUntilSecurityDelivered ?? false) ||
    (form.emailRetryEnabled ?? true) !== (settings.emailRetryEnabled ?? true) ||
    (form.emailRetryMaxAttempts ?? 6) !== (settings.emailRetryMaxAttempts ?? 6) ||
    (form.emailRetryInitialDelayMinutes ?? 1) !== (settings.emailRetryInitialDelayMinutes ?? 1) ||
    (form.emailRetryMaxDelayMinutes ?? 60) !== (settings.emailRetryMaxDelayMinutes ?? 60) ||
    form.emailEnabled !== settings.emailEnabled ||
    form.timezone !== settings.timezone ||
    (form.dailyDigest?.enabled ?? false) !== (settings.dailyDigest?.enabled ?? false) ||
    (form.dailyDigest?.time ?? '09:00') !== (settings.dailyDigest?.time ?? '09:00') ||
    (form.dailyDigest?.includeHealthReport ?? true) !== (settings.dailyDigest?.includeHealthReport ?? true) ||
    selfHealingForm.emailNotifications !== (settings.selfHealing?.emailNotifications ?? true);
  const queuedConfidenceError = confidenceInputError(confidenceDrafts.queued);
  const reviewConfidenceError = confidenceInputError(confidenceDrafts.review);
  const findingInvalid = Boolean(queuedConfidenceError || reviewConfidenceError);
  const findingDirty = JSON.stringify(findingForm) !== JSON.stringify(findingDispatchSettings(settings)) ||
    confidenceDrafts.queued !== String(settings.autoDispatchConfidenceThreshold ?? 90) ||
    confidenceDrafts.review !== String(settings.reviewConfidenceThreshold ?? 0);
  const securityDirty =
    securityForm.sessionTimeoutMins !== settings.securityPolicy.sessionTimeoutMins ||
    securityForm.minPasswordLen !== settings.securityPolicy.minPasswordLen ||
    securityForm.maxLoginAttempts !== settings.securityPolicy.maxLoginAttempts ||
    securityForm.lockoutMins !== settings.securityPolicy.lockoutMins;
  const sections = [
    ...(admin
      ? [
          {
            id: 'processing',
            title: 'Processing',
            description: 'Schedule, digests & retries',
            icon: SlidersHorizontal,
          },
          {
            id: 'finding-dispatch',
            title: 'Finding dispatch',
            description: 'Confidence & review',
            icon: ShieldCheck,
          },
          { id: 'email', title: 'Email delivery', description: 'Providers & sender identity', icon: Mail },
        ]
      : []),
    { id: 'security', title: 'Account security', description: 'Password & sign-in', icon: ShieldCheck },
    ...(admin
      ? [{ id: 'access', title: 'Workspace access', description: 'Accounts & permissions', icon: Users }]
      : []),
  ];

  const reloadUsers = async () => {
    setUsersLoading(true);
    setUsersError('');
    try {
      const result = await listUsers();
      if (result) setUsers(result);
      else setUsersError('Workspace accounts could not be loaded.');
    } finally {
      setUsersLoading(false);
    }
  };

  useEffect(() => {
    if (admin) void reloadUsers();
  }, [admin]);

  const executeProcessingToggle = async () => {
    if (!confirmProcessingToggle) return;
    const { id, action } = confirmProcessingToggle;
    const enable = action === 'enable';
    setForm((prev) => {
      switch (id) {
        case 'scheduler': return { ...prev, schedulerEnabled: enable };
        case 'batching': return { ...prev, digestBatchingEnabled: enable };
        case 'news': return { ...prev, autoDispatchNewsToSecurityTeam: enable };
        case 'defer': return { ...prev, deferEveryoneUntilSecurityDelivered: enable };
        case 'email': return { ...prev, emailEnabled: enable };
        case 'retry': return { ...prev, emailRetryEnabled: enable };
      }
      return prev;
    });
    setConfirmProcessingToggle(null);
  };

  const executeProcessingSave = async () => {
    if (!confirmProcessingSave) return;
    setProcessingSaveError(false);
    const saved = await updateSettings({
      ...form,
      ...findingDispatchSettings(settings),
      securityPolicy: settings.securityPolicy,
      selfHealing: selfHealingForm,
    });
    setProcessingSaveError(!saved);
    setMessage(
      saved
        ? 'Settings saved successfully.'
        : 'Could not save processing settings. Your changes are still available to retry.',
    );
    setConfirmProcessingSave(null);
  };

  const executeFindingToggle = async () => {
    if (!confirmFindingToggle) return;
    const { id, action } = confirmFindingToggle;
    const enable = action === 'enable';
    setFindingForm((prev) => {
      if (id === 'auto-dispatch') return { ...prev, autoDispatchEnabled: enable };
      return prev;
    });
    setConfirmFindingToggle(null);
  };

  const executeFindingSave = async () => {
    if (!confirmFindingSave) return;
    setFindingSaveError(false);
    const nextFindingForm = {
      ...findingForm,
      autoDispatchConfidenceThreshold: Number(confidenceDrafts.queued),
      reviewConfidenceThreshold: Number(confidenceDrafts.review),
    };
    const saved = await updateSettings(nextFindingForm);
    if (saved) {
      setFindingForm(nextFindingForm);
      setConfidenceDrafts({
        queued: String(nextFindingForm.autoDispatchConfidenceThreshold),
        review: String(nextFindingForm.reviewConfidenceThreshold),
      });
    }
    setFindingSaveError(!saved);
    setFindingMessage(
      saved
        ? 'Finding dispatch settings saved.'
        : 'Could not save finding dispatch settings. Your changes are still available to retry.',
    );
    setConfirmFindingSave(null);
  };

  const executeSecuritySave = async () => {
    if (!confirmSecuritySave) return;
    setSecurityMessage('');
    if (await updateSettings({ securityPolicy: securityForm }))
      setSecurityMessage('Security policy saved successfully.');
    setConfirmSecuritySave(null);
  };

  const executeChangePassword = async () => {
    if (!confirmChangePassword) return;
    const changed = await changePassword(currentPassword, newPassword);
    if (changed) {
      setCurrentPassword('');
      setNewPassword('');
    }
    setConfirmChangePassword(null);
  };

  const executeCreateUser = async () => {
    if (!confirmCreateUser) return;
    setAccountMessage('');
    if (await createUser({ username, password, role, email: email.trim() })) {
      setUsername('');
      setPassword('');
      setRole('VIEWER');
      setEmail('');
      await reloadUsers();
      setAccountMessage('Operator created successfully.');
    } else {
      setAccountMessage('Failed to create operator.');
    }
    setConfirmCreateUser(null);
  };

  const executeEditUser = async () => {
    if (!confirmEditUser || !editingUser) return;
    setEditMessage('');
    const ok = await updateUser(editingUser.id, {
      role: editForm.role,
      email: editForm.email.trim(),
      disabled: editForm.disabled,
    });
    if (!ok) {
      setEditMessage('The account could not be updated.');
      return;
    }
    await reloadUsers();
    setEditingUser(null);
    setConfirmEditUser(null);
  };

  const executeEnableUser = async () => {
    if (!confirmEnableUser) return;
    const target = users.find((u) => u.id === confirmEnableUser.id);
    if (!target) {
      setConfirmEnableUser(null);
      return;
    }
    await updateUser(target.id, { role: target.role, disabled: false });
    await reloadUsers();
    setConfirmEnableUser(null);
  };

  return (
    <div className="settings-page space-y-6 text-zinc-100 light:text-zinc-900">
      <header className="ui-page-header">
        <PageHeading page="settings">
          Configure processing, email delivery, account security, and workspace access.
        </PageHeading>
        <span className="settings-role-badge">
          <ShieldCheck size={14} />
          {admin ? 'Administrator access' : 'Personal settings'}
        </span>
      </header>

      <div className="settings-layout">
        <aside className="settings-sidebar">
          <div className="settings-nav-label">Workspace settings</div>
          <nav aria-label="Settings sections" className="settings-section-nav">
            {sections.map(({ id, title, description, icon: Icon }) => (
              <button
                key={id}
                type="button"
                aria-pressed={activeSection === id}
                aria-controls={`settings-${id}`}
                onClick={() => setActiveSection(id)}
              >
                <Icon size={17} aria-hidden="true" />
                <span>
                  <strong>
                    {title}
                    {((id === 'processing' && processingDirty) ||
                      (id === 'finding-dispatch' && findingDirty) ||
                      (id === 'security' && securityDirty)) && (
                      <span
                        className="settings-dirty-indicator"
                        title="Unsaved changes"
                        aria-label="Unsaved changes"
                      />
                    )}
                  </strong>
                  <small>{description}</small>
                </span>
                <ChevronRight size={13} aria-hidden="true" />
              </button>
            ))}
          </nav>
          <div className="settings-identity">
            <div className="settings-avatar">{session?.username.slice(0, 1).toUpperCase()}</div>
            <div>
              <strong>{session?.username}</strong>
              <span>{session?.role.toLowerCase()} account</span>
            </div>
          </div>
        </aside>
        <div className="settings-content">
          {admin &&
            ((activeSection === 'processing' && processingDirty) ||
              (activeSection === 'finding-dispatch' && findingDirty) ||
              (activeSection === 'security' && securityDirty)) && (
              <div className="settings-unsaved-bar" role="status">
                <div>
                  <span className="settings-dirty-indicator" />
                  <div>
                    <strong>You have unsaved changes</strong>
                    <p>Review your changes, then save to apply them.</p>
                  </div>
                </div>
                <button
                  type="submit"
                  form={
                    activeSection === 'processing'
                      ? 'processing-settings-form'
                      : activeSection === 'finding-dispatch'
                        ? 'finding-dispatch-form'
                        : 'security-policy-form'
                  }
                  disabled={pending > 0 || (activeSection === 'finding-dispatch' && findingInvalid)}
                  className="ui-primary"
                >
                  <Save size={14} aria-hidden="true" />
                  {pending > 0 ? 'Saving…' : 'Save changes'}
                </button>
              </div>
            )}
          {admin && (
            <div id="settings-email" hidden={activeSection !== 'email'}>
              <EmailProviderSettings />
            </div>
          )}

          {admin && (
            <div id="settings-processing" hidden={activeSection !== 'processing'}>
              <form
                id="processing-settings-form"
                className="ui-card processing-settings-form"
                aria-labelledby="processing-settings-title"
                aria-busy={pending > 0}
                onChangeCapture={() => setMessage('')}
                onSubmit={async (event) => {
                  event.preventDefault();
                  if (pending > 0 || !processingDirty) return;
                  setMessage('');
                  setProcessingSaveError(false);
                  setConfirmProcessingSave({
                    id: 'processing-settings',
                    action: 'save',
                    label: 'Processing settings',
                  });
                }}
              >
                <SectionHeading
                  icon={SlidersHorizontal}
                  id="processing-settings-title"
                  title="Processing"
                  description="Configure collection schedules, recipient delivery, digests, and retry behavior."
                />
                <div
                  className="settings-configuration-summary processing-summary"
                  role="region"
                  aria-label="Processing configuration summary"
                >
                  <div>
                    <span>Pipeline schedule</span>
                    <strong>
                      <i className={form.schedulerEnabled ? 'is-enabled' : ''} aria-hidden="true" />
                      {form.schedulerEnabled ? `Every ${form.schedulerIntervalMinutes} min` : 'Manual runs'}
                    </strong>
                  </div>
                  <div>
                    <span>News notifications</span>
                    <strong>
                      <i
                        className={form.autoDispatchNewsToSecurityTeam ? 'is-enabled' : ''}
                        aria-hidden="true"
                      />
                      {form.autoDispatchNewsToSecurityTeam ? 'Automatic' : 'Review only'}
                    </strong>
                  </div>
                  <div>
                    <span>Daily digest</span>
                    <strong>
                      <i className={form.dailyDigest?.enabled ? 'is-enabled' : ''} aria-hidden="true" />
                      {form.dailyDigest?.enabled
                        ? `${form.dailyDigest.time || '09:00'} · ${form.timezone || DEFAULT_TIMEZONE}`
                        : 'Disabled'}
                    </strong>
                  </div>
                  <div>
                    <span>Email retries</span>
                    <strong>
                      <i
                        className={(form.emailRetryEnabled ?? true) ? 'is-enabled' : ''}
                        aria-hidden="true"
                      />
                      {(form.emailRetryEnabled ?? true)
                        ? `Up to ${form.emailRetryMaxAttempts ?? 6} attempts`
                        : 'Disabled'}
                    </strong>
                  </div>
                </div>
                <nav className="processing-section-nav" aria-label="Processing sections">
                  <span>Jump to</span>
                  {[
                    ['pipeline', 'Schedule'],
                    ['recipients', 'Recipients'],
                    ['news', 'News'],
                    ['digests', 'Digests'],
                    ['retries', 'Retries'],
                    ['output', 'Output & logs'],
                  ].map(([id, label], index) => (
                    <a key={id} href={`#processing-${id}`}>
                      <span aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
                      {label}
                    </a>
                  ))}
                </nav>
                <fieldset className="processing-settings-fields" disabled={pending > 0 || processingConfirmPending}>
                  <legend className="sr-only">Processing and delivery configuration</legend>
                  <ProcessingSection
                    number="01"
                    id="processing-pipeline"
                    title="Pipeline scheduling"
                    description="Set the collection window and the interval between automatic runs."
                  >
                      <ProcessingToggle
                        id="processing-scheduler"
                        title="Enable server scheduler"
                        description="Allow the server to start pipeline runs on the configured interval."
                        checked={form.schedulerEnabled}
                        disabled={processingConfirmPending}
                        onChange={(checked) =>
                          setConfirmProcessingToggle({
                            id: 'scheduler',
                            action: checked ? 'enable' : 'disable',
                            label: 'Server scheduler',
                          })
                        }
                      />
                    <div className="processing-field-grid">
                      <ProcessingField
                        id="processing-scope"
                        label="Scope window"
                        unit="hours"
                        hint="How far back each ingestion run checks for updates."
                      >
                        <input
                          id="processing-scope"
                          type="number"
                          min={1}
                          max={2880}
                          required
                          aria-describedby="processing-scope-hint"
                          className={field}
                          value={form.scopeHours}
                          onChange={(event) => setForm({ ...form, scopeHours: Number(event.target.value) })}
                        />
                      </ProcessingField>
                      <ProcessingField
                        id="processing-interval"
                        label="Schedule interval"
                        unit="minutes"
                        hint={
                          form.schedulerEnabled
                            ? 'Time between scheduled pipeline runs.'
                            : 'Enable the scheduler to apply this interval.'
                        }
                      >
                        <input
                          id="processing-interval"
                          type="number"
                          min={5}
                          max={10080}
                          required
                          disabled={!form.schedulerEnabled}
                          aria-describedby="processing-interval-hint"
                          className={field}
                          value={form.schedulerIntervalMinutes}
                          onChange={(event) =>
                            setForm({ ...form, schedulerIntervalMinutes: Number(event.target.value) })
                          }
                        />
                      </ProcessingField>
                    </div>
                  </ProcessingSection>
                  <ProcessingSection
                    number="02"
                    id="processing-recipients"
                    title="Recipient review and handoff"
                    description="Control when an advisory becomes available to the Everyone group."
                  >
                      <ProcessingToggle
                        id="processing-defer-everyone"
                        title="Send to the Security team before Everyone"
                        description="After the transport accepts a Security-team email, queue the advisory for Everyone-group preview and approval."
                        checked={form.deferEveryoneUntilSecurityDelivered ?? false}
                        disabled={processingConfirmPending}
                        onChange={(checked) =>
                          setConfirmProcessingToggle({
                            id: 'defer',
                            action: checked ? 'enable' : 'disable',
                            label: 'Send to Security team before Everyone',
                          })
                        }
                      />
                    {form.deferEveryoneUntilSecurityDelivered ? (
                      <ol className="processing-delivery-flow" aria-label="Recipient delivery sequence">
                        <li>
                          <span>1</span>
                          <div>
                            <strong>Security team</strong>
                            <p>Transport accepts the email</p>
                          </div>
                        </li>
                        <li>
                          <span>2</span>
                          <div>
                            <strong>Email queue</strong>
                            <p>Operator previews and approves</p>
                          </div>
                        </li>
                        <li>
                          <span>3</span>
                          <div>
                            <strong>Everyone</strong>
                            <p>Approved broadcast is queued</p>
                          </div>
                        </li>
                      </ol>
                    ) : (
                      <p className="processing-footnote">
                        <ShieldCheck size={14} aria-hidden="true" />
                        Everyone-group emails require operator preview and approval in the email queue.
                      </p>
                    )}
                  </ProcessingSection>
                  <ProcessingSection
                    number="03"
                    id="processing-news"
                    title="News evidence"
                    description="Control how security news and advisory evidence is handled."
                  >
                      <ProcessingToggle
                        id="processing-auto-news"
                        title="Send matching news to Security team"
                        description="Automatically notify Security-team recipients about news that matches a monitored vendor and product."
                        checked={form.autoDispatchNewsToSecurityTeam}
                        disabled={processingConfirmPending}
                        onChange={(checked) =>
                          setConfirmProcessingToggle({
                            id: 'news',
                            action: checked ? 'enable' : 'disable',
                            label: 'Send matching news to Security team',
                          })
                        }
                      />
                    <div className="processing-context">
                      <ShieldCheck size={17} aria-hidden="true" />
                      <div>
                        <strong>Review evidence before remediation</strong>
                        <p>
                          Matching news is applicability evidence, not a confirmed advisory. Recipients are
                          asked to confirm source authenticity and consult the vendor before remediation.
                        </p>
                      </div>
                    </div>
                  </ProcessingSection>
                  <ProcessingSection
                    number="04"
                    id="processing-digests"
                    title="Digest delivery"
                    description="Configure short-window batching and the scheduled daily summary independently."
                  >
                    <ProcessingField
                      id="processing-timezone"
                      label="Workspace timezone"
                      hint="Used for the daily digest schedule and human-readable dates."
                    >
                      <select
                        id="processing-timezone"
                        aria-describedby="processing-timezone-hint"
                        className={field}
                        value={form.timezone || DEFAULT_TIMEZONE}
                        onChange={(event) => setForm({ ...form, timezone: event.target.value })}
                      >
                        {form.timezone && !TIMEZONES.includes(form.timezone) && (
                          <option value={form.timezone}>{form.timezone}</option>
                        )}
                        {TIMEZONES.map((timezone) => (
                          <option key={timezone} value={timezone}>
                            {timezone}
                          </option>
                        ))}
                      </select>
                    </ProcessingField>
                    <div className="processing-digest-group">
                      <div className="processing-subheading">
                        <h4>Batch new findings</h4>
                        <p>Combine detections within a short delivery window.</p>
                      </div>
                      <ProcessingToggle
                        id="processing-batching"
                        title="Combine threats into one email"
                        description="Send one combined email per recipient, containing only findings permitted by their subscription."
                        checked={form.digestBatchingEnabled ?? true}
                        disabled={processingConfirmPending}
                        onChange={(checked) =>
                          setConfirmProcessingToggle({
                            id: 'batching',
                            action: checked ? 'enable' : 'disable',
                            label: 'Combine threats into one email',
                          })
                        }
                      />
                      <ProcessingField
                        id="processing-batch-window"
                        label="Batching window"
                        unit="minutes"
                        hint="How long to collect detections before sending the combined email."
                      >
                        <input
                          id="processing-batch-window"
                          type="number"
                          min={1}
                          max={1440}
                          disabled={!form.digestBatchingEnabled}
                          aria-describedby="processing-batch-window-hint"
                          className={field}
                          value={form.digestWindowMinutes ?? 5}
                          onChange={(event) =>
                            setForm({
                              ...form,
                              digestWindowMinutes: Math.max(1, parseInt(event.target.value) || 1),
                            })
                          }
                        />
                      </ProcessingField>
                    </div>
                    <div className="processing-digest-group">
                      <div className="processing-subheading">
                        <h4>Daily summary</h4>
                        <p>A calendar-based digest for recipients who opt in.</p>
                      </div>
                      <ProcessingToggle
                        id="processing-daily-digest"
                        title="Enable daily digest"
                        description="Send a daily findings summary at the selected local time."
                        checked={form.dailyDigest?.enabled ?? false}
                        onChange={(checked) =>
                          setForm({
                            ...form,
                            dailyDigest: {
                              ...(form.dailyDigest ?? { time: '09:00', includeHealthReport: true }),
                              enabled: checked,
                            },
                          })
                        }
                      />
                      <div className="processing-field-grid">
                        <ProcessingField
                          id="processing-digest-time"
                          label="Delivery time"
                          hint={`Local time in ${form.timezone || DEFAULT_TIMEZONE}.`}
                        >
                          <input
                            id="processing-digest-time"
                            type="time"
                            required
                            disabled={!form.dailyDigest?.enabled}
                            aria-describedby="processing-digest-time-hint"
                            className={field}
                            value={form.dailyDigest?.time ?? '09:00'}
                            onChange={(event) =>
                              setForm({
                                ...form,
                                dailyDigest: {
                                  ...(form.dailyDigest ?? { enabled: false, includeHealthReport: true }),
                                  time: event.target.value,
                                },
                              })
                            }
                          />
                        </ProcessingField>
                        <ProcessingToggle
                          id="processing-health-report"
                          title="Include health-check report"
                          description="Append an operational health snapshot to the daily digest."
                          checked={form.dailyDigest?.includeHealthReport ?? true}
                          disabled={!form.dailyDigest?.enabled}
                          onChange={(checked) =>
                            setForm({
                              ...form,
                              dailyDigest: {
                                ...(form.dailyDigest ?? { enabled: false, time: '09:00' }),
                                includeHealthReport: checked,
                              },
                            })
                          }
                        />
                      </div>
                    </div>
                  </ProcessingSection>
                  <ProcessingSection
                    number="05"
                    id="processing-retries"
                    title="Email retry policy"
                    description="Recover from transient provider or network failures with exponential backoff."
                  >
                    <ProcessingToggle
                      id="processing-email-enabled"
                      title="Enable email delivery"
                      description="Master switch for all outbound email. When off, no advisory, digest, news, self-healing, or test email is generated or sent."
                      checked={form.emailEnabled ?? true}
                      disabled={processingConfirmPending}
                      onChange={(checked) =>
                        setConfirmProcessingToggle({
                          id: 'email',
                          action: checked ? 'enable' : 'disable',
                          label: 'Email delivery',
                        })
                      }
                    />
                    <ProcessingToggle
                      id="processing-retry-enabled"
                      title="Enable automatic email retry"
                      description="Keep eligible failed deliveries queued and retry them with an increasing delay."
                      checked={form.emailRetryEnabled ?? true}
                      disabled={processingConfirmPending}
                      onChange={(checked) =>
                        setConfirmProcessingToggle({
                          id: 'retry',
                          action: checked ? 'enable' : 'disable',
                          label: 'Automatic email retry',
                        })
                      }
                    />
                    <div className="processing-field-grid processing-retry-grid">
                      <ProcessingField
                        id="processing-retry-attempts"
                        label="Maximum attempts"
                        unit="sends"
                        hint="Includes the first send. A value of 1 permits only the initial attempt."
                      >
                        <input
                          id="processing-retry-attempts"
                          type="number"
                          min={1}
                          max={20}
                          disabled={!form.emailRetryEnabled}
                          aria-describedby="processing-retry-attempts-hint"
                          className={field}
                          value={form.emailRetryMaxAttempts ?? 6}
                          onChange={(event) =>
                            setForm({
                              ...form,
                              emailRetryMaxAttempts: Math.min(
                                20,
                                Math.max(1, parseInt(event.target.value) || 1),
                              ),
                            })
                          }
                        />
                      </ProcessingField>
                      <ProcessingField
                        id="processing-retry-initial"
                        label="Initial backoff"
                        unit="minutes"
                        hint="Delay before the second attempt; doubles after each failure."
                      >
                        <input
                          id="processing-retry-initial"
                          type="number"
                          min={1}
                          max={1440}
                          disabled={!form.emailRetryEnabled}
                          aria-describedby="processing-retry-initial-hint"
                          className={field}
                          value={form.emailRetryInitialDelayMinutes ?? 1}
                          onChange={(event) => {
                            const initial = Math.min(1440, Math.max(1, parseInt(event.target.value) || 1));
                            setForm({
                              ...form,
                              emailRetryInitialDelayMinutes: initial,
                              emailRetryMaxDelayMinutes: Math.max(
                                initial,
                                form.emailRetryMaxDelayMinutes ?? 60,
                              ),
                            });
                          }}
                        />
                      </ProcessingField>
                      <ProcessingField
                        id="processing-retry-maximum"
                        label="Maximum backoff"
                        unit="minutes"
                        hint="Upper limit for the delay between attempts."
                      >
                        <input
                          id="processing-retry-maximum"
                          type="number"
                          min={form.emailRetryInitialDelayMinutes ?? 1}
                          max={10080}
                          disabled={!form.emailRetryEnabled}
                          aria-describedby="processing-retry-maximum-hint"
                          className={field}
                          value={form.emailRetryMaxDelayMinutes ?? 60}
                          onChange={(event) =>
                            setForm({ ...form, emailRetryMaxDelayMinutes: Number(event.target.value) })
                          }
                          onBlur={(event) =>
                            setForm({
                              ...form,
                              emailRetryMaxDelayMinutes: Math.max(
                                form.emailRetryInitialDelayMinutes ?? 1,
                                Math.min(10080, Math.max(1, parseInt(event.target.value) || 1)),
                              ),
                            })
                          }
                        />
                      </ProcessingField>
                    </div>
                    <p className="processing-footnote">
                      <AlertCircle size={14} aria-hidden="true" />
                      Permanent provider rejections, such as invalid recipients or credentials, require
                      operator correction.
                    </p>
                  </ProcessingSection>
                  <ProcessingSection
                    number="06"
                    id="processing-output"
                    title="Advisory identifiers and logs"
                    description="Set the naming convention for advisories and the detail recorded in operational logs."
                  >
                    <div className="processing-field-grid">
                      <ProcessingField
                        id="processing-prefix"
                        label="Advisory prefix"
                        hint="Used when generating advisory identifiers."
                      >
                        <input
                          id="processing-prefix"
                          required
                          pattern={String.raw`[A-Za-z0-9_\-]{1,30}`}
                          aria-describedby="processing-prefix-hint"
                          className={field}
                          value={form.advisoryPrefix}
                          onChange={(event) => setForm({ ...form, advisoryPrefix: event.target.value })}
                        />
                      </ProcessingField>
                      <ProcessingField
                        id="processing-logs"
                        label="Operational log detail"
                        hint="Warnings and errors are recorded at both levels."
                      >
                        <select
                          id="processing-logs"
                          aria-describedby="processing-logs-hint"
                          className={field}
                          value={form.logVerbosity ?? 'standard'}
                          onChange={(event) =>
                            setForm({
                              ...form,
                              logVerbosity: event.target.value as AppSettings['logVerbosity'],
                            })
                          }
                        >
                          <option value="standard">Standard · lifecycle and security</option>
                          <option value="verbose">Verbose · forensic telemetry</option>
                        </select>
                      </ProcessingField>
                    </div>
                    <details className="processing-help">
                      <summary>What is included in operational logs?</summary>
                      <p>
                        Standard records pipeline, feed, matching, delivery, and security events. Verbose adds
                        per-advisory correlation telemetry, including extraction and database timings. Changes
                        apply to the next advisory.
                      </p>
                    </details>
                  </ProcessingSection>
                  <ProcessingSection
                    number="07"
                    id="processing-self-healing"
                    title="Self-healing watchdog"
                    description="Automatically recovers degraded pipeline, scheduler, feed, and system health."
                  >
                    <ProcessingToggle
                      id="self-healing-email-notifications"
                      title="Send system health degraded alerts by email"
                      description="When system health is degraded (e.g. heap pressure), send a consolidated alert email to Security-team recipients."
                      checked={selfHealingForm.emailNotifications}
                      onChange={(checked) =>
                        setSelfHealingForm({ ...selfHealingForm, emailNotifications: checked })
                      }
                    />
                  </ProcessingSection>
                </fieldset>
                <div className="ui-actions processing-save-actions">
                  {message ? (
                    <p
                      role={processingSaveError ? 'alert' : 'status'}
                      className={`${processingSaveError ? 'processing-save-error' : 'ui-success'} processing-save-feedback`}
                    >
                      {processingSaveError ? (
                        <AlertCircle size={15} aria-hidden="true" />
                      ) : (
                        <Check size={15} aria-hidden="true" />
                      )}
                      {message}
                    </p>
                  ) : (
                    <span className="settings-save-state">
                      <span className={processingDirty ? 'is-dirty' : ''} />
                      {processingDirty ? 'Unsaved changes' : 'Settings are up to date'}
                    </span>
                  )}
                  <div className="settings-action-buttons">
                    {processingDirty && (
                      <button
                        type="button"
                        className="ui-secondary"
                        disabled={pending > 0}
                        onClick={() => {
                          setForm(withProcessingDefaults(settings));
                          setMessage('');
                          setProcessingSaveError(false);
                        }}
                      >
                        <RotateCcw size={14} aria-hidden="true" />
                        Reset changes
                      </button>
                    )}
                    <button type="submit" disabled={pending > 0 || !processingDirty} className="ui-primary">
                      {pending > 0 ? (
                        <LoaderCircle size={14} className="animate-spin" aria-hidden="true" />
                      ) : (
                        <Save size={14} aria-hidden="true" />
                      )}
                      {pending > 0 ? 'Saving…' : 'Save settings'}
                    </button>
                  </div>
                </div>
              </form>
            </div>
          )}

          {admin && (
            <div id="settings-finding-dispatch" hidden={activeSection !== 'finding-dispatch'}>
              <form
                id="finding-dispatch-form"
                className="ui-card processing-settings-form"
                aria-labelledby="finding-dispatch-title"
                aria-busy={pending > 0}
                onChangeCapture={() => setFindingMessage('')}
                onSubmit={async (event) => {
                  event.preventDefault();
                  if (pending > 0 || !findingDirty || findingInvalid) return;
                  setFindingMessage('');
                  setFindingSaveError(false);
                  setConfirmFindingSave({
                    id: 'finding-dispatch-settings',
                    action: 'save',
                    label: 'Finding dispatch settings',
                  });
                }}
              >
                <SectionHeading
                  icon={ShieldCheck}
                  id="finding-dispatch-title"
                  title="Finding dispatch and review"
                  description="Configure automatic finding notifications, match confidence, and review notices."
                />
                   <fieldset className="processing-settings-fields" disabled={pending > 0 || findingConfirmPending}>
                     <legend className="sr-only">Finding dispatch and review configuration</legend>
                  <ProcessingSection
                    number="01"
                    id="processing-dispatch"
                    title="Dispatch policy"
                    description="Set the confidence minimum and review options for matched findings."
                  >
                     <ProcessingToggle
                       id="processing-auto-dispatch"
                       title="Send confirmed findings automatically"
                       description="Send queued findings automatically to eligible Security-team recipients. When off, eligible findings stay queued."
                       checked={findingForm.autoDispatchEnabled}
                       disabled={findingConfirmPending}
                       onChange={(checked) =>
                         setConfirmFindingToggle({
                           id: 'auto-dispatch',
                           action: checked ? 'enable' : 'disable',
                           label: 'Automatic finding dispatch',
                         })
                       }
                     />
                    <div className="processing-field-grid">
                      <ProcessingField
                        id="processing-confidence"
                        label="Queued email minimum confidence"
                        unit="/ 100"
                        hint="Eligible matches at or above this minimum receive QUEUED_FOR_DISPATCH. The saved minimum applies even with trained ML."
                        error={queuedConfidenceError}
                      >
                        <input
                          id="processing-confidence"
                          type="number"
                          min={0}
                          max={100}
                          step={1}
                          required
                          aria-invalid={Boolean(queuedConfidenceError)}
                          aria-describedby={`processing-confidence-hint${queuedConfidenceError ? ' processing-confidence-error' : ''}`}
                          className={field}
                          value={confidenceDrafts.queued}
                          onChange={(event) =>
                            setConfidenceDrafts({
                              ...confidenceDrafts,
                              queued: event.target.value,
                            })
                          }
                        />
                      </ProcessingField>
                      <ProcessingField
                        id="processing-review-confidence"
                        label="Limited-confidence notice threshold"
                        unit="/ 100"
                        hint="Every finding is dispatched. Findings below this confidence are annotated in the email with their confidence and the reason applicability needs confirmation. This setting never suppresses an email."
                        error={reviewConfidenceError}
                      >
                        <input
                          id="processing-review-confidence"
                          type="number"
                          min={0}
                          max={100}
                          step={1}
                          required
                          aria-invalid={Boolean(reviewConfidenceError)}
                          aria-describedby={`processing-review-confidence-hint${reviewConfidenceError ? ' processing-review-confidence-error' : ''}`}
                          className={field}
                          value={confidenceDrafts.review}
                          onChange={(event) =>
                            setConfidenceDrafts({
                              ...confidenceDrafts,
                              review: event.target.value,
                            })
                          }
                        />
                      </ProcessingField>
                    </div>
                    <div className="processing-context">
                      <ShieldCheck size={17} aria-hidden="true" />
                      <div>
                        <strong>Recipient policies apply</strong>
                        <p>
                          Subscription tiers and approval requirements determine who receives each
                          notification.
                        </p>
                      </div>
                    </div>
                    <div className="processing-policy-group">
                      <div className="processing-subheading">
                        <h4>Product matches with uncertain versions</h4>
                        <p>
                          Choose how to handle a product correlation when its affected version range cannot be
                          verified.
                        </p>
                      </div>
                      <div className="processing-choice-grid">
                        <ProcessingToggle
                          id="processing-unverifiable"
                          title="Annotate limited-confidence findings"
                          description="Findings that cannot be fully confirmed are always dispatched; this states the limitation and its reason on the finding in the email."
                          checked={findingForm.reviewUnverifiableMatches ?? false}
                          onChange={(checked) =>
                            setFindingForm({ ...findingForm, reviewUnverifiableMatches: checked })
                          }
                        />
                        <ProcessingToggle
                          id="processing-auto-unverifiable"
                          title="Allow version-uncertain findings to dispatch"
                          description="Compare measured confidence with the queue minimum for version-uncertain matches. Automatic sending still requires automatic dispatch to be enabled."
                          checked={findingForm.autoDispatchUnverifiableMatches ?? false}
                          onChange={(checked) =>
                            setFindingForm({ ...findingForm, autoDispatchUnverifiableMatches: checked })
                          }
                        />
                      </div>
                      <p className="processing-policy-note">
                        <AlertCircle size={14} aria-hidden="true" />
                        <span>
                          All findings are dispatched; there is no review queue. Confidence below 100% is
                          stated on the finding in the email, together with why applicability must be
                          confirmed. No findings are deleted or withheld by these thresholds.
                        </span>
                      </p>
                    </div>
                  </ProcessingSection>
                </fieldset>
                <div className="ui-actions processing-save-actions">
                  {findingMessage ? (
                    <p
                      role={findingSaveError ? 'alert' : 'status'}
                      className={`${findingSaveError ? 'processing-save-error' : 'ui-success'} processing-save-feedback`}
                    >
                      {findingSaveError ? (
                        <AlertCircle size={15} aria-hidden="true" />
                      ) : (
                        <Check size={15} aria-hidden="true" />
                      )}
                      {findingMessage}
                    </p>
                  ) : (
                    <span className="settings-save-state">
                      <span className={findingDirty ? 'is-dirty' : ''} />
                      {findingDirty ? 'Unsaved changes' : 'Settings are up to date'}
                    </span>
                  )}
                  <div className="settings-action-buttons">
                    {findingDirty && (
                      <button
                        type="button"
                        className="ui-secondary"
                        disabled={pending > 0}
                        onClick={() => {
                          setFindingForm(findingDispatchSettings(settings));
                          setConfidenceDrafts({
                            queued: String(settings.autoDispatchConfidenceThreshold ?? 90),
                            review: String(settings.reviewConfidenceThreshold ?? 0),
                          });
                          setFindingMessage('');
                          setFindingSaveError(false);
                        }}
                      >
                        <RotateCcw size={14} aria-hidden="true" />
                        Reset changes
                      </button>
                    )}
                    <button type="submit" disabled={pending > 0 || !findingDirty || findingInvalid} className="ui-primary">
                      {pending > 0 ? (
                        <LoaderCircle size={14} className="animate-spin" aria-hidden="true" />
                      ) : (
                        <Save size={14} aria-hidden="true" />
                      )}
                      {pending > 0 ? 'Saving…' : 'Save settings'}
                    </button>
                  </div>
                </div>
              </form>
            </div>
          )}

          <div id="settings-security" hidden={activeSection !== 'security'} className="space-y-6">
            {admin && (
              <form
                id="security-policy-form"
                className="ui-card space-y-5"
                aria-labelledby="account-security-policy-title"
                onChangeCapture={() => setSecurityMessage('')}
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (pending > 0 || !securityDirty) return;
                  setSecurityMessage('');
                  setConfirmSecuritySave({
                    id: 'security-policy',
                    action: 'save',
                    label: 'Security policy',
                  });
                }}
              >
                <SectionHeading
                  icon={Clock}
                  id="account-security-policy-title"
                  title="Login timeout & password policy"
                  description="Session expiry, password strength, and brute-force lockout for operator accounts."
                />

                <div className="grid gap-x-5 gap-y-4 sm:grid-cols-2">
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Session timeout
                    <span className="ml-1 font-normal text-zinc-500">(minutes)</span>
                    <input
                      type="number"
                      min={5}
                      max={60}
                      required
                      className={field}
                      value={securityForm.sessionTimeoutMins}
                      onChange={(e) =>
                        setSecurityForm({
                          ...securityForm,
                          sessionTimeoutMins: Math.min(60, Math.max(5, Number(e.target.value) || 5)),
                        })
                      }
                    />
                    <span className="ui-description mt-1.5 block">
                      Inactive authenticated sessions are signed out after this period. Applied on the next
                      login.
                    </span>
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Minimum password length
                    <span className="ml-1 font-normal text-zinc-500">(characters)</span>
                    <input
                      type="number"
                      min={14}
                      max={128}
                      required
                      className={field}
                      value={securityForm.minPasswordLen}
                      onChange={(e) =>
                        setSecurityForm({
                          ...securityForm,
                          minPasswordLen: Math.min(128, Math.max(14, Number(e.target.value) || 14)),
                        })
                      }
                    />
                    <span className="ui-description mt-1.5 block">
                      Length enforced for new and changed passwords. Existing passwords are unaffected until
                      the operator updates them.
                    </span>
                  </label>
                </div>

                <div className="sm:col-span-2 mt-1 border-t border-zinc-800/70 pt-4 light:border-zinc-200">
                  <h3 className="text-xs font-semibold text-zinc-200 light:text-zinc-800">
                    Login attempt limits
                  </h3>
                  <p className="ui-description mt-1">
                    Repeated failed sign-ins are blocked for a cooling-off period. The threshold is tracked
                    per account and per source IP to resist distributed guessing.
                  </p>
                </div>
                <div className="grid gap-x-5 gap-y-4 sm:grid-cols-2">
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Failed attempts before lockout
                    <input
                      type="number"
                      min={1}
                      max={20}
                      required
                      className={field}
                      value={securityForm.maxLoginAttempts}
                      onChange={(e) =>
                        setSecurityForm({
                          ...securityForm,
                          maxLoginAttempts: Math.min(20, Math.max(1, Number(e.target.value) || 1)),
                        })
                      }
                    />
                    <span className="ui-description mt-1.5 block">
                      Consecutive failed sign-ins against a single account before it is temporarily locked.
                    </span>
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Lockout duration
                    <span className="ml-1 font-normal text-zinc-500">(minutes)</span>
                    <input
                      type="number"
                      min={1}
                      max={60}
                      required
                      className={field}
                      value={securityForm.lockoutMins}
                      onChange={(e) =>
                        setSecurityForm({
                          ...securityForm,
                          lockoutMins: Math.min(60, Math.max(1, Number(e.target.value) || 1)),
                        })
                      }
                    />
                    <span className="ui-description mt-1.5 block">
                      How long a locked account stays locked before another sign-in can be attempted.
                    </span>
                  </label>
                </div>

                <p className="rounded-xl border border-zinc-800 bg-zinc-950/30 px-4 py-3 text-xs leading-relaxed text-zinc-400 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-600">
                  CSRF protection, secure cookie attributes, and HTTP security headers are enforced at runtime
                  and cannot be relaxed from the application.
                </p>

                <div className="ui-actions justify-between">
                  {securityMessage ? (
                    <p role="status" className="ui-success inline-flex items-center gap-2">
                      <Check className="h-3.5 w-3.5" aria-hidden="true" /> {securityMessage}
                    </p>
                  ) : (
                    <span className="settings-save-state">
                      <span className={securityDirty ? 'is-dirty' : ''} />
                      {securityDirty ? 'Unsaved changes' : 'Settings are up to date'}
                    </span>
                  )}
                  <div className="settings-action-buttons">
                    {securityDirty && (
                      <button
                        type="button"
                        className="ui-secondary"
                        disabled={pending > 0}
                        onClick={() => {
                          setSecurityForm(settings.securityPolicy);
                          setSecurityMessage('');
                        }}
                      >
                        <RotateCcw size={14} />
                        Reset changes
                      </button>
                    )}
                    <button type="submit" disabled={pending > 0 || !securityDirty} className="ui-primary">
                      {pending > 0 ? <LoaderCircle size={14} className="animate-spin" /> : <Save size={14} />}
                      {pending > 0 ? 'Saving…' : 'Save policy'}
                    </button>
                  </div>
                </div>
              </form>
            )}

            <form
              className="ui-card space-y-5"
              aria-labelledby="account-security-title"
              onSubmit={async (e) => {
                e.preventDefault();
                if (pending > 0) return;
                setConfirmChangePassword({
                  id: 'change-password',
                  action: 'change',
                  label: 'Account password',
                });
              }}
            >
              <SectionHeading
                icon={ShieldCheck}
                id="account-security-title"
                title="Change password"
                description="Update the password used to sign in to this account."
              />
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                  Current password
                  <input
                    type="password"
                    autoComplete="current-password"
                    required
                    maxLength={128}
                    className={field}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                  />
                </label>
                <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                  New password
                  <input
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={settings.securityPolicy.minPasswordLen}
                    maxLength={128}
                    className={field}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                  />
                  <span className="ui-description mt-1.5 block">
                    Use at least {settings.securityPolicy.minPasswordLen} characters.
                  </span>
                </label>
              </div>
              <div className="ui-actions justify-between">
                <p className="inline-flex items-center gap-2 text-xs text-zinc-400 light:text-zinc-600">
                  <LockKeyhole className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  Changing your password signs out all active sessions.
                </p>
                <button type="submit" disabled={pending > 0} className="ui-primary">
                  <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                  Change password
                </button>
              </div>
            </form>
          </div>

          {admin && (
            <section
              id="settings-access"
              hidden={activeSection !== 'access'}
              className="ui-card space-y-5"
              aria-labelledby="operator-accounts-title"
            >
              <SectionHeading
                icon={Users}
                id="operator-accounts-title"
                title="Workspace access"
                description="Manage who can access this workspace and what they can do."
              />
              <details className="settings-role-guide">
                <summary>
                  <ShieldCheck size={14} />
                  Understand access roles
                  <ChevronRight size={13} />
                </summary>{' '}
                <div className="grid gap-2 sm:grid-cols-3">
                  {[
                    ['Admin', 'Configuration and account management'],
                    ['Operator', 'Inventory and pipeline runs'],
                    ['Viewer', 'Read-only workspace access'],
                  ].map(([name, description]) => (
                    <div
                      key={name}
                      className="rounded-xl border border-zinc-800/80 bg-zinc-950/25 px-3.5 py-3 light:border-zinc-200 light:bg-zinc-50"
                    >
                      <p className="text-xs font-semibold">{name}</p>
                      <p className="ui-description mt-1">{description}</p>
                    </div>
                  ))}
                </div>
              </details>
              <div className="grid grid-cols-3 gap-2" aria-label="Account totals">
                {[
                  [
                    'Active',
                    users.filter((user) => !user.disabled).length,
                    'text-emerald-300 light:text-emerald-700',
                  ],
                  ['Disabled', users.filter((user) => user.disabled).length, 'text-zinc-400'],
                  [
                    'Admins',
                    users.filter((user) => user.role === 'ADMIN').length,
                    'text-blue-300 light:text-blue-700',
                  ],
                ].map(([label, count, color]) => (
                  <div
                    key={String(label)}
                    className="rounded-xl border border-zinc-800/80 bg-zinc-950/25 px-3 py-2.5 light:border-zinc-200 light:bg-zinc-50"
                  >
                    <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">{label}</p>
                    <p className={`mt-1 text-lg font-semibold tabular-nums ${color}`}>{count}</p>
                  </div>
                ))}
              </div>

              <details className="settings-create-account">
                <summary>
                  <span>
                    <Plus size={15} />
                    Add workspace account
                  </span>
                  <ChevronRight size={14} />
                </summary>
                <form
                  className="grid gap-4 rounded-xl border border-zinc-800/80 bg-zinc-950/25 p-4 sm:grid-cols-2 xl:grid-cols-2 xl:items-end light:border-zinc-200 light:bg-zinc-50"
                  onSubmit={async (e) => {
                    e.preventDefault();
                    if (!username.trim() || !password || !role) {
                      setAccountMessage('Username, password, and role are required.');
                      return;
                    }
                    // Without an address there is nowhere to send a reset code,
                    // so it is part of what makes an account usable.
                    if (!email.trim()) {
                      setAccountMessage('An email address is required for password reset.');
                      return;
                    }
                    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
                      setAccountMessage('Enter a valid email address, for example name@company.com.');
                      return;
                    }
                    if (password.length < 14) {
                      setAccountMessage('Password must be at least 14 characters.');
                      return;
                    }
                    if (!/^[a-zA-Z0-9._@-]{3,100}$/.test(username)) {
                      setAccountMessage(
                        'Username can only contain letters, numbers, periods, underscores, at signs, and hyphens.',
                      );
                      return;
                    }
                    setAccountMessage('');
                    setConfirmCreateUser({
                      id: 'create-user',
                      action: 'create',
                      label: `Workspace account "${username.trim()}"`,
                    });
                  }}
                >
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Username
                    <input
                      required
                      pattern="[a-zA-Z0-9._@\-]{3,100}"
                      autoComplete="username"
                      className={field}
                      value={username}
                      onChange={(e) => {
                        setUsername(e.target.value);
                        setAccountMessage('');
                      }}
                    />
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Initial password
                    <input
                      type="password"
                      autoComplete="new-password"
                      required
                      minLength={14}
                      maxLength={128}
                      className={field}
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        setAccountMessage('');
                      }}
                    />
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Reset email address
                    <input
                      type="email"
                      required
                      autoComplete="email"
                      maxLength={254}
                      placeholder="name@company.com"
                      className={field}
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        setAccountMessage('');
                      }}
                    />
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Access role
                    <select
                      className={field}
                      value={role}
                      onChange={(e) => {
                        setRole(e.target.value);
                        setAccountMessage('');
                      }}
                    >
                      <option>VIEWER</option>
                      <option>OPERATOR</option>
                      <option>ADMIN</option>
                    </select>
                  </label>
                  <button type="submit" disabled={pending > 0} className="ui-primary lg:mb-0">
                    <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                    Create account
                  </button>
                  {accountMessage && (
                    <p
                      role="status"
                      className={`text-xs sm:col-span-2 xl:col-span-2 ${accountMessage.includes('successfully') ? 'text-emerald-400 light:text-emerald-700' : 'text-rose-400 light:text-rose-700'}`}
                    >
                      {accountMessage}
                    </p>
                  )}
                </form>
              </details>

              <div>
                <div className="mb-2 flex items-center justify-between gap-3">
                  <h3 className="text-xs font-semibold">Workspace accounts</h3>
                  <span className="ui-description">
                    {usersLoading ? '…' : users.length} {users.length === 1 ? 'account' : 'accounts'}
                  </span>
                </div>
                {usersLoading ? (
                  <div className="settings-empty">
                    <LoaderCircle size={22} className="animate-spin" />
                    <p>Loading workspace accounts…</p>
                  </div>
                ) : usersError ? (
                  <div className="settings-empty" role="alert">
                    <AlertCircle size={22} />
                    <p>{usersError}</p>
                    <button type="button" className="ui-secondary" onClick={() => void reloadUsers()}>
                      Retry
                    </button>
                  </div>
                ) : users.length ? (
                  <ul className="divide-y divide-zinc-800/80 overflow-hidden rounded-xl border border-zinc-800/80 light:divide-zinc-200 light:border-zinc-200">
                    {[...users]
                      .sort(
                        (a, b) =>
                          Number(a.disabled) - Number(b.disabled) || a.username.localeCompare(b.username),
                      )
                      .map((user) => (
                        <li
                          key={user.id}
                          className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                        >
                          <div className="settings-user-identity">
                            <span className="settings-user-avatar">
                              {user.username.slice(0, 1).toUpperCase()}
                            </span>
                            <div className="min-w-0">
                              <p className="truncate text-sm font-medium">{user.username}</p>
                              <p className="truncate text-[11px] text-zinc-500 light:text-zinc-600">
                                {user.email || 'No reset email set'}
                              </p>
                              <div className="mt-1.5 flex flex-wrap items-center gap-2">
                                <span
                                  className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                                    user.role === 'ADMIN'
                                      ? 'border-blue-500/25 bg-blue-500/10 text-blue-300 light:text-blue-700'
                                      : user.role === 'OPERATOR'
                                        ? 'border-violet-500/25 bg-violet-500/10 text-violet-300 light:text-violet-700'
                                        : 'border-zinc-700/80 bg-zinc-800/60 text-zinc-300 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-700'
                                  }`}
                                >
                                  {user.role}
                                </span>
                                <span
                                  className={`inline-flex items-center gap-1.5 text-[10px] ${user.disabled ? 'text-zinc-500' : 'text-emerald-400 light:text-emerald-700'}`}
                                >
                                  <span
                                    className={`h-1.5 w-1.5 rounded-full ${user.disabled ? 'bg-zinc-500' : 'bg-emerald-400'}`}
                                  />
                                  {user.disabled ? 'Disabled' : 'Active'}
                                </span>
                                {user.username === session?.username && (
                                  <span className="text-[10px] text-zinc-500">You</span>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <button
                              type="button"
                              className="min-h-8 rounded-lg border border-zinc-700 px-3 py-1.5 text-[11px] font-medium text-zinc-300 hover:bg-zinc-800 transition light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100"
                              onClick={() => {
                                setEditingUser(user);
                                setEditForm({
                                  username: user.username,
                                  role: user.role,
                                  email: user.email || '',
                                  disabled: !!user.disabled,
                                });
                                setEditMessage('');
                              }}
                            >
                              <Pencil className="h-3 w-3 inline mr-1" />
                              Edit
                            </button>
                            {user.username !== session?.username && !user.disabled && (
                              <button
                                type="button"
                                className="min-h-8 rounded-lg border border-zinc-700 px-3 py-1.5 text-[11px] font-medium text-zinc-300 hover:bg-zinc-800 transition light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100"
                                onClick={() => {
                                  setResetUserId(user.id);
                                  setResetPassword('');
                                }}
                              >
                                <KeyRound className="h-3 w-3 inline mr-1" />
                                Reset password
                              </button>
                            )}
                            {user.username !== session?.username && (
                              <button
                                type="button"
                                className={`min-h-8 rounded-lg border px-3 py-1.5 text-[11px] font-medium transition ${
                                  user.disabled
                                    ? 'border-emerald-500/25 text-emerald-300 hover:bg-emerald-500/10 light:text-emerald-700'
                                    : 'border-zinc-700 text-zinc-300 hover:bg-zinc-800 light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100'
                                }`}
                                disabled={pending > 0 || confirmEnableUser !== null}
                                onClick={async () => {
                                  if (!user.disabled) {
                                    setDisablingUserId(user.id);
                                    return;
                                  }
                                  setConfirmEnableUser({
                                    id: user.id,
                                    action: 'enable',
                                    label: `Account "${user.username}"`,
                                  });
                                }}
                              >
                                {user.disabled ? 'Enable account' : 'Disable account'}
                              </button>
                            )}
                            {user.username !== session?.username && (
                              <button
                                type="button"
                                className="min-h-8 rounded-lg border border-rose-500/25 px-3 py-1.5 text-[11px] font-medium text-rose-300 hover:bg-rose-500/10 transition light:border-rose-200 light:text-rose-700 light:hover:bg-rose-100"
                                disabled={pending > 0}
                                onClick={() => setDeleteUserId(user.id)}
                              >
                                <Trash2 className="h-3 w-3 inline mr-1" />
                                Delete account
                              </button>
                            )}
                          </div>
                        </li>
                      ))}
                  </ul>
                ) : (
                  <p className="rounded-xl border border-dashed border-zinc-700 px-4 py-8 text-center text-xs text-zinc-500 light:border-zinc-300">
                    No operator accounts found.
                  </p>
                )}
              </div>
            </section>
          )}
        </div>
      </div>

      {resetUserId && (
        <SettingsDialog title="Reset operator password" onClose={() => setResetUserId(null)}>
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <button
              aria-label="Close"
              onClick={() => setResetUserId(null)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:text-zinc-500 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
            >
              <span className="text-xl">×</span>
            </button>
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-4">
              Reset password
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Enter a new password for this operator. All active sessions will be signed out.
            </p>
            <input
              type="password"
              autoComplete="new-password"
              required
              minLength={14}
              maxLength={128}
              className={field}
              value={resetPassword}
              onChange={(e) => setResetPassword(e.target.value)}
              placeholder="New password (min 14 characters)"
            />
            <div className="flex justify-end gap-2 mt-4">
              <button
                type="button"
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
                onClick={() => setResetUserId(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
                disabled={pending > 0 || resetPassword.length < 14}
                onClick={async () => {
                  const ok = await resetUserPassword(resetUserId!, resetPassword);
                  if (ok) {
                    await reloadUsers();
                    setResetUserId(null);
                    setResetPassword('');
                  }
                }}
              >
                Reset
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Edit Account Modal */}
      {editingUser && (
        <SettingsDialog title="Edit workspace account" onClose={() => setEditingUser(null)}>
          <form
            className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative space-y-4"
            aria-labelledby="edit-account-title"
            onSubmit={async (e) => {
              e.preventDefault();
              const address = editForm.email.trim();
              if (!address) {
                setEditMessage('An email address is required for password reset.');
                return;
              }
              if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
                setEditMessage('Enter a valid email address, for example name@company.com.');
                return;
              }
                setEditMessage('');
                setConfirmEditUser({
                  id: editingUser?.id ?? '',
                  action: 'update',
                  label: `Workspace account "${editForm.username}"`,
                });
              }}
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h3
                    id="edit-account-title"
                    className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900"
                  >
                    Edit workspace account
                  </h3>
                <p className="mt-1 text-xs text-zinc-400 light:text-zinc-600">
                  The username <strong>{editForm.username}</strong> is the login and cannot be changed. Use
                  Reset password to set a new one.
                </p>
              </div>
              <button
                type="button"
                aria-label="Close"
                onClick={() => setEditingUser(null)}
                className="text-zinc-500 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
              >
                <span className="text-xl">×</span>
              </button>
            </div>
            <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
              Reset email address
              <input
                type="email"
                required
                maxLength={254}
                className={field}
                value={editForm.email}
                onChange={(e) => {
                  setEditForm((f) => ({ ...f, email: e.target.value }));
                  setEditMessage('');
                }}
              />
            </label>
            <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
              Access role
              <select
                className={field}
                value={editForm.role}
                // The server refuses to demote or disable your own account; the
                // control is locked here so the reason is visible before saving.
                disabled={editingUser.id === users.find((u) => u.username === session?.username)?.id}
                onChange={(e) => setEditForm((f) => ({ ...f, role: e.target.value }))}
              >
                <option>VIEWER</option>
                <option>OPERATOR</option>
                <option>ADMIN</option>
              </select>
            </label>
            <label className="flex items-center gap-2 text-xs text-zinc-300 light:text-zinc-700">
              <input
                type="checkbox"
                checked={editForm.disabled}
                disabled={editingUser.id === users.find((u) => u.username === session?.username)?.id}
                onChange={(e) => setEditForm((f) => ({ ...f, disabled: e.target.checked }))}
              />
              Account disabled (cannot sign in; active sessions are revoked)
            </label>
            {editMessage && (
              <p role="alert" className="text-xs text-rose-400 light:text-rose-700">
                {editMessage}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setEditingUser(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={pending > 0}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Saving…' : 'Save changes'}
              </button>
            </div>
          </form>
        </SettingsDialog>
      )}

      {/* Disable Account Confirmation Modal */}
      {disablingUserId && (
        <SettingsDialog title="Disable operator account" onClose={() => setDisablingUserId(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-rose-300 dark:text-rose-300 light:text-rose-700 mb-2">
              Disable Operator Account?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to disable this account? The operator will be unable to sign in until the
              account is re-enabled, and any active sessions are revoked.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDisablingUserId(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  const target = users.find((u) => u.id === disablingUserId);
                  if (!target) {
                    setDisablingUserId(null);
                    return;
                  }
                  await updateUser(target.id, { role: target.role, disabled: true });
                  await reloadUsers();
                  setDisablingUserId(null);
                }}
                disabled={pending > 0}
                className="px-3.5 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Disabling…' : 'Disable Account'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Delete Account Confirmation Modal */}
      {deleteUserId && (
        <SettingsDialog title="Delete operator account" onClose={() => setDeleteUserId(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-rose-300 dark:text-rose-300 light:text-rose-700 mb-2">
              Delete Operator Account?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              This action is permanent. The operator will be removed from the workspace and all active
              sessions will be revoked. This cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeleteUserId(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  const target = users.find((u) => u.id === deleteUserId);
                  if (!target) {
                    setDeleteUserId(null);
                    return;
                  }
                  await deleteUser(target.id);
                  await reloadUsers();
                  setDeleteUserId(null);
                }}
                disabled={pending > 0}
                className="px-3.5 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Deleting…' : 'Delete Account'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Processing Toggle Confirmation */}
      {confirmProcessingToggle && (
        <SettingsDialog title="Confirm processing change" onClose={() => setConfirmProcessingToggle(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {confirmProcessingToggle.action === 'enable' ? 'Enable' : 'Disable'} {confirmProcessingToggle.label}?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to {confirmProcessingToggle.action} {confirmProcessingToggle.label.toLowerCase()}? The change will be saved with your processing settings.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmProcessingToggle(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeProcessingToggle}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Saving…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Processing Save Confirmation */}
      {confirmProcessingSave && (
        <SettingsDialog title="Confirm save processing settings" onClose={() => setConfirmProcessingSave(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">Save processing settings?</h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              This will persist scheduler, digest, retry, email, and self-healing changes to the server.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmProcessingSave(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeProcessingSave}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Saving…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Finding Dispatch Toggle Confirmation */}
      {confirmFindingToggle && (
        <SettingsDialog title="Confirm finding dispatch change" onClose={() => setConfirmFindingToggle(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {confirmFindingToggle.action === 'enable' ? 'Enable' : 'Disable'} {confirmFindingToggle.label}?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to {confirmFindingToggle.action} {confirmFindingToggle.label.toLowerCase()}? The change will be saved with your finding dispatch settings.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmFindingToggle(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeFindingToggle}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Saving…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Finding Dispatch Save Confirmation */}
      {confirmFindingSave && (
        <SettingsDialog title="Confirm save finding dispatch settings" onClose={() => setConfirmFindingSave(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">Save finding dispatch settings?</h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              This will persist automatic dispatch and confidence threshold changes to the server.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmFindingSave(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeFindingSave}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Saving…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Security Policy Save Confirmation */}
      {confirmSecuritySave && (
        <SettingsDialog title="Confirm save security policy" onClose={() => setConfirmSecuritySave(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">Save security policy?</h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              This will persist session timeout, password length, and lockout settings to the server.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmSecuritySave(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeSecuritySave}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Saving…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Change Password Confirmation */}
      {confirmChangePassword && (
        <SettingsDialog title="Confirm password change" onClose={() => setConfirmChangePassword(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">Change password?</h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Changing your password will sign out all active sessions.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmChangePassword(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeChangePassword}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Changing…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Create User Confirmation */}
      {confirmCreateUser && (
        <SettingsDialog title="Confirm create operator" onClose={() => setConfirmCreateUser(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">Create operator account?</h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to create the account {confirmCreateUser.label}?
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmCreateUser(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeCreateUser}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Creating…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Edit User Confirmation */}
      {confirmEditUser && (
        <SettingsDialog title="Confirm save workspace account" onClose={() => setConfirmEditUser(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">Save account changes?</h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to save changes to {confirmEditUser.label}?
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmEditUser(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeEditUser}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Saving…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}

      {/* Enable User Confirmation */}
      {confirmEnableUser && (
        <SettingsDialog title="Confirm enable operator account" onClose={() => setConfirmEnableUser(null)}>
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">Enable account?</h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to re-enable {confirmEnableUser.label}? The operator will be able to sign in again.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmEnableUser(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pending > 0}
                onClick={executeEnableUser}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Enabling…' : 'Confirm'}
              </button>
            </div>
          </div>
        </SettingsDialog>
      )}
    </div>
  );
}
