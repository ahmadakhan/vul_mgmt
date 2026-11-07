import React, { useState, useRef } from 'react';
import { PageHeading } from './PageHeading';
import { useApp } from '../context/AppContext';
import type { AliasEntry } from '../types';
import { DEFAULT_VENDOR_ALIASES, DEFAULT_PRODUCT_ALIASES } from '../utils/cpeMatcher';
import {
  Tags,
  Plus,
  Trash2,
  Pencil,
  X,
  Search,
  AlertCircle,
  Lock,
  Info,
  ShieldCheck,
  Ban,
  Clock,
  Sparkles,
  ArrowRight,
  Loader2,
} from 'lucide-react';
import { formatDate, formatDateTime } from '../utils/dateTime';
import { useDialogFocus } from '../hooks/useDialogFocus';
import './investigation-pages.css';
import './aliases.css';

type Scope = AliasEntry['scope'];
type SourceFilter = 'ALL' | 'MANUAL' | 'AUTO' | 'REVOKED';
const namesFor = (entry: AliasEntry) =>
  entry.source === 'REVOKED' ? (entry.revokedAliases ?? []) : entry.aliases;
const sourceFor = (entry: AliasEntry) => entry.source ?? 'MANUAL';
function AliasDialog({
  title,
  children,
  onClose,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}) {
  const ref = useDialogFocus(onClose);
  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabIndex={-1}
      className="alias-dialog"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="ui-panel">{children}</div>
    </div>
  );
}
export const AliasesView: React.FC = () => {
  const { aliases, addAlias, updateAlias, deleteAlias, promoteAlias, revokeAlias, session, settings } =
    useApp();
  const admin = session?.role === 'ADMIN';
  const [scope, setScope] = useState<Scope>('VENDOR');
  const [search, setSearch] = useState('');
  const [source, setSource] = useState<SourceFilter>('ALL');
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState<AliasEntry | null>(null);
  const [deleting, setDeleting] = useState<AliasEntry | null>(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmChangeSource, setConfirmChangeSource] = useState<{ id: string; action: 'promote' | 'revoke'; label: string } | null>(null);
  const [confirmingAliasSave, setConfirmingAliasSave] = useState(false);
  const pendingAliasSave = useRef<{ payload: { scope: Scope; canonical: string; aliases: string[]; notes?: string }; isEdit: boolean } | null>(null);
  const [form, setForm] = useState({ canonical: '', aliasText: '', notes: '' });
  const term = search.trim().toLowerCase();
  const managed = aliases.filter((entry) => entry.scope === scope);
  const filtered = managed
    .filter(
      (entry) =>
        (source === 'ALL' || sourceFor(entry) === source) &&
        [entry.canonical, ...namesFor(entry), entry.notes || ''].some((value) =>
          value.toLowerCase().includes(term),
        ),
    )
    .sort((a, b) => a.canonical.localeCompare(b.canonical));
  const defaults = Object.entries(scope === 'VENDOR' ? DEFAULT_VENDOR_ALIASES : DEFAULT_PRODUCT_ALIASES)
    .filter(([canonical, names]) => [canonical, ...names].some((value) => value.toLowerCase().includes(term)))
    .sort(([a], [b]) => a.localeCompare(b));
  const openForm = (entry: AliasEntry | null = null) => {
    setEditing(entry);
    setForm({
      canonical: entry?.canonical ?? '',
      aliasText: entry?.aliases.join(', ') ?? '',
      notes: entry?.notes ?? '',
    });
    setError('');
    setMessage('');
    setShowModal(true);
  };
  const closeForm = () => {
    if (!busy) {
      setShowModal(false);
      setError('');
    }
  };
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy || confirmingAliasSave) return;
    setError('');
    const canonical = form.canonical.trim().toLowerCase();
    const names = [
      ...new Set(
        form.aliasText
          .split(/[,\n]/)
          .map((value) => value.trim().toLowerCase())
          .filter(Boolean),
      ),
    ];
    if (!canonical || !names.length)
      return setError('Enter a canonical name and at least one alternate name.');
    if (names.length > 50 || names.some((name) => name.length > 200))
      return setError('Use up to 50 alternate names, with no more than 200 characters each.');
    pendingAliasSave.current = {
      payload: {
        scope: editing?.scope ?? scope,
        canonical,
        aliases: names,
        notes: form.notes.trim() || undefined,
      },
      isEdit: Boolean(editing),
    };
    setConfirmingAliasSave(true);
  };

  const executeConfirmedAliasSave = async () => {
    const pending = pendingAliasSave.current;
    if (!pending) return;
    setConfirmingAliasSave(false);
    setBusy(true);
    setError('');
    try {
      const { payload, isEdit } = pending;
      const saved = isEdit
        ? await updateAlias({ ...editing!, ...payload })
        : await addAlias(payload);
      if (!saved) return setError('Could not save this mapping. Review the fields and try again.');
      setShowModal(false);
      setMessage(isEdit ? 'Alias mapping updated.' : 'Alias mapping added.');
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not save this mapping.');
    } finally {
      setBusy(false);
      pendingAliasSave.current = null;
    }
  };
  const changeSource = (entry: AliasEntry, action: 'promote' | 'revoke') => {
    if (busy) return;
    setConfirmChangeSource({ id: entry.id, action, label: entry.canonical });
  };

  const executeConfirmedChangeSource = async () => {
    if (!confirmChangeSource) return;
    const { id, action, label } = confirmChangeSource;
    setBusy(true);
    setError('');
    setMessage('');
    try {
      const ok = action === 'promote' ? await promoteAlias(id) : await revokeAlias(id);
      if (!ok) setError(`Could not ${action} this mapping. Please retry.`);
      else
        setMessage(
          action === 'promote'
            ? 'Mapping kept as a permanent operator alias.'
            : 'Mapping revoked. This relation will not be learned again.',
        );
    } catch {
      setError('Could not update this mapping. Please retry.');
    } finally {
      setBusy(false);
      setConfirmChangeSource(null);
    }
  };
  const remove = async () => {
    if (!deleting || busy) return;
    setBusy(true);
    setError('');
    try {
      if (await deleteAlias(deleting.id)) {
        setDeleting(null);
        setMessage('Alias mapping removed.');
      } else setError('Could not remove this mapping. Please retry.');
    } catch {
      setError('Could not remove this mapping. Please retry.');
    } finally {
      setBusy(false);
    }
  };
  const clearFilters = () => {
    setSearch('');
    setSource('ALL');
  };
  return (
    <div className="aliases-page space-y-6">
      <header className="ui-page-header">
        <PageHeading page="aliases">
          Connect alternate vendor and product names so inventory and vulnerability records resolve to the
          same identity.
        </PageHeading>
        {admin ? (
            <button type="button" className="ui-primary" onClick={() => openForm()} disabled={confirmChangeSource !== null || confirmingAliasSave}>
              <Plus size={16} aria-hidden="true" />
              Add alias mapping
          </button>
        ) : (
          <span className="alias-readonly">
            <Lock size={14} aria-hidden="true" />
            Read-only access
          </span>
        )}
      </header>
      <div className="alias-toolbar ui-panel">
        <div className="investigation-tabs" aria-label="Alias scope">
          {(['VENDOR', 'PRODUCT'] as const).map((value) => (
            <button
              type="button"
              key={value}
              aria-pressed={scope === value}
              onClick={() => {
                setScope(value);
                setError('');
                setMessage('');
              }}
            >
              <Tags size={15} aria-hidden="true" />
              {value === 'VENDOR' ? 'Vendor aliases' : 'Product aliases'}
            </button>
          ))}
        </div>
        <div className="alias-search">
          <Search size={16} aria-hidden="true" />
          <input
            aria-label="Search aliases"
            placeholder="Search canonical or alternate names…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          {search && (
            <button type="button" aria-label="Clear alias search" onClick={() => setSearch('')}>
              <X size={14} />
            </button>
          )}
        </div>
      </div>
      <div className="alias-summary">
        {[
          {
            label: 'Operator managed',
            count: managed.filter((entry) => sourceFor(entry) === 'MANUAL').length,
            icon: ShieldCheck,
            hint: 'Permanent mappings',
          },
          {
            label: 'Learned automatically',
            count: managed.filter((entry) => entry.source === 'AUTO').length,
            icon: Sparkles,
            hint: 'Supported by inventory or findings',
          },
          {
            label: 'Revoked relations',
            count: managed.filter((entry) => entry.source === 'REVOKED').length,
            icon: Ban,
            hint: 'Blocked from matching and re-learning',
          },
        ].map(({ label, count, icon: Icon, hint }) => (
          <div className="ui-panel" key={label}>
            <div>
              <span>{label}</span>
              <strong>{count}</strong>
              <p>{hint}</p>
            </div>
            <Icon size={19} aria-hidden="true" />
          </div>
        ))}
      </div>
      {message && (
        <p className="alias-feedback" role="status">
          <ShieldCheck size={16} aria-hidden="true" />
          {message}
        </p>
      )}
      {error && !showModal && !deleting && (
        <p className="alias-feedback is-error" role="alert">
          <AlertCircle size={16} aria-hidden="true" />
          {error}
        </p>
      )}
      <section className="ui-panel alias-mappings" aria-labelledby="managed-aliases-title">
        <div className="alias-section-header">
          <div>
            <h2 id="managed-aliases-title">Managed {scope === 'VENDOR' ? 'vendor' : 'product'} mappings</h2>
            <p>Review the names your matching engine treats as equivalent.</p>
          </div>
          <label className="alias-source-filter">
            <span className="sr-only">Filter managed mappings by source</span>
            <select
              aria-label="Filter alias source"
              value={source}
              onChange={(event) => setSource(event.target.value as SourceFilter)}
            >
              <option value="ALL">All sources</option>
              <option value="MANUAL">Operator managed</option>
              <option value="AUTO">Automatically learned</option>
              <option value="REVOKED">Revoked</option>
            </select>
          </label>
        </div>
        <div className="alias-list-status">
          <span aria-live="polite">
            {filtered.length} {filtered.length === 1 ? 'mapping' : 'mappings'}
            {term || source !== 'ALL' ? ` of ${managed.length}` : ''}
          </span>
          {(term || source !== 'ALL') && (
            <button type="button" onClick={clearFilters}>
              Clear filters
            </button>
          )}
        </div>
        {!filtered.length ? (
          <div className="alias-empty">
            <Tags size={28} strokeWidth={1.5} aria-hidden="true" />
            <h3>
              {term || source !== 'ALL' ? 'No mappings match these filters' : 'No managed mappings yet'}
            </h3>
            <p>
              {term || source !== 'ALL'
                ? 'Try another name or source. Built-in mappings are shown below.'
                : 'Add alternate names for your environment, or review mappings learned from supporting evidence.'}
            </p>
            {admin && !term && source === 'ALL' && (
              <button type="button" className="ui-secondary" onClick={() => openForm()}>
                <Plus size={14} />
                Add your first mapping
              </button>
            )}
          </div>
        ) : (
          <div className="alias-list">
            {filtered.map((entry) => (
              <article
                className={`alias-row ${entry.source === 'REVOKED' ? 'is-revoked' : ''}`}
                key={entry.id}
              >
                <div className="alias-row-content">
                  <div className="alias-row-heading">
                    <code>{entry.canonical}</code>
                    <span className={`alias-source source-${sourceFor(entry).toLowerCase()}`}>
                      {entry.source === 'AUTO'
                        ? 'Automatic'
                        : entry.source === 'REVOKED'
                          ? 'Revoked'
                          : 'Operator managed'}
                    </span>
                  </div>
                  <div className="alias-names">
                    <ArrowRight size={14} aria-label="Alternate names" />
                    {namesFor(entry).map((name) => (
                      <code key={name}>{name}</code>
                    ))}
                  </div>
                  {entry.notes && <p className="alias-notes">{entry.notes}</p>}
                  {entry.source === 'AUTO' && (
                    <div className="alias-evidence">
                      <span>
                        {entry.provenance === 'CONFIRMED_CORRELATION'
                          ? 'Confirmed correlation'
                          : 'Inventory evidence'}
                        {entry.evidenceCount ? ` · ${entry.evidenceCount} supporting findings` : ''}
                      </span>
                      {entry.expiresAt && (
                        <span title={`Expires ${formatDateTime(entry.expiresAt, settings.timezone)}`}>
                          <Clock size={12} aria-hidden="true" />
                          Expires {formatDate(entry.expiresAt, settings.timezone)}
                        </span>
                      )}
                    </div>
                  )}
                </div>
                {admin && (
                  <div className="alias-row-actions">
                    {entry.source === 'AUTO' ? (
                      <>
                        <button
                          type="button"
                          disabled={busy || confirmChangeSource !== null || confirmingAliasSave}
                          onClick={() => void changeSource(entry, 'promote')}
                          aria-label={`Keep ${entry.canonical} permanently`}
                        >
                          <ShieldCheck size={14} />
                          Keep
                        </button>
                        <button
                          type="button"
                          disabled={busy || confirmChangeSource !== null || confirmingAliasSave}
                          onClick={() => void changeSource(entry, 'revoke')}
                          aria-label={`Revoke ${entry.canonical}`}
                        >
                          <Ban size={14} />
                          Revoke
                        </button>
                      </>
                    ) : (
                      entry.source !== 'REVOKED' && (
                        <button
                          type="button"
                          disabled={busy || confirmChangeSource !== null || confirmingAliasSave}
                          onClick={() => openForm(entry)}
                          aria-label={`Edit ${entry.canonical}`}
                        >
                          <Pencil size={14} />
                          Edit
                        </button>
                      )
                    )}
                    <button
                      type="button"
                      disabled={busy || confirmChangeSource !== null || confirmingAliasSave}
                      aria-label={`Remove ${entry.canonical}`}
                      onClick={() => {
                        setError('');
                        setDeleting(entry);
                      }}
                    >
                      <Trash2 size={14} />
                      Remove
                    </button>
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </section>
      <details className="ui-panel alias-guidance">
        <summary>
          <Info size={16} aria-hidden="true" />
          How automatic aliases are managed
        </summary>
        <p>
          Inventory aliases come from an active asset’s declared names and CPE identity. Correlation aliases
          require confirmed findings. Automatic mappings expire 30 days after their last supporting evidence.
          Keep a mapping to make it permanent, or revoke it to block matching and re-learning. Operator
          mappings are never changed automatically.
        </p>
      </details>
      <section className="ui-panel alias-mappings" aria-labelledby="baseline-aliases-title">
        <div className="alias-section-header">
          <div>
            <h2 id="baseline-aliases-title">
              <Lock size={15} aria-hidden="true" />
              Built-in baseline
            </h2>
            <p>Reviewed mappings included with the matching engine. Managed mappings extend this baseline.</p>
          </div>
          <span className="alias-readonly">
            {defaults.length} {defaults.length === 1 ? 'mapping' : 'mappings'}
          </span>
        </div>
        <div className="alias-baseline-list">
          {defaults.length ? (
            defaults.map(([canonical, names]) => (
              <div className="alias-baseline-row" key={canonical}>
                <code>{canonical}</code>
                <div className="alias-names">
                  <ArrowRight size={14} aria-hidden="true" />
                  {names.map((name) => (
                    <code key={name}>{name}</code>
                  ))}
                </div>
              </div>
            ))
          ) : (
            <p className="alias-empty">No built-in mappings match your search.</p>
          )}
        </div>
      </section>
      {showModal && (
        <AliasDialog title={editing ? 'Edit alias mapping' : 'Add alias mapping'} onClose={closeForm}>
          <button
            type="button"
            className="alias-dialog-close"
            onClick={closeForm}
            disabled={busy}
            aria-label="Close alias form"
          >
            <X size={19} />
          </button>
          <span className="investigation-icon">
            <Tags size={20} />
          </span>
          <h2>
            {editing ? 'Edit' : 'Add'} {scope === 'VENDOR' ? 'vendor' : 'product'} mapping
          </h2>
          <p>Link a canonical identifier with the alternate names used in your environment.</p>
          {error && (
            <p className="alias-feedback is-error" role="alert">
              <AlertCircle size={16} />
              {error}
            </p>
          )}
          <form onSubmit={submit}>
            <label htmlFor="alias-canonical">
              Canonical name
              <input
                id="alias-canonical"
                required
                maxLength={200}
                value={form.canonical}
                onChange={(event) => setForm({ ...form, canonical: event.target.value })}
                placeholder={scope === 'VENDOR' ? 'e.g. paloaltonetworks' : 'e.g. pan_os'}
              />
              <small>The canonical vendor or product identifier.</small>
            </label>
            <label htmlFor="alias-names">
              Alternate names
              <textarea
                id="alias-names"
                required
                rows={3}
                value={form.aliasText}
                onChange={(event) => setForm({ ...form, aliasText: event.target.value })}
                placeholder="Separate names with commas or new lines"
              />
              <small>Up to 50 names. Duplicate names are combined.</small>
            </label>
            <label htmlFor="alias-notes">
              Notes <span>(optional)</span>
              <textarea
                id="alias-notes"
                maxLength={500}
                rows={2}
                value={form.notes}
                onChange={(event) => setForm({ ...form, notes: event.target.value })}
                placeholder="Context for other operators"
              />
            </label>
            <footer>
              <button type="button" className="ui-secondary" onClick={closeForm} disabled={busy}>
                Cancel
              </button>
              <button type="submit" className="ui-primary" disabled={busy}>
                {busy && <Loader2 size={14} className="animate-spin" />}
                {busy ? 'Saving…' : editing ? 'Save changes' : 'Add mapping'}
              </button>
            </footer>
          </form>
        </AliasDialog>
      )}
      {deleting && (
        <AliasDialog
          title="Remove alias mapping"
          onClose={() => {
            if (!busy) {
              setDeleting(null);
              setError('');
            }
          }}
        >
          <span className="investigation-icon">
            <Trash2 size={20} />
          </span>
          <h2>Remove this mapping?</h2>
          <p>
            <strong>{deleting.canonical}</strong>
            {deleting.source === 'REVOKED'
              ? ' will no longer be blocked from automatic re-learning.'
              : deleting.source === 'AUTO'
                ? ' may be learned again if its supporting evidence remains. Revoke the mapping to block it instead.'
                : ' and its alternate names will be removed from the managed mappings. Built-in mappings and existing findings are unchanged.'}
          </p>
          {error && (
            <p className="alias-feedback is-error" role="alert">
              {error}
            </p>
          )}
          <footer>
            <button
              type="button"
              className="ui-secondary"
              onClick={() => {
                setDeleting(null);
                setError('');
              }}
              disabled={busy}
            >
              Cancel
            </button>
            <button type="button" className="alias-danger" onClick={() => void remove()} disabled={busy}>
              {busy ? 'Removing…' : 'Remove mapping'}
            </button>
          </footer>
        </AliasDialog>
      )}

      {/* Change alias source Confirmation Modal */}
      {confirmChangeSource && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {confirmChangeSource.action === 'promote' ? 'Keep this mapping?' : 'Revoke this mapping?'}
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              <strong>{confirmChangeSource.label}</strong>{' '}
              {confirmChangeSource.action === 'promote'
                ? 'will be kept as a permanent operator alias.'
                : 'will be revoked and blocked from matching and re-learning.'}
              {' '}This cannot be undone automatically.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                className="ui-secondary"
                onClick={() => setConfirmChangeSource(null)}
                disabled={busy}
              >
                Cancel
              </button>
              <button
                type="button"
                className="alias-danger"
                onClick={() => void executeConfirmedChangeSource()}
                disabled={busy}
              >
                {busy ? 'Processing…' : confirmChangeSource.action === 'promote' ? 'Keep mapping' : 'Revoke mapping'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Save alias mapping Confirmation Modal */}
      {confirmingAliasSave && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              {pendingAliasSave.current?.isEdit ? 'Save alias changes?' : 'Add alias mapping?'}
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              This will {pendingAliasSave.current?.isEdit ? 'update' : 'create'} the{' '}
              <strong>{pendingAliasSave.current?.payload.canonical || ''}</strong> alias mapping.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                className="ui-secondary"
                onClick={() => setConfirmingAliasSave(false)}
                disabled={busy}
              >
                Cancel
              </button>
              <button
                type="button"
                className="ui-primary"
                onClick={() => void executeConfirmedAliasSave()}
                disabled={busy}
              >
                {busy ? 'Saving…' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
