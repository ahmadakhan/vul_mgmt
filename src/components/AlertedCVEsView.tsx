import { PageHeading } from './PageHeading';
import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { AlertedCVE } from '../types';
import { Search, Send, X, ShieldCheck } from 'lucide-react';
import { Pagination } from './Pagination';
import { useCollection } from '../hooks/useCollection';
import { CveLink } from './CveLink';
import { formatDateTime as fmtDateTime } from '../utils/dateTime';

export const AlertedCVEsView: React.FC = () => {
  const { counts, resendNotification, settings } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCve, setSelectedCve] = useState<AlertedCVE | null>(null);
  const [resendReason, setResendReason] = useState('');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Server-side search and pagination: the snapshot's alertedCves array is a
  // capped recent slice, not the full dispatch registry.
  const { items: paginatedItems, total } = useCollection<AlertedCVE>('alertedCves', {
    page: currentPage,
    pageSize,
    search: searchTerm,
  });

  const handleConfirmResend = () => {
    if (selectedCve && resendReason.trim()) {
      resendNotification(selectedCve.cveId, resendReason);
      setSelectedCve(null);
      setResendReason('');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="ui-page-header">
        <PageHeading page="alerted-cves">
          Canonical O(1) deduplication cache preventing redundant email alerts across periodic runs. Records
          all automated dispatches.
        </PageHeading>

        <div className="flex items-center space-x-2 text-xs font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-3 py-1.5 rounded-xl shadow-sm">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>O(1) Deduplication Active</span>
        </div>
      </div>

      {/* Search Bar */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm transition-colors">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by CVE, Advisory ID, or recipient..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>

        <div className="text-xs font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
          Total Tracked:{' '}
          <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900">
            {counts.alertedCves}
          </strong>
        </div>
      </div>

      {/* Table */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Canonical CVE ID</th>
                <th className="py-3 px-4">Advisory Reference</th>
                <th className="py-3 px-4">First Dispatched</th>
                <th className="py-3 px-4">Last Dispatched</th>
                <th className="py-3 px-4">Dispatch Count</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {paginatedItems.map((item) => (
                <tr
                  key={item.cveId}
                  className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition"
                >
                  <td className="py-3 px-4 font-mono font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 text-sm">
                    <CveLink cveId={item.cveId} />
                  </td>
                  <td className="py-3 px-4 font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-800">
                    {item.advisoryId}
                  </td>
                  <td className="py-3 px-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono text-[11px]">
                    {fmtDateTime(item.firstAlertedAt, settings.timezone)}
                  </td>
                  <td className="py-3 px-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono text-[11px]">
                    {fmtDateTime(item.lastAlertedAt, settings.timezone)}
                    {item.lastDispatchReason && (
                      <div className="text-[10px] text-zinc-500 light:text-zinc-600 font-sans italic line-clamp-1">
                        Reason: {item.lastDispatchReason}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-4 font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-800">
                    {item.dispatchCount}
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-[10px] font-medium px-2 py-0.5 rounded-full font-mono bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300">
                      {item.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => {
                        setSelectedCve(item);
                        setResendReason('');
                      }}
                      className="px-2.5 py-1 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 font-medium text-xs inline-flex items-center space-x-1 transition"
                    >
                      <Send className="w-3 h-3 text-zinc-400" />
                      <span>Resend</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <Pagination
          currentPage={currentPage}
          totalItems={total}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={(size) => {
            setPageSize(size);
            setCurrentPage(1);
          }}
          pageSizeOptions={[10, 25, 50]}
        />
      </div>

      {/* Resend Modal */}
      {selectedCve && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setSelectedCve(null)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2">
              <Send className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              Resend Notification: <CveLink cveId={selectedCve.cveId} />
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Dispatches an updated vulnerability notice for this product to the security distribution list.
            </p>

            <label className="block text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-mono mb-1">
              Dispatch Rationale / Update Note *
            </label>
            <textarea
              rows={3}
              required
              placeholder="e.g. Vendor released critical updated patch; re-notifying engineering."
              value={resendReason}
              onChange={(e) => setResendReason(e.target.value)}
              className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            />

            <div className="flex justify-end space-x-2 mt-4 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
              <button
                onClick={() => setSelectedCve(null)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmResend}
                disabled={!resendReason.trim()}
                className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold text-xs disabled:opacity-50 transition"
              >
                Dispatch Notification
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
