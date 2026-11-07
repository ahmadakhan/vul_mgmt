import React from 'react';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';

interface PaginationProps {
  currentPage: number;
  totalItems: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  pageSizeOptions?: number[];
}

export const Pagination: React.FC<PaginationProps> = ({
  currentPage,
  totalItems,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [10, 25, 50],
}) => {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  React.useEffect(() => {
    if (currentPage > totalPages) onPageChange(totalPages);
  }, [currentPage, totalPages, onPageChange]);
  const startItem = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endItem = Math.min(totalItems, currentPage * pageSize);

  // Generate page numbers to show
  const getPageNumbers = () => {
    const pages: (number | string)[] = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      if (currentPage > 3) pages.push('...');

      const start = Math.max(2, currentPage - 1);
      const end = Math.min(totalPages - 1, currentPage + 1);
      for (let i = start; i <= end; i++) pages.push(i);

      if (currentPage < totalPages - 2) pages.push('...');
      pages.push(totalPages);
    }
    return pages;
  };

  return (
    <div className="ui-pagination flex flex-col sm:flex-row items-center justify-between gap-3 px-4 py-3 border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
      {/* Items count & page size */}
      <div className="flex items-center space-x-3">
        <span className="font-mono text-[11px]">
          Showing{' '}
          <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900">{startItem}</strong>-
          <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900">{endItem}</strong> of{' '}
          <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900">{totalItems}</strong>{' '}
          records
        </span>

        {onPageSizeChange && (
          <div className="flex items-center space-x-1.5 text-[11px] font-mono">
            <span>Per page:</span>
            <select
              aria-label="Records per page"
              value={pageSize}
              onChange={(e) => {
                onPageSizeChange(Number(e.target.value));
                onPageChange(1);
              }}
              className="bg-zinc-950 dark:bg-zinc-950 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded px-1.5 py-0.5 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 focus:outline-none"
            >
              {pageSizeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Pagination Controls */}
      <nav aria-label="Table pagination" className="flex items-center space-x-1">
        <button
          onClick={() => onPageChange(1)}
          disabled={currentPage === 1}
          className="p-1 rounded-lg border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 disabled:opacity-30 disabled:pointer-events-none text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
          title="First Page"
          aria-label="First Page"
        >
          <ChevronsLeft className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="p-1 rounded-lg border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 disabled:opacity-30 disabled:pointer-events-none text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
          title="Previous Page"
          aria-label="Previous Page"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </button>

        <div className="flex items-center space-x-1 px-1">
          {getPageNumbers().map((p, idx) =>
            typeof p === 'string' ? (
              <span
                key={`ellipsis-${idx}`}
                className="px-1.5 py-0.5 text-zinc-500 light:text-zinc-400 font-mono text-xs"
              >
                ...
              </span>
            ) : (
              <button
                key={p}
                aria-label={`Page ${p}`}
                aria-current={currentPage === p ? 'page' : undefined}
                onClick={() => onPageChange(p)}
                className={`min-w-[26px] h-[26px] rounded-lg font-mono text-xs flex items-center justify-center transition ${
                  currentPage === p
                    ? 'bg-zinc-100 text-zinc-950 font-bold dark:bg-zinc-100 dark:text-zinc-950 light:bg-zinc-900 light:text-zinc-50 shadow-sm'
                    : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 hover:bg-zinc-800/60 dark:hover:bg-zinc-800/60 light:hover:bg-zinc-200'
                }`}
              >
                {p}
              </button>
            ),
          )}
        </div>

        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="p-1 rounded-lg border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 disabled:opacity-30 disabled:pointer-events-none text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
          title="Next Page"
          aria-label="Next Page"
        >
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => onPageChange(totalPages)}
          disabled={currentPage === totalPages}
          className="p-1 rounded-lg border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 disabled:opacity-30 disabled:pointer-events-none text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
          title="Last Page"
          aria-label="Last Page"
        >
          <ChevronsRight className="w-3.5 h-3.5" />
        </button>
      </nav>
    </div>
  );
};
