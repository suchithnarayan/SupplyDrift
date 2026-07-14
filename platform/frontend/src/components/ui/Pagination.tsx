import {ChevronLeft, ChevronRight} from "lucide-react";

interface Props {
  page: number;
  totalPages: number;
  total: number;
  onPage: (p: number) => void;
}

/** Compact prev/next pager with a "N items · page X of Y" label. */
export function Pagination({page, totalPages, total, onPage}: Props) {
  if (total === 0) return null;
  const btn =
    "grid h-8 w-8 place-items-center rounded-lg ring-1 ring-white/10 bg-white/[0.03] text-muted transition hover:text-ink disabled:cursor-not-allowed disabled:opacity-30";
  return (
    <div className="flex items-center justify-between gap-3 pt-1">
      <span className="text-xs text-faint">
        {total.toLocaleString()} {total === 1 ? "item" : "items"}
        {totalPages > 1 && ` · page ${page} of ${totalPages}`}
      </span>
      {totalPages > 1 && (
        <div className="flex items-center gap-1">
          <button className={btn} disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
            <ChevronLeft className="h-4 w-4" />
          </button>
          <button
            className={btn}
            disabled={page >= totalPages}
            onClick={() => onPage(page + 1)}
            aria-label="Next page"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
}
