import type {ReactNode} from "react";
import {cn} from "../../lib/cn";

export function DataTable({columns, children}: {columns: string[]; children: ReactNode}) {
  return (
    <div className="glass overflow-hidden p-0">
      <div className="max-h-[70vh] overflow-auto">
        <table className="w-full border-collapse text-sm">
          <thead className="sticky top-0 z-10">
            <tr className="border-b border-white/8">
              {columns.map((c) => (
                <th
                  key={c}
                  className="bg-[#0e1424] px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-faint"
                >
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>{children}</tbody>
        </table>
      </div>
    </div>
  );
}

export function Row({children, onClick, className}: {children: ReactNode; onClick?: () => void; className?: string}) {
  return (
    <tr
      onClick={onClick}
      className={cn(
        "border-b border-white/5 transition-colors last:border-0",
        onClick && "cursor-pointer hover:bg-white/[0.04]",
        className,
      )}
    >
      {children}
    </tr>
  );
}

export function Cell({children, className}: {children: ReactNode; className?: string}) {
  return <td className={cn("px-4 py-3 align-middle text-ink/90", className)}>{children}</td>;
}
