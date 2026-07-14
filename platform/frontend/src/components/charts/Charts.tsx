import {memo} from "react";
import {assetMeta, SEVERITY_COLOR} from "../../lib/meta";

/** Pure-SVG donut (no chart lib) — cheap to render, no ResizeObserver. */
export const SourceDonut = memo(function SourceDonut({byType}: {byType: Record<string, number>}) {
  const data = Object.entries(byType)
    .filter(([, v]) => v > 0)
    .map(([type, value]) => ({type, value, label: assetMeta(type).label, color: `rgb(${assetMeta(type).glow})`}));
  const total = data.reduce((a, b) => a + b.value, 0) || 1;

  let offset = 0;
  const segments = data.map((d) => {
    const pct = (d.value / total) * 100;
    const seg = {...d, pct, dash: `${pct} ${100 - pct}`, dashoffset: 25 - offset};
    offset += pct;
    return seg;
  });

  return (
    <div className="flex items-center gap-5">
      <svg viewBox="0 0 36 36" className="h-36 w-36 shrink-0 -rotate-90">
        <circle cx="18" cy="18" r="15.915" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="3.4" />
        {segments.map((s) => (
          <circle
            key={s.type}
            cx="18"
            cy="18"
            r="15.915"
            fill="none"
            stroke={s.color}
            strokeWidth="3.4"
            strokeDasharray={s.dash}
            strokeDashoffset={s.dashoffset}
            strokeLinecap="butt"
          />
        ))}
        <text x="18" y="17.6" textAnchor="middle" className="rotate-90 fill-ink font-mono" style={{transformOrigin: "center", fontSize: 7, fontWeight: 600}}>
          {total}
        </text>
        <text x="18" y="22.2" textAnchor="middle" className="rotate-90 fill-[#5b6b8c]" style={{transformOrigin: "center", fontSize: 2.6, letterSpacing: 0.3}}>
          ASSETS
        </text>
      </svg>
      <div className="flex-1 space-y-2">
        {data.map((d) => (
          <div key={d.type} className="flex items-center gap-2 text-sm">
            <span className="h-2.5 w-2.5 rounded-full" style={{background: d.color}} />
            <span className="flex-1 text-muted">{d.label}</span>
            <span className="font-mono text-ink">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
});

export const SeverityBars = memo(function SeverityBars({bySeverity}: {bySeverity: Record<string, number>}) {
  const order = ["critical", "high", "medium", "low", "info"];
  const max = Math.max(1, ...order.map((s) => bySeverity[s] || 0));
  return (
    <div className="space-y-3">
      {order.map((sev) => {
        const v = bySeverity[sev] || 0;
        const color = SEVERITY_COLOR[sev];
        return (
          <div key={sev} className="flex items-center gap-3">
            <span className="w-16 text-xs capitalize text-muted">{sev}</span>
            <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-white/5">
              <div
                className="h-full rounded-full transition-[width] duration-700"
                style={{width: `${(v / max) * 100}%`, background: color, boxShadow: `0 0 12px ${color}80`}}
              />
            </div>
            <span className="w-8 text-right font-mono text-sm text-ink">{v}</span>
          </div>
        );
      })}
    </div>
  );
});
