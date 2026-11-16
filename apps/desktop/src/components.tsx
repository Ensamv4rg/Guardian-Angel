import type { ReactNode } from "react";

export function PageHead({ title, lead, actions }: { title: string; lead: string; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        <p className="lead">{lead}</p>
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function Card({ title, children, actions }: { title?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <div className="row" style={{ marginBottom: 12 }}>
          {title && <h2 style={{ margin: 0 }}>{title}</h2>}
          <span className="spacer" />
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({ value, label }: { value: ReactNode; label: string }) {
  return (
    <div className="card stat">
      <div className="value">{value}</div>
      <div className="label">{label}</div>
    </div>
  );
}

export function Badge({ tone, children }: { tone: "bad" | "warn" | "good" | "neutral" | "accent"; children: ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function riskTone(risk: string): "bad" | "warn" | "good" {
  return risk === "High" ? "bad" : risk === "Medium" ? "warn" : "good";
}

export function Bar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <div className="bar" aria-hidden>
      <span style={{ width: `${pct}%` }} />
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Waiting({ what }: { what: string }) {
  return (
    <Empty>
      <span className="spinner" /> {what}
    </Empty>
  );
}

export function ErrorNotice({ message }: { message: string | null }) {
  return message ? <div className="notice error">{message}</div> : null;
}

/** A ring that fills with the score; colour follows the value. */
export function ScoreRing({ value }: { value: number }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const color = value >= 75 ? "var(--good)" : value >= 50 ? "var(--warn)" : "var(--bad)";
  return (
    <svg width="132" height="132" viewBox="0 0 132 132" role="img" aria-label={`Privacy score ${value} out of 100`}>
      <circle cx="66" cy="66" r={r} fill="none" stroke="var(--panel-2)" strokeWidth="12" />
      <circle
        cx="66" cy="66" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
        strokeDasharray={`${(c * value) / 100} ${c}`} transform="rotate(-90 66 66)"
      />
      <text x="66" y="74" textAnchor="middle" fontSize="30" fontWeight="700" fill="var(--text)">{value}</text>
    </svg>
  );
}

export function ago(unix: number | null | undefined): string {
  if (!unix) return "never";
  const s = Math.max(0, Date.now() / 1000 - unix);
  if (s < 60) return "just now";
  const units: [number, string][] = [[31536000, "year"], [2592000, "month"], [86400, "day"], [3600, "hour"], [60, "minute"]];
  for (const [secs, name] of units) {
    if (s >= secs) {
      const n = Math.floor(s / secs);
      return `${n} ${name}${n === 1 ? "" : "s"} ago`;
    }
  }
  return "just now";
}

export const fmt = (n: number) => n.toLocaleString();

/** `session_recording` -> "Session recording". */
export function categoryLabel(cat: string): string {
  const words = cat.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}
