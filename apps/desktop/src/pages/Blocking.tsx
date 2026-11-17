import { useCallback, useEffect, useState } from "react";
import { call, errorText } from "../api";
import { Badge, Card, Empty, ErrorNotice, PageHead, Stat, Tip, fmt } from "../components";
import type { BlockingPreview, BlockingProfile, BlockingStatus } from "../types";

const LEVELS: { id: BlockingProfile; name: string; what: string }[] = [
  { id: "relaxed", name: "Relaxed", what: "Advertising and data brokers. Rarely breaks anything." },
  { id: "balanced", name: "Balanced", what: "Also analytics and session recording. Recommended." },
  {
    id: "strict",
    name: "Strict",
    what: "Also social media widgets, tag managers and error reporting. May break embedded posts, chat widgets and some sign-up forms.",
  },
];

function minutesLeft(unix: number): number {
  return Math.max(1, Math.round((unix * 1000 - Date.now()) / 60000));
}

export default function BlockingPage() {
  const [status, setStatus] = useState<BlockingStatus | null>(null);
  const [preview, setPreview] = useState<BlockingPreview | null>(null);
  const [level, setLevel] = useState<BlockingProfile>("balanced");
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await call<BlockingStatus>("blocking_status");
      setStatus(s);
      if (!s.enabled) setLevel(s.profile);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const run = async (method: string, params?: unknown) => {
    setBusy(true);
    setError(null);
    try {
      setStatus(await call<BlockingStatus>(method, params));
      setPreview(null);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const askConsent = async () => {
    setError(null);
    try {
      setPreview(await call<BlockingPreview>("blocking_preview"));
    } catch (e) {
      setError(errorText(e));
    }
  };

  if (!status) return <PageHead title="Blocking" lead="Loading..." />;
  const paused = status.paused_until !== null;

  return (
    <>
      <PageHead
        title="Blocking"
        lead="Stops apps and websites on this PC from reaching tracking companies, by refusing to look up their addresses."
      />
      <ErrorNotice message={error ?? status.error} />
      {status.notice && <div className="notice error">{status.notice}</div>}

      {!status.enabled ? (
        <Card title="Turn on blocking">
          <p style={{ marginTop: 0 }}>
            Every program finds a server by looking up its name first. Guardian Angel answers those lookups and refuses the ones
            for tracking companies, so the tracker is never contacted. Everything else is looked up as before.
            <Tip text="This covers every app and browser on the PC, for every user. Browsers with 'Secure DNS' turned on skip it for websites; Guardian Angel still sees and blocks other apps." />
          </p>
          <div className="choices">
            {LEVELS.map((l) => (
              <label key={l.id} className={`choice ${level === l.id ? "selected" : ""}`}>
                <input type="radio" name="level" checked={level === l.id} onChange={() => setLevel(l.id)} />
                <div>
                  <b>{l.name}</b>
                  <div className="muted small">{l.what}</div>
                </div>
              </label>
            ))}
          </div>

          {!preview ? (
            <button className="btn primary" onClick={askConsent}>Turn on blocking...</button>
          ) : (
            <div className="consent">
              <h3 style={{ marginTop: 0 }}>Before you turn it on</h3>
              <p>Guardian Angel will change the DNS setting of these network connections:</p>
              {preview.adapters.length === 0 ? (
                <Empty>No connected network was found. Connect to a network first.</Empty>
              ) : (
                <ul>
                  {preview.adapters.map((a) => (
                    <li key={a.name}>
                      <b>{a.name}</b> <span className="muted">now: {a.current}</span>
                    </li>
                  ))}
                </ul>
              )}
              <ul className="small">
                <li>Your current DNS server stays as a backup, so the internet keeps working if Guardian Angel stops.</li>
                <li>If lookups stop working, blocking turns itself off and puts these settings back.</li>
                <li>Turning blocking off, or uninstalling Guardian Angel, puts every setting back exactly as it is now.</li>
              </ul>
              <div className="row">
                <button className="btn primary" disabled={busy || preview.adapters.length === 0} onClick={() => run("blocking_enable", { profile: level })}>
                  {busy ? "Turning on..." : "Turn on"}
                </button>
                <button className="btn" disabled={busy} onClick={() => setPreview(null)}>Cancel</button>
              </div>
            </div>
          )}
        </Card>
      ) : (
        <>
          <div className="grid cols-4" style={{ margin: "16px 0" }}>
            <Stat value={fmt(status.blocked)} label="tracker lookups blocked" />
            <Stat value={fmt(status.queries)} label="lookups in total" />
            <Stat value={status.queries ? `${Math.round((status.blocked / status.queries) * 100)}%` : "0%"} label="of lookups were trackers" />
          </div>
          <Card
            title="Blocking is on"
            actions={
              <>
                {paused ? <Badge tone="warn">Paused, {minutesLeft(status.paused_until!)} min left</Badge> : <Badge tone="good">Active</Badge>}
                <button className="btn" disabled={busy} onClick={() => run("blocking_disable")}>Turn off</button>
              </>
            }
          >
            <div className="muted small">Network connections: {status.adapters.join(", ") || "none"}</div>
            <div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
              <span>Level:</span>
              <select className="text" value={status.profile} disabled={busy} onChange={(e) => run("blocking_set_profile", { profile: e.target.value })}>
                {LEVELS.map((l) => (
                  <option key={l.id} value={l.id}>{l.name}</option>
                ))}
              </select>
              <Tip text={LEVELS.map((l) => `${l.name}: ${l.what}`).join(" ")} />
              {paused ? (
                <button className="btn" disabled={busy} onClick={() => run("blocking_resume")}>Resume now</button>
              ) : (
                <>
                  <button className="btn" disabled={busy} onClick={() => run("blocking_pause", { minutes: 10 })} title="Something broke? Pause and try again.">
                    Pause 10 minutes
                  </button>
                  <button className="btn" disabled={busy} onClick={() => run("blocking_pause", { minutes: 60 })}>Pause 1 hour</button>
                </>
              )}
            </div>
          </Card>

          <Card title="Most blocked since the service started">
            {status.top_companies.length === 0 ? (
              <Empty>Nothing blocked yet. Use your PC as normal and check back.</Empty>
            ) : (
              <table>
                <tbody>
                  {status.top_companies.map((c) => (
                    <tr key={c.company}>
                      <td>{c.company}</td>
                      <td style={{ textAlign: "right" }}>{fmt(c.blocked)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}

      <Card title="Never block">
        <p className="small muted" style={{ marginTop: 0 }}>
          If a site or app stops working, add its domain here (for example <span className="mono">example.com</span>). Windows Update,
          antivirus and certificate checks are never blocked.
        </p>
        <div className="chips">
          {status.allowed.length === 0 && <span className="muted">Nothing added.</span>}
          {status.allowed.map((d) => (
            <span key={d} className="chip">
              {d}
              <button aria-label={`Block ${d} again`} title="Remove" onClick={() => run("blocking_allow", { domain: d, allow: false })}>&times;</button>
            </span>
          ))}
        </div>
        <div className="row">
          <input className="text" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <button
            className="btn"
            disabled={!domain.trim() || busy}
            onClick={async () => {
              await run("blocking_allow", { domain: domain.trim(), allow: true });
              setDomain("");
            }}
          >
            Add
          </button>
        </div>
      </Card>
    </>
  );
}
