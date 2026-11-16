import { useState } from "react";
import type { PageProps } from "../App";
import { call, errorText } from "../api";
import { Card, ErrorNotice, PageHead, ScoreRing, Waiting, ago, fmt } from "../components";

export default function OverviewPage({ overview: o, refresh, go }: PageProps) {
  const [error, setError] = useState<string | null>(null);
  if (!o) return <Waiting what="Connecting to the Guardian Angel service..." />;

  const scanNow = async () => {
    try {
      await call("scan_now");
      await refresh();
    } catch (e) {
      setError(errorText(e));
    }
  };

  const exposed = o.privacy?.settings.filter((s) => s.exposure === "Exposed").length;
  const riskyExtensions = o.extensions?.extensions.filter((e) => e.enabled && e.risk === "High").length;
  const appsWithSdks = o.apps?.apps.filter((a) => a.findings.some((f) => f.confidence === "High")).length;

  return (
    <>
      <PageHead
        title="Overview"
        lead="Who can see what on this computer, and what you can do about it."
        actions={
          <>
            <span className="muted small">
              {o.scanning ? (
                <>
                  <span className="spinner" /> Scanning...
                </>
              ) : (
                `Last scan ${ago(o.generated_unix)}`
              )}
            </span>
            <button className="btn primary" onClick={scanNow} disabled={o.scanning}>
              Scan now
            </button>
          </>
        }
      />
      <ErrorNotice message={error} />

      <Card>
        <div className="score">
          <ScoreRing value={o.score.value} />
          <div>
            <div className="muted small">Privacy score (100 is best)</div>
            {o.score.penalties.length === 0 ? (
              <p>Nothing found that lowers your score.</p>
            ) : (
              <ul className="reasons">
                {o.score.penalties.map((p) => (
                  <li key={p.reason}>
                    {p.reason} <span className="muted">(-{p.points})</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </Card>

      <div className="grid cols-4" style={{ margin: "16px 0" }}>
        <button className="card stat tile" onClick={() => go("trackers")}>
          <div className="value">{o.cookies ? fmt(o.cookies.companies.length) : "..."}</div>
          <div className="label">tracking companies in your browsers</div>
        </button>
        <button className="card stat tile" onClick={() => go("apps")}>
          <div className="value">{appsWithSdks ?? "..."}</div>
          <div className="label">apps with tracking or telemetry SDKs</div>
        </button>
        <button className="card stat tile" onClick={() => go("extensions")}>
          <div className="value">{riskyExtensions ?? "..."}</div>
          <div className="label">extensions that can read every website</div>
        </button>
        <button className="card stat tile" onClick={() => go("settings")}>
          <div className="value">{exposed ?? "..."}</div>
          <div className="label">Windows settings sharing your data</div>
        </button>
      </div>

      {o.network && (
        <Card title="Right now" actions={<button className="btn" onClick={() => go("network")}>See network</button>}>
          <p style={{ margin: 0 }}>
            Since the service started, programs looked up <b>{fmt(o.network.total_lookups)}</b> addresses;{" "}
            <b>{fmt(o.network.tracker_lookups)}</b> belonged to <b>{o.network.companies.length}</b> tracking companies.
          </p>
        </Card>
      )}

      {o.unread_alerts > 0 && (
        <Card title="Alerts" actions={<button className="btn" onClick={() => go("alerts")}>Review</button>}>
          <p style={{ margin: 0 }}>
            {o.unread_alerts} new {o.unread_alerts === 1 ? "change" : "changes"} since your last look.
          </p>
        </Card>
      )}
    </>
  );
}
