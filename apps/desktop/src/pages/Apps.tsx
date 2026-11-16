import { useState } from "react";
import type { PageProps } from "../App";
import { call, errorText } from "../api";
import { Badge, Card, Empty, ErrorNotice, PageHead, Tip, Waiting, categoryLabel, fmt } from "../components";
import type { InstalledApp, SkippedFile } from "../types";

const REASON: Record<SkippedFile["reason"], string> = {
  too_large: "too large",
  app_limit: "app limit reached",
  partly_read: "partly read",
};

function size(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${Math.round(bytes / 1024 ** 2)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export default function AppsPage({ overview, refresh, go }: PageProps) {
  const [showMentions, setShowMentions] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scan = overview?.apps;
  if (!scan) return <Waiting what="Looking inside installed apps (this takes a minute or two)..." />;

  const apps = scan.apps
    .map((a) => ({ ...a, shown: a.findings.filter((f) => showMentions || f.confidence === "High") }))
    .filter((a) => a.shown.length > 0);
  const skimmed = scan.apps.filter((a) => a.truncated).sort((a, b) => b.skipped_bytes - a.skipped_bytes);
  const busy = overview?.scanning ?? false;

  const scanFully = async (app: InstalledApp) => {
    setError(null);
    try {
      const { started } = await call<{ started: boolean }>("scan_app_fully", { name: app.name });
      if (!started) setError("Another scan is running. Try again when it has finished.");
      await refresh();
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <>
      <PageHead
        title="Apps"
        lead="Tracking and telemetry code built into your desktop apps. To see what an app actually sends, inspect its traffic."
        actions={
          <label className="row small">
            <input type="checkbox" checked={showMentions} onChange={(e) => setShowMentions(e.target.checked)} />
            Also show apps that only mention a tracker
          </label>
        }
      />
      <ErrorNotice message={error} />
      <p className="small muted">
        <Badge tone="bad">Bundled</Badge> the SDK itself ships with the app. <Badge tone="neutral">Mentions</Badge> the app's
        code contains a tracker's address; it may or may not send data there.
      </p>
      {apps.length === 0 ? (
        <Card>
          <Empty>No tracking SDKs found{showMentions ? "" : " bundled in your apps"}.</Empty>
        </Card>
      ) : (
        apps.map((a) => (
          <Card
            key={a.install_dir}
            title={a.name}
            actions={
              <>
                {a.full_scan && <Badge tone="good">Fully scanned</Badge>}
                {a.electron && <Badge tone="neutral">Electron</Badge>}
                <button className="btn" onClick={() => go("inspect")}>Inspect traffic</button>
              </>
            }
          >
            {a.publisher && <div className="muted small" style={{ marginTop: -8, marginBottom: 8 }}>{a.publisher}</div>}
            {a.shown.map((f) => (
              <div key={f.sdk} className="list-item">
                <div className="row">
                  <b>{f.sdk}</b>
                  <Badge tone={f.confidence === "High" ? "bad" : "neutral"}>{f.confidence === "High" ? "Bundled" : "Mentions"}</Badge>
                  <Badge tone="accent">{categoryLabel(f.category)}</Badge>
                </div>
                <div className="muted">{f.purpose}</div>
                <details>
                  <summary>Why we think so</summary>
                  {f.evidence.map((e) => (
                    <div key={e} className="mono muted">{e}</div>
                  ))}
                </details>
              </div>
            ))}
            {a.truncated && <div className="muted small" style={{ marginTop: 8 }}>Large app: only part of its code was searched. See "Partly scanned apps" below.</div>}
          </Card>
        ))
      )}

      <Card title={`Partly scanned apps (${skimmed.length})`}>
        <p className="small muted" style={{ marginTop: 0 }}>
          To keep scans quick, Guardian Angel reads at most 64 MB of each app and skips single files over 32 MB. These apps
          had more than that, so trackers in the unread files would be missed.
          <Tip text="Scanning everything reads every file of the app. For big apps this can take several minutes, and your antivirus may slow it down further. The result is kept until the app is updated." />
        </p>
        {skimmed.length === 0 ? (
          <Empty>Every app was read completely.</Empty>
        ) : (
          skimmed.map((a) => (
            <div key={a.install_dir} className="list-item">
              <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
                <div>
                  <b>{a.name}</b>{" "}
                  <span className="muted small">
                    {a.skipped_count > 0 && `${fmt(a.skipped_count)} file${a.skipped_count === 1 ? "" : "s"} not fully read (${size(a.skipped_bytes)})`}
                    {a.skipped_count > 0 && a.too_many_files && ", "}
                    {a.too_many_files && "too many files to list them all"}
                  </span>
                </div>
                <button className="btn" disabled={busy} onClick={() => scanFully(a)} title={busy ? "Wait for the current scan to finish" : undefined}>
                  Scan everything
                </button>
              </div>
              {a.skipped.length > 0 && (
                <details>
                  <summary>Show the skipped files</summary>
                  <div className="fields">
                    {a.skipped.map((f) => (
                      <div key={f.path} style={{ display: "contents" }}>
                        <div className="v mono">{f.path}</div>
                        <div className="k">
                          {size(f.size)}, {REASON[f.reason]}
                        </div>
                      </div>
                    ))}
                  </div>
                  {a.skipped_count > a.skipped.length && (
                    <div className="muted small">and {fmt(a.skipped_count - a.skipped.length)} smaller files</div>
                  )}
                </details>
              )}
            </div>
          ))
        )}
      </Card>
    </>
  );
}
