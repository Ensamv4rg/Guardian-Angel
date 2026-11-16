import { useState } from "react";
import type { PageProps } from "../App";
import { Badge, Card, Empty, PageHead, Waiting, categoryLabel } from "../components";

export default function AppsPage({ overview, go }: PageProps) {
  const [showMentions, setShowMentions] = useState(false);
  const scan = overview?.apps;
  if (!scan) return <Waiting what="Looking inside installed apps (this takes a minute or two)..." />;

  const apps = scan.apps
    .map((a) => ({ ...a, shown: a.findings.filter((f) => showMentions || f.confidence === "High") }))
    .filter((a) => a.shown.length > 0);

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
            {a.truncated && <div className="muted small" style={{ marginTop: 8 }}>Large app: only part of its code was searched.</div>}
          </Card>
        ))
      )}
    </>
  );
}
