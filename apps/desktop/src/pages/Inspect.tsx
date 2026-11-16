import { useCallback, useEffect, useState } from "react";
import type { PageProps } from "../App";
import { call, errorText } from "../api";
import { Badge, Card, Empty, ErrorNotice, PageHead } from "../components";
import type { InspectedRequest, ProxyStatus } from "../types";

/** Plain words for each kind of data, most sensitive first (matches ga-core DataKind). */
const KIND: Record<string, string> = {
  Email: "your email address",
  HashedEmail: "your email address (hashed, still identifies you)",
  HashedPersonalDetail: "personal details (hashed)",
  PersonalDetail: "personal details",
  UserId: "your account ID",
  PersistentId: "a long-lived ID for your device",
  ClickId: "the ad you clicked",
  PageUrl: "what you were looking at",
  PageTitle: "the page title",
  Referrer: "where you came from",
  Event: "what you did",
  Purchase: "purchase details",
  Device: "device details",
  TrackerAccount: "the app's tracker account",
  Other: "other details",
};
const ORDER = Object.keys(KIND);

export default function InspectPage({ overview }: PageProps) {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [events, setEvents] = useState<InspectedRequest[]>([]);
  const [app, setApp] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [ca, setCa] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setStatus(await call<ProxyStatus>("proxy_status"));
      setEvents(await call<InspectedRequest[]>("proxy_events"));
    } catch (e) {
      setError(errorText(e));
    }
  }, []);
  useEffect(() => {
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, [load]);

  const setApps = async (apps: string[]) => {
    try {
      setStatus(await call<ProxyStatus>("proxy_set_apps", { apps }));
    } catch (e) {
      setError(errorText(e));
    }
  };
  const add = () => {
    const exe = app.trim();
    if (!exe || !status) return;
    setApps([...status.inspected_apps, exe.toLowerCase().endsWith(".exe") ? exe : `${exe}.exe`]);
    setApp("");
  };
  const exportCa = async () => {
    try {
      const r = await call<{ path: string }>("proxy_export_ca");
      setCa(r.path);
    } catch (e) {
      setError(errorText(e));
    }
  };

  // Suggest apps the scanner found SDKs in.
  const suggestions = (overview?.apps?.apps ?? [])
    .filter((a) => a.findings.some((f) => f.confidence === "High"))
    .map((a) => a.name);

  const decoded = events.filter((e) => e.payloads.length > 0);

  return (
    <>
      <PageHead
        title="Inspect traffic"
        lead="See exactly what an app sends to trackers. Only apps you choose are decrypted; everything else passes through untouched. Apps that refuse inspection are left alone automatically."
      />
      <ErrorNotice message={error} />

      <Card title="Apps to inspect">
        {status?.error && <div className="notice error">The inspection proxy is not running: {status.error}</div>}
        <div className="row" style={{ flexWrap: "wrap", marginBottom: 12 }}>
          {status?.inspected_apps.length ? (
            status.inspected_apps.map((a) => (
              <span key={a} className="badge accent" style={{ padding: "4px 10px" }}>
                {a}{" "}
                <button className="btn" style={{ padding: "0 6px", marginLeft: 4 }} onClick={() => setApps(status.inspected_apps.filter((x) => x !== a))} aria-label={`Stop inspecting ${a}`}>
                  x
                </button>
              </span>
            ))
          ) : (
            <span className="muted">No apps chosen yet.</span>
          )}
        </div>
        <div className="row">
          <input className="text" placeholder="Program file, e.g. Discord.exe" value={app} onChange={(e) => setApp(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} />
          <button className="btn primary" onClick={add} disabled={!app.trim()}>Inspect</button>
        </div>
        {suggestions.length > 0 && (
          <p className="small muted">Apps with tracking SDKs on this PC: {suggestions.join(", ")}</p>
        )}
        {status?.refused_inspection.length ? (
          <p className="small muted">Refused inspection (left alone): {status.refused_inspection.join(", ")}</p>
        ) : null}
      </Card>

      <Card title="Before it can see anything">
        <ol style={{ margin: 0, paddingLeft: 18 }}>
          <li>
            Trust Guardian Angel's inspection certificate. It is unique to this computer.{" "}
            <button className="btn" onClick={exportCa}>Save certificate</button>
            {ca && <div className="small muted">Saved to <span className="mono">{ca}</span>. Double-click it and choose "Install Certificate" if you want to trust it.</div>}
          </li>
          <li>
            Send the app's traffic through <span className="mono">{status?.listening ?? "127.0.0.1:8899"}</span>: set it as the
            Windows proxy, or start an Electron app with <span className="mono">--proxy-server={status?.listening ?? "127.0.0.1:8899"}</span>.
          </li>
        </ol>
      </Card>

      <Card title={`What apps sent (${decoded.length})`}>
        {decoded.length === 0 ? (
          <Empty>Nothing decoded yet. {events.length > 0 && `${events.length} requests were inspected but none were a known tracker format.`}</Empty>
        ) : (
          decoded.map((ev, i) =>
            ev.payloads.map((p, j) => {
              const kinds = [...new Set(p.fields.map((f) => f.kind))].sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b));
              return (
                <div key={`${i}-${j}`} className="list-item">
                  <div className="row">
                    <b>{ev.app ?? "An app"}</b> <span className="muted">sent to</span> <b>{p.product}</b>
                    <Badge tone="neutral">{p.company}</Badge>
                  </div>
                  <div className="muted">{kinds.map((k) => KIND[k] ?? k).join(", ")}</div>
                  <div className="fields">
                    {p.fields.map((f) => (
                      <div key={f.key} style={{ display: "contents" }}>
                        <div className="k">{f.label}</div>
                        <div className="v mono">{f.value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            }),
          )
        )}
      </Card>
    </>
  );
}
