import { useCallback, useEffect, useState } from "react";
import type { PageProps } from "../App";
import { call, errorText, isDesktopApp, native } from "../api";
import { Badge, Card, Empty, ErrorNotice, PageHead, Tip } from "../components";
import type { InspectedRequest, ProxyStatus, RunningApp } from "../types";

/** Plain words for each kind of data, most sensitive first (matches ga-core DataKind). */
const KIND: Record<string, string> = {
  Email: "your email address",
  HashedEmail: "your email address (scrambled, but still identifies you)",
  HashedPersonalDetail: "personal details (scrambled)",
  PersonalDetail: "personal details",
  UserId: "your account ID",
  PersistentId: "an ID that recognises your device every time",
  ClickId: "which ad you clicked",
  PageUrl: "what you were looking at",
  PageTitle: "the page title",
  Referrer: "where you came from",
  Event: "what you did",
  Purchase: "what you bought",
  Device: "details about your device",
  TrackerAccount: "the app's tracker account",
  Other: "other details",
};
const ORDER = Object.keys(KIND);

export default function InspectPage() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [events, setEvents] = useState<InspectedRequest[]>([]);
  const [running, setRunning] = useState<RunningApp[]>([]);
  const [picked, setPicked] = useState("");
  const [typed, setTyped] = useState("");
  const [trusted, setTrusted] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setStatus(await call<ProxyStatus>("proxy_status"));
      setEvents(await call<InspectedRequest[]>("proxy_events"));
    } catch (e) {
      setError(errorText(e));
    }
  }, []);
  const [windowed, setWindowed] = useState<Set<number> | null>(null);
  const loadRunning = useCallback(async () => {
    try {
      setRunning(await call<RunningApp[]>("running_apps"));
      // Which apps have a window open; only the desktop app can tell.
      if (isDesktopApp) setWindowed(new Set(await native<number[]>("windowed_pids")));
    } catch (e) {
      setError(errorText(e));
    }
  }, []);
  const checkTrust = useCallback(async () => {
    if (isDesktopApp) setTrusted(await native<boolean>("certificate_trusted").catch(() => false));
  }, []);

  useEffect(() => {
    load();
    loadRunning();
    checkTrust();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, [load, loadRunning, checkTrust]);

  const run = async (action: () => Promise<unknown>, success?: string) => {
    setError(null);
    setNote(null);
    try {
      await action();
      if (success) setNote(success);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const chosen = status?.inspected_apps ?? [];
  const setApps = (apps: string[]) => run(async () => setStatus(await call<ProxyStatus>("proxy_set_apps", { apps })));
  const add = (exe: string) => {
    const name = exe.trim();
    if (!name) return;
    const withExe = name.toLowerCase().endsWith(".exe") ? name : `${name}.exe`;
    if (!chosen.includes(withExe.toLowerCase())) setApps([...chosen, withExe]);
    setPicked("");
    setTyped("");
  };

  const trust = () =>
    run(async () => {
      const { path } = await call<{ path: string }>("proxy_export_ca");
      await native("trust_certificate", { path });
      await checkTrust();
    }, "Certificate trusted. Guardian Angel can now read the traffic of the apps you chose.");
  const untrust = () =>
    run(async () => {
      await native("remove_certificate");
      await checkTrust();
    }, "Certificate removed. Guardian Angel can no longer read any app's encrypted traffic.");

  const proxy = status?.listening ?? "127.0.0.1:8899";
  const chosenApps = chosen.map((exe) => ({ exe, app: running.find((r) => r.exe.toLowerCase() === exe) }));
  const relaunch = (app: RunningApp) =>
    run(
      () => native("launch_with_proxy", { path: app.path, proxy }),
      `Started ${app.name} with inspection. If it was already open, close every ${app.name} window first and try again.`,
    );

  const decoded = events.filter((e) => e.payloads.length > 0);
  const notYetChosen = running.filter((r) => !chosen.includes(r.exe.toLowerCase()));
  const hasWindow = (r: RunningApp) => windowed === null || r.pids.some((p) => windowed.has(p));
  const openApps = notYetChosen.filter(hasWindow);
  const background = notYetChosen.filter((r) => !hasWindow(r));

  return (
    <>
      <PageHead
        title="Inspect traffic"
        lead="See exactly what an app sends to tracking companies. Only the apps you pick are read; everything else passes through untouched."
      />
      <ErrorNotice message={error} />
      {note && <div className="notice info">{note}</div>}
      {status?.error && <div className="notice error">Inspection is not available: {status.error}</div>}

      <Card>
        <div className="steps">
          <div className={`step ${chosen.length ? "done" : ""}`}>
            <div>
              <h3>
                Pick the apps to inspect
                <Tip text="Guardian Angel only reads traffic from the apps listed here. Your browser, banking apps and everything else keep their privacy." />
              </h3>
              <div className="chips">
                {chosen.length === 0 && <span className="muted">No apps picked yet.</span>}
                {chosen.map((exe) => (
                  <span key={exe} className="chip">
                    {exe}
                    <button aria-label={`Stop inspecting ${exe}`} title="Stop inspecting" onClick={() => setApps(chosen.filter((x) => x !== exe))}>
                      &times;
                    </button>
                  </span>
                ))}
              </div>
              <div className="row" style={{ flexWrap: "wrap" }}>
                <select className="text" value={picked} onChange={(e) => setPicked(e.target.value)} aria-label="Running apps">
                  <option value="">Choose a running app...</option>
                  <optgroup label={windowed ? "Open apps" : "Running programs"}>
                    {openApps.map((r) => (
                      <option key={r.exe} value={r.exe}>
                        {r.name}
                      </option>
                    ))}
                  </optgroup>
                  {background.length > 0 && (
                    <optgroup label="Running in the background">
                      {background.map((r) => (
                        <option key={r.exe} value={r.exe}>
                          {r.name}
                        </option>
                      ))}
                    </optgroup>
                  )}
                </select>
                <button className="btn primary" disabled={!picked} onClick={() => add(picked)}>Add</button>
                <button className="btn" onClick={loadRunning} title="Refresh the list of running apps">Refresh</button>
              </div>
              <div className="row" style={{ marginTop: 8, flexWrap: "wrap" }}>
                <input
                  className="text"
                  placeholder="Or type a program name, e.g. Discord"
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && add(typed)}
                />
                <button className="btn" disabled={!typed.trim()} onClick={() => add(typed)}>Add</button>
              </div>
            </div>
          </div>

          <div className={`step ${trusted ? "done" : ""}`}>
            <div>
              <h3>
                Allow Guardian Angel to read their encrypted traffic
                <Tip text="Apps encrypt what they send. To read it, Windows needs to trust Guardian Angel's certificate. It was made on this computer, exists nowhere else, and is only used for the apps you picked. You can remove it any time." />
              </h3>
              {!isDesktopApp ? (
                <span className="muted">Available in the Guardian Angel desktop app.</span>
              ) : trusted ? (
                <div className="row">
                  <Badge tone="good">Allowed</Badge>
                  <button className="btn" onClick={untrust}>Remove permission</button>
                </div>
              ) : (
                <div className="row">
                  <button className="btn primary" onClick={trust}>Allow</button>
                  <span className="muted small">Windows will ask you to confirm.</span>
                </div>
              )}
            </div>
          </div>

          <div className="step">
            <div>
              <h3>
                Restart the app through Guardian Angel
                <Tip text="Apps only send their traffic through Guardian Angel when started this way. Close the app completely first; it then opens again with inspection on. Restarting it normally turns inspection off." />
              </h3>
              {chosenApps.length === 0 ? (
                <span className="muted">Pick an app first.</span>
              ) : (
                chosenApps.map(({ exe, app }) => (
                  <div key={exe} className="row" style={{ marginBottom: 6 }}>
                    <b style={{ minWidth: 160 }}>{app?.name ?? exe}</b>
                    {!app ? (
                      <span className="muted small">Not running right now. Open it, then press Refresh above.</span>
                    ) : app.electron ? (
                      <button className="btn" disabled={!isDesktopApp || !trusted} onClick={() => relaunch(app)}>
                        Restart with inspection
                      </button>
                    ) : (
                      <span className="muted small">
                        This app does not support one-click inspection yet; it will work once Guardian Angel can use the Windows proxy setting.
                      </span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </Card>

      <Card title={`What apps sent (${decoded.length})`}>
        {decoded.length === 0 ? (
          <Empty>
            Nothing yet. Use the app for a minute after restarting it.
            {events.length > 0 && ` ${events.length} requests were read, but none went to a tracker Guardian Angel can decode yet.`}
          </Empty>
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
                  <div>{kinds.map((k) => KIND[k] ?? k).join(", ")}</div>
                  <details>
                    <summary>Show exactly what was sent</summary>
                    <div className="fields">
                      {p.fields.map((f) => (
                        <div key={f.key} style={{ display: "contents" }}>
                          <div className="k">{f.label}</div>
                          <div className="v mono">{f.value}</div>
                        </div>
                      ))}
                    </div>
                  </details>
                </div>
              );
            }),
          )
        )}
      </Card>
    </>
  );
}
