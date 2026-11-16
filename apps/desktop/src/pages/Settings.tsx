import { useCallback, useEffect, useState } from "react";
import type { PageProps } from "../App";
import { call, errorText } from "../api";
import { Badge, Card, Empty, ErrorNotice, PageHead, Waiting, ago } from "../components";
import type { ChangeRecord, Fix } from "../types";

export default function SettingsPage({ overview, refresh }: PageProps) {
  const [fixes, setFixes] = useState<Fix[] | null>(null);
  const [changes, setChanges] = useState<ChangeRecord[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setFixes(await call<Fix[]>("fixes"));
      setChanges(await call<ChangeRecord[]>("changes"));
    } catch (e) {
      setError(errorText(e));
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const act = async (key: string, method: string, params?: unknown, message?: string) => {
    setBusy(key);
    setError(null);
    setDone(null);
    try {
      await call(method, params);
      setDone(message ?? null);
      await Promise.all([load(), refresh()]);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const protectedSettings = overview?.privacy?.settings.filter((s) => s.exposure === "Protected") ?? [];
  const access = (overview?.privacy?.app_access ?? []).filter((a) => a.in_use_now || a.last_used_start_unix);

  return (
    <>
      <PageHead
        title="Windows settings"
        lead="Settings that send data to Microsoft or advertisers. Every change is recorded first and can be undone at any time."
        actions={
          changes.length > 0 && (
            <button className="btn" disabled={busy !== null} onClick={() => act("all", "undo_all", undefined, "All changes were undone.")}>
              Undo all changes
            </button>
          )
        }
      />
      <ErrorNotice message={error} />
      {done && <div className="notice info">{done}</div>}

      <Card title="Sharing your data">
        {!fixes ? (
          <Waiting what="Checking settings..." />
        ) : fixes.length === 0 ? (
          <Empty>Every setting Guardian Angel checks is already set the private way.</Empty>
        ) : (
          fixes.map((f) => (
            <div key={f.setting_id} className="list-item">
              <div className="row">
                <b>{f.setting}</b>
                <Badge tone="warn">{f.state}</Badge>
                {f.needs_admin && <Badge tone="neutral">Needs administrator</Badge>}
                <span className="spacer" />
                <button
                  className="btn primary"
                  disabled={busy !== null}
                  onClick={() => act(f.setting_id, "apply_fix", { setting_id: f.setting_id }, `${f.fix}: done.${f.needs_restart ? " It takes effect after you sign out." : ""}`)}
                >
                  {busy === f.setting_id ? <span className="spinner" /> : f.fix}
                </button>
              </div>
              <div className="muted">{f.explanation}</div>
              <details>
                <summary>What will change</summary>
                {f.writes.map((w) => (
                  <div key={w.location} className="mono muted">
                    {w.location}: {w.current ?? "not set"} &rarr; {w.new}
                  </div>
                ))}
              </details>
            </div>
          ))
        )}
      </Card>

      {changes.length > 0 && (
        <Card title="Changes you made with Guardian Angel">
          {changes.map((c) => (
            <div key={c.id} className="list-item row">
              <div>
                <b>{c.title}</b>
                <div className="muted small">{ago(c.applied_unix)}</div>
              </div>
              <span className="spacer" />
              <button className="btn" disabled={busy !== null} onClick={() => act(c.id, "undo", { id: c.id }, `Undid: ${c.title}.`)}>
                Undo
              </button>
            </div>
          ))}
        </Card>
      )}

      {protectedSettings.length > 0 && (
        <Card title="Already private">
          {protectedSettings.map((s) => (
            <div key={s.id} className="list-item row">
              <span>{s.title}</span>
              <span className="spacer" />
              <Badge tone="good">{s.state}</Badge>
            </div>
          ))}
        </Card>
      )}

      <Card title="Camera, microphone and location use">
        {access.length === 0 ? (
          <Empty>No app has used them.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>App</th>
                <th>Used</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {access.slice(0, 30).map((a) => (
                <tr key={`${a.capability}-${a.identifier}`}>
                  <td>{a.app}</td>
                  <td>{a.capability}</td>
                  <td>{a.in_use_now ? <Badge tone="bad">In use now</Badge> : <span className="muted">{ago(a.last_used_start_unix)}</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
