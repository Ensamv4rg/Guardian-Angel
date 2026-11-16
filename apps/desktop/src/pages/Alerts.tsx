import { useCallback, useEffect, useState } from "react";
import type { PageProps } from "../App";
import { call, errorText } from "../api";
import { Badge, Card, Empty, ErrorNotice, PageHead, ago } from "../components";
import type { Alert } from "../types";

export default function AlertsPage({ refresh }: PageProps) {
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setAlerts(await call<Alert[]>("alerts"));
    } catch (e) {
      setError(errorText(e));
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const markRead = async () => {
    try {
      await call("mark_alerts_read");
      await Promise.all([load(), refresh()]);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const unread = alerts?.filter((a) => !a.read).length ?? 0;

  return (
    <>
      <PageHead
        title="Alerts"
        lead="Changes found since earlier scans: new extensions with broad access, privacy settings switched back on (updates sometimes do this), and new tracking SDKs in apps."
        actions={unread > 0 && <button className="btn" onClick={markRead}>Mark all as read</button>}
      />
      <ErrorNotice message={error} />
      <Card>
        {!alerts || alerts.length === 0 ? (
          <Empty>No changes yet. Guardian Angel compares each scan with the one before.</Empty>
        ) : (
          alerts.map((a) => (
            <div key={a.id} className="list-item" style={{ opacity: a.read ? 0.65 : 1 }}>
              <div className="row">
                <Badge tone={a.severity === "High" ? "bad" : a.severity === "Medium" ? "warn" : "accent"}>{a.severity}</Badge>
                <b>{a.title}</b>
                <span className="spacer" />
                <span className="muted small">{ago(a.unix)}</span>
              </div>
              {a.detail && <div className="muted">{a.detail}</div>}
            </div>
          ))
        )}
      </Card>
    </>
  );
}
