import { type ReactElement, useCallback, useEffect, useState } from "react";
import { call, errorText } from "./api";
import { ScanProgressBar } from "./components";
import type { Overview } from "./types";
import { UpdateBanner, UpdateFooter, useUpdates } from "./updates";
import logo from "../src-tauri/icons/128x128.png";
import OverviewPage from "./pages/Overview";
import TrackersPage from "./pages/Trackers";
import AppsPage from "./pages/Apps";
import NetworkPage from "./pages/Network";
import InspectPage from "./pages/Inspect";
import BlockingPage from "./pages/Blocking";
import ReceivedPage from "./pages/Received";
import ExtensionsPage from "./pages/Extensions";
import SettingsPage from "./pages/Settings";
import AlertsPage from "./pages/Alerts";

export type Page = "overview" | "trackers" | "apps" | "network" | "inspect" | "received" | "blocking" | "extensions" | "settings" | "alerts";

export interface PageProps {
  overview: Overview | null;
  refresh: () => Promise<void>;
  go: (p: Page) => void;
}

const SECTIONS: { title: string; pages: [Page, string][] }[] = [
  { title: "", pages: [["overview", "Overview"]] },
  { title: "Who collects data", pages: [["trackers", "Trackers"], ["apps", "Apps"], ["network", "Network"], ["received", "What trackers got"], ["inspect", "Inspect traffic"]] },
  { title: "Protect", pages: [["blocking", "Blocking"]] },
  { title: "Your setup", pages: [["extensions", "Extensions"], ["settings", "Windows settings"], ["alerts", "Alerts"]] },
];

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const updates = useUpdates();

  const refresh = useCallback(async () => {
    try {
      setOverview(await call<Overview>("overview"));
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  // Poll quickly while a scan runs, slowly otherwise.
  useEffect(() => {
    refresh();
    const scanning = overview?.scanning ?? true;
    const id = setInterval(refresh, scanning ? 1500 : 30000);
    return () => clearInterval(id);
  }, [refresh, overview?.scanning]);

  const props: PageProps = { overview, refresh, go: setPage };
  const pages: Record<Page, ReactElement> = {
    overview: <OverviewPage {...props} />,
    trackers: <TrackersPage {...props} />,
    apps: <AppsPage {...props} />,
    network: <NetworkPage {...props} />,
    inspect: <InspectPage />,
    received: <ReceivedPage {...props} />,
    blocking: <BlockingPage />,
    extensions: <ExtensionsPage {...props} />,
    settings: <SettingsPage {...props} />,
    alerts: <AlertsPage {...props} />,
  };

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Sections">
        <div className="brand">
          <img src={logo} alt="" />
          Guardian Angel
        </div>
        {SECTIONS.map((s) => (
          <div key={s.title}>
            {s.title && <div className="nav-section">{s.title}</div>}
            {s.pages.map(([id, label]) => (
              <button key={id} className={`nav ${page === id ? "active" : ""}`} onClick={() => setPage(id)}>
                {label}
                {id === "alerts" && (overview?.unread_alerts ?? 0) > 0 && <span className="count">{overview?.unread_alerts}</span>}
              </button>
            ))}
          </div>
        ))}
        <div className="foot">
          Your data is analysed on this computer and never leaves it.
          <UpdateFooter updates={updates} />
        </div>
      </nav>
      <main>
        {error && (
          <div className="notice error">
            {error} Start it with <span className="mono">guardian-service console</span> (development) or install the service.
          </div>
        )}
        <UpdateBanner updates={updates} />
        {overview?.progress && <ScanProgressBar progress={overview.progress} />}
        {pages[page]}
      </main>
    </div>
  );
}
