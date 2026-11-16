import type { PageProps } from "../App";
import { Badge, Card, Empty, PageHead, Waiting, riskTone } from "../components";

export default function ExtensionsPage({ overview }: PageProps) {
  const scan = overview?.extensions;
  if (!scan) return <Waiting what="Reading browser extensions..." />;
  const high = scan.extensions.filter((e) => e.risk === "High").length;

  return (
    <>
      <PageHead
        title="Extensions"
        lead={`${scan.extensions.length} browser extensions across ${scan.profiles_scanned} profiles; ${high} can read and change everything on every website you visit. Remove the ones you do not use from the browser's extensions page.`}
      />
      <Card>
        {scan.extensions.length === 0 ? (
          <Empty>No browser extensions installed.</Empty>
        ) : (
          scan.extensions.map((e) => (
            <div key={`${e.browser}-${e.profile}-${e.id}`} className="list-item">
              <div className="row">
                <b>{e.name}</b>
                <span className="muted small">{e.version}</span>
                <Badge tone={riskTone(e.risk)}>{e.risk} risk</Badge>
                {!e.enabled && <Badge tone="neutral">Disabled</Badge>}
                {e.source !== "Store" && <Badge tone="warn">{e.source === "Sideloaded" ? "Installed by another program" : e.source}</Badge>}
                <span className="spacer" />
                <span className="muted small">{e.browser} - {e.profile}</span>
              </div>
              {e.risk_reasons.length > 0 && (
                <ul className="reasons">
                  {e.risk_reasons.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              )}
            </div>
          ))
        )}
      </Card>
    </>
  );
}
