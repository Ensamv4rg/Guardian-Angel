import type { PageProps } from "../App";
import { Bar, Card, Empty, PageHead, categoryLabel, fmt } from "../components";

export default function NetworkPage({ overview }: PageProps) {
  const n = overview?.network;
  if (!n) {
    return (
      <>
        <PageHead title="Network" lead="Which programs contact tracking companies." />
        <Card>
          <Empty>The network monitor is not running. The service needs administrator rights or the Performance Log Users group.</Empty>
        </Card>
      </>
    );
  }
  const maxCompany = n.companies[0]?.lookups ?? 0;
  const programs = n.processes.filter((p) => p.tracker_lookups > 0);
  const mins = Math.max(1, Math.round(n.duration_secs / 60));

  return (
    <>
      <PageHead
        title="Network"
        lead={`Live, from Windows' own DNS records over the last ${mins} minute${mins === 1 ? "" : "s"}: ${fmt(n.tracker_lookups)} of ${fmt(n.total_lookups)} lookups went to tracking companies. This shows who is contacted, not what is sent; use Inspect traffic for that.`}
      />
      <div className="grid cols-2">
        <Card title="Companies contacted">
          {n.companies.length === 0 ? (
            <Empty>No tracking companies contacted yet.</Empty>
          ) : (
            <table>
              <tbody>
                {n.companies.map((c) => (
                  <tr key={c.company}>
                    <td>
                      <b>{c.company}</b>
                      <div className="muted small">
                        {c.categories.map(categoryLabel).join(", ")} - by {c.processes.join(", ")}
                      </div>
                    </td>
                    <td className="num">{fmt(c.lookups)}</td>
                    <td style={{ width: 110 }}>
                      <Bar value={c.lookups} max={maxCompany} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Programs">
          {programs.length === 0 ? (
            <Empty>No program has contacted a tracker yet.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Program</th>
                  <th className="num">Tracker lookups</th>
                  <th className="num">All lookups</th>
                </tr>
              </thead>
              <tbody>
                {programs.map((p) => (
                  <tr key={p.process}>
                    <td>
                      <b>{p.process}</b>
                      <div className="muted small">{p.companies.join(", ")}</div>
                    </td>
                    <td className="num">{fmt(p.tracker_lookups)}</td>
                    <td className="num muted">{fmt(p.lookups)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}
