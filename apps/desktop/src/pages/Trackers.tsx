import type { PageProps } from "../App";
import { Badge, Bar, Card, Empty, PageHead, Waiting, categoryLabel, fmt } from "../components";

export default function TrackersPage({ overview }: PageProps) {
  const c = overview?.cookies;
  if (!c) return <Waiting what="Reading browser cookies..." />;
  const max = c.companies[0]?.cookie_count ?? 0;
  const share = c.total_cookies ? Math.round((c.tracker_cookies / c.total_cookies) * 100) : 0;

  return (
    <>
      <PageHead
        title="Trackers"
        lead={`Companies that keep cookies in your browsers. ${fmt(c.tracker_cookies)} of ${fmt(c.total_cookies)} cookies (${share}%) belong to known trackers, across ${c.profiles_scanned} browser profiles. Only names and sites are read, never cookie contents.`}
      />
      {c.warnings.length > 0 && (
        <div className="notice info">
          {c.warnings.length} browser profile{c.warnings.length === 1 ? " was" : "s were"} skipped because the browser is open.
          Close it and scan again to include {c.warnings.length === 1 ? "it" : "them"}.
        </div>
      )}
      <Card>
        {c.companies.length === 0 ? (
          <Empty>No known tracking companies found.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Company</th>
                <th>What they do</th>
                <th>Browsers</th>
                <th className="num">Cookies</th>
                <th style={{ width: 140 }} />
              </tr>
            </thead>
            <tbody>
              {c.companies.map((co) => (
                <tr key={co.company}>
                  <td>
                    <b>{co.company}</b>
                    <div className="muted small">{co.domains.join(", ")}</div>
                  </td>
                  <td>
                    {co.categories.map((cat) => (
                      <span key={cat} style={{ marginRight: 4 }}>
                        <Badge tone={cat === "advertising" || cat === "audience_data" ? "bad" : "accent"}>{categoryLabel(cat)}</Badge>
                      </span>
                    ))}
                  </td>
                  <td className="muted">{co.browsers.join(", ")}</td>
                  <td className="num">{fmt(co.cookie_count)}</td>
                  <td>
                    <Bar value={co.cookie_count} max={max} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {c.unclassified_cookies > 0 && (
        <p className="muted small">
          {fmt(c.unclassified_cookies)} more cookies come from {fmt(c.unclassified_domains)} sites not in the tracker list yet.
        </p>
      )}
    </>
  );
}
