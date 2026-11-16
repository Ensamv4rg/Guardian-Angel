import type { PageProps } from "../App";
import { Badge, Bar, Card, Empty, PageHead, Tip, Waiting, categoryLabel, fmt } from "../components";
import type { CookiePurpose, CookieReport } from "../types";

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
      {c.unclassified_cookies > 0 && <OtherCookiesCard report={c} />}
      <p className="small muted">
        Tracker data: Guardian Angel's own list and DuckDuckGo Tracker Radar (CC BY-NC-SA 4.0), used for
        non-commercial purposes.
      </p>
    </>
  );
}

const PURPOSE: Record<CookiePurpose, { label: string; tone: "bad" | "warn" | "good" | "neutral" | "accent"; help: string }> = {
  tracking: {
    label: "Tracking",
    tone: "bad",
    help: "Set by a known tracking tool (like Google Analytics or Meta Pixel) under the website's own name, so tracker lists that check only domains miss it.",
  },
  login: { label: "Signing in", tone: "good", help: "Keeps you logged in or remembers your session. Needed for sites to work." },
  security: { label: "Security", tone: "good", help: "Bot protection (for example Cloudflare) and protection against forged requests." },
  preferences: { label: "Preferences", tone: "accent", help: "Remembers choices like language, theme or region." },
  consent: { label: "Cookie choices", tone: "accent", help: "Remembers what you picked in a cookie banner." },
  unknown: { label: "Unknown", tone: "neutral", help: "The name does not reveal what it is for. Most are harmless site settings, but some are custom trackers." },
};

function OtherCookiesCard({ report: c }: { report: CookieReport }) {
  const o = c.other;
  const maxPurpose = o.by_purpose[0]?.count ?? 0;
  return (
    <>
      <Card title={`Other cookies (${fmt(c.unclassified_cookies)} from ${fmt(c.unclassified_domains)} sites)`}>
        <p className="muted" style={{ marginTop: -4 }}>
          Cookies from sites that are not on the tracker list, sorted by what their names say they are for.
        </p>
        <table>
          <tbody>
            {o.by_purpose.map((p) => (
              <tr key={p.purpose}>
                <td style={{ width: 200 }}>
                  <Badge tone={PURPOSE[p.purpose].tone}>{PURPOSE[p.purpose].label}</Badge>
                  <Tip text={PURPOSE[p.purpose].help} />
                </td>
                <td className="num" style={{ width: 80 }}>{fmt(p.count)}</td>
                <td>
                  <Bar value={p.count} max={maxPurpose} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      {o.hidden_trackers.length > 0 && (
        <Card title="Trackers hiding under sites' own names">
          <p className="muted" style={{ marginTop: -4 }}>
            These tracking tools run on websites you visited and store their cookies under each site's own name.
          </p>
          <table>
            <thead>
              <tr>
                <th>Tool</th>
                <th className="num">Sites</th>
                <th className="num">Cookies</th>
                <th>For example</th>
              </tr>
            </thead>
            <tbody>
              {o.hidden_trackers.map((h) => (
                <tr key={h.tool}>
                  <td><b>{h.tool}</b></td>
                  <td className="num">{fmt(h.sites)}</td>
                  <td className="num">{fmt(h.cookies)}</td>
                  <td className="muted small">{h.examples.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Card title="Sites with the most other cookies">
        <table>
          <tbody>
            {o.top_sites.map((s) => (
              <tr key={s.site}>
                <td>{s.site}</td>
                <td>
                  {s.purposes.map((p) => (
                    <span key={p} style={{ marginRight: 4 }}>
                      <Badge tone={PURPOSE[p].tone}>{PURPOSE[p].label}</Badge>
                    </span>
                  ))}
                </td>
                <td className="num">{fmt(s.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}
