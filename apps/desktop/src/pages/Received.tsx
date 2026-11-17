import { useCallback, useEffect, useMemo, useState } from "react";
import type { PageProps } from "../App";
import { call, errorText, isDesktopApp, native } from "../api";
import { Badge, Card, Empty, ErrorNotice, PageHead, Stat, Tip, ago, fmt } from "../components";
import { kindsInWords } from "../kinds";
import {
  KIND_NAMES,
  REGION_NAMES,
  REGULATORS,
  type Region,
  type RequestKind,
  dueDays,
  gmail,
  letter,
  mailto,
  outlook,
} from "../letters";
import type { CompanyActivity, SystemProxyStatus, TrackerActivity } from "../types";

type Tab = "companies" | "sites" | "choices" | "requests" | "latest";
const TABS: [Tab, string][] = [
  ["companies", "By company"],
  ["sites", "By site"],
  ["choices", "Did they listen?"],
  ["requests", "Ask for your data"],
  ["latest", "Latest"],
];

const open = (url: string) => native("open_link", { url });
const date = (unix: number) => new Date(unix * 1000).toLocaleDateString();

export default function ReceivedPage({ go }: PageProps) {
  const [data, setData] = useState<TrackerActivity | null>(null);
  const [proxy, setProxy] = useState<SystemProxyStatus | null>(null);
  const [trusted, setTrusted] = useState<boolean | null>(null);
  const [tab, setTab] = useState<Tab>("companies");
  const [error, setError] = useState<string | null>(null);
  const [requestFor, setRequestFor] = useState<string>("");

  const load = useCallback(async () => {
    try {
      setData(await call<TrackerActivity>("tracker_activity"));
      if (isDesktopApp) {
        setProxy(await native<SystemProxyStatus>("system_proxy_status").catch(() => null));
        setTrusted(await native<boolean>("certificate_trusted").catch(() => false));
      }
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, [load]);

  const act = async (method: string, params: unknown) => {
    setError(null);
    try {
      await call(method, params);
      await load();
    } catch (e) {
      setError(errorText(e));
    }
  };

  if (!data) return <PageHead title="What trackers got" lead="Loading..." />;
  const ready = data.watching && trusted && proxy?.on;
  const sitesCount = data.sites.length;

  return (
    <>
      <PageHead
        title="What trackers got"
        lead="What your browsers and apps sent to tracking companies, where it came from, and whether sites kept to your choices. Only connections to known trackers are read; everything else is left alone."
      />
      <ErrorNotice message={error} />

      {!ready && (
        <Card title="Set up watching">
          <div className="steps">
            <div className={`step ${data.watching ? "done" : ""}`}>
              <div>
                <h3>
                  Watch traffic to trackers
                  <Tip text="Guardian Angel reads only connections to known tracking companies, from every app and browser. Your bank, email and everything else are never read." />
                </h3>
                {data.watching ? (
                  <Badge tone="good">On</Badge>
                ) : (
                  <button className="btn primary" onClick={() => act("set_watch_trackers", { on: true })}>Turn on</button>
                )}
              </div>
            </div>
            <div className={`step ${trusted ? "done" : ""}`}>
              <div>
                <h3>Allow Guardian Angel to read encrypted traffic</h3>
                {trusted ? <Badge tone="good">Allowed</Badge> : <button className="btn" onClick={() => go("inspect")}>Set up in Inspect traffic (step 2)</button>}
              </div>
            </div>
            <div className={`step ${proxy?.on ? "done" : ""}`}>
              <div>
                <h3>Send traffic through Guardian Angel</h3>
                {proxy?.on ? <Badge tone="good">On</Badge> : <button className="btn" onClick={() => go("inspect")}>Set up in Inspect traffic (step 3)</button>}
              </div>
            </div>
          </div>
          <p className="small muted">After setting up, restart your browser. Results appear as you browse.</p>
        </Card>
      )}

      <div className="grid cols-4" style={{ margin: "16px 0" }}>
        <Stat value={fmt(data.total)} label="requests to trackers (30 days)" />
        <Stat value={fmt(data.companies.length)} label="companies received data" />
        <Stat value={fmt(sitesCount)} label="sites sent it" />
        <Stat
          value={fmt(data.choices.filter((c) => c.verdict === "ignored").length)}
          label="sites ignored your choice"
        />
      </div>

      <div className="tabs" role="tablist">
        {TABS.map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={`tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
        {data.watching && (
          <button className="btn small-btn" style={{ marginLeft: "auto" }} onClick={() => act("set_watch_trackers", { on: false })}>
            Stop watching
          </button>
        )}
      </div>

      {tab === "companies" && (
        <CompaniesTab
          companies={data.companies}
          ask={(company) => {
            setRequestFor(company);
            setTab("requests");
          }}
        />
      )}
      {tab === "sites" && <SitesTab data={data} choose={(site, refused) => act("set_site_choice", { site, refused })} />}
      {tab === "choices" && <ChoicesTab data={data} choose={(site, refused) => act("set_site_choice", { site, refused })} />}
      {tab === "requests" && <RequestsTab data={data} company={requestFor} setCompany={setRequestFor} act={act} />}
      {tab === "latest" && <LatestTab data={data} />}

      {data.network_only && data.network_only.length > 0 && (
        <Card title="Also contacted trackers, contents not readable">
          <p className="small muted" style={{ marginTop: 0 }}>
            These programs looked up tracking companies but don't use Windows' proxy setting, so what they sent can't be read.
          </p>
          {data.network_only.map((p) => (
            <div key={p.process} className="list-item">
              <b>{p.process}</b> <span className="muted">contacted {p.companies.join(", ")}</span>
            </div>
          ))}
        </Card>
      )}
    </>
  );
}

function CompaniesTab({ companies, ask }: { companies: CompanyActivity[]; ask: (company: string) => void }) {
  if (companies.length === 0) return <Card><Empty>Nothing yet. Browse as normal and check back.</Empty></Card>;
  return (
    <>
      {companies.map((c) => (
        <Card
          key={c.company}
          title={c.company}
          actions={
            <>
              <Badge tone="neutral">{fmt(c.requests)} requests</Badge>
              <button className="btn" onClick={() => ask(c.company)}>Ask for my data</button>
            </>
          }
        >
          {c.refused_but_identified > 0 && (
            <div className="notice error">
              {fmt(c.refused_but_identified)} request{c.refused_but_identified === 1 ? "" : "s"} carried your refusal from a cookie banner but still included an ID for you.
            </div>
          )}
          <div><b>Received:</b> {kindsInWords(c.kinds) || "nothing readable"}</div>
          {c.products.length > 0 && <div className="muted small">Through: {c.products.join(", ")}</div>}
          <div style={{ marginTop: 6 }}>
            <b>Sent from:</b> {c.sources.map((s) => `${s.source} (${fmt(s.requests)})`).join(", ")}
            {c.source_count > c.sources.length && ` and ${c.source_count - c.sources.length} more`}
          </div>
          {c.cookies_set.length > 0 && (
            <div style={{ marginTop: 6 }}>
              <b>Cookies it set:</b>{" "}
              {c.cookies_set.map((k) => `${k.name} (while on ${k.from.slice(0, 3).join(", ")}${k.from.length > 3 ? "..." : ""})`).join("; ")}
              <Tip text="Which site you were on when this company placed each cookie in your browser. Only cookie names are recorded, never their contents." />
            </div>
          )}
          {c.identifiers.length > 0 && (
            <details>
              <summary>IDs it holds for you ({c.identifiers.length})</summary>
              <div className="fields">
                {c.identifiers.map((i) => (
                  <div key={i.value} style={{ display: "contents" }}>
                    <div className="k">{i.label}</div>
                    <div className="v mono">{i.value}</div>
                  </div>
                ))}
              </div>
            </details>
          )}
        </Card>
      ))}
    </>
  );
}

function SitesTab({ data, choose }: { data: TrackerActivity; choose: (site: string, refused: boolean) => void }) {
  if (data.sites.length === 0) return <Card><Empty>No sites yet.</Empty></Card>;
  const refused = new Set(data.choices.map((c) => c.site));
  return (
    <Card>
      <table>
        <thead>
          <tr>
            <th>Site</th>
            <th>Sent data to</th>
            <th className="num">Requests</th>
            <th>
              Your choice <Tip text="Mark the sites where you refused tracking in their cookie banner. Guardian Angel then checks whether they still send your data." />
            </th>
          </tr>
        </thead>
        <tbody>
          {data.sites.map((s) => (
            <tr key={s.site}>
              <td>{s.site}</td>
              <td>{s.companies.join(", ")}</td>
              <td className="num">{fmt(s.requests)}</td>
              <td>
                {refused.has(s.site) ? (
                  <button className="btn" onClick={() => choose(s.site, false)}>Forget my choice</button>
                ) : (
                  <button className="btn" onClick={() => choose(s.site, true)}>I said no here</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

const VERDICT: Record<string, { tone: "bad" | "warn" | "good"; text: string }> = {
  ignored: { tone: "bad", text: "Still sent your ID" },
  anonymous_only: { tone: "warn", text: "Contacted trackers, no ID seen" },
  nothing_seen: { tone: "good", text: "No tracker contact seen" },
};

function ChoicesTab({ data, choose }: { data: TrackerActivity; choose: (site: string, refused: boolean) => void }) {
  const [site, setSite] = useState("");
  const region = (data.requester.region || "gdpr") as Region;
  return (
    <>
      <Card title="Sites where you said no">
        <p className="small muted" style={{ marginTop: 0 }}>
          When you refuse tracking in a site's cookie banner, add the site here (or use "I said no here" under By site). Guardian Angel then
          watches what it sends from that moment on. Choices inside the requests themselves (Google Consent Mode, IAB consent strings, Global Privacy
          Control) are checked automatically.
        </p>
        <div className="row">
          <input className="text" placeholder="news.example" value={site} onChange={(e) => setSite(e.target.value)} />
          <button
            className="btn primary"
            disabled={!site.trim()}
            onClick={() => {
              choose(site.trim(), true);
              setSite("");
            }}
          >
            Add
          </button>
        </div>
      </Card>
      <Card>
        {data.choices.length === 0 ? (
          <Empty>No choices recorded yet.</Empty>
        ) : (
          data.choices.map((c) => (
            <div key={c.site} className="list-item">
              <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
                <div>
                  <b>{c.site}</b> <span className="muted small">you said no on {date(c.refused_unix)}</span>
                </div>
                <div className="row">
                  <Badge tone={VERDICT[c.verdict].tone}>{VERDICT[c.verdict].text}</Badge>
                  <button className="btn" onClick={() => choose(c.site, false)}>Forget</button>
                </div>
              </div>
              {c.verdict === "ignored" && (
                <div className="small" style={{ marginTop: 6 }}>
                  Since then, {fmt(c.identifying_after)} request{c.identifying_after === 1 ? "" : "s"} sent an ID for you to {c.companies_after.join(", ")}.
                  {REGULATORS[region].length > 0 && (
                    <>
                      {" "}You can report this:{" "}
                      {REGULATORS[region].map((r) => (
                        <button key={r.url} className="link" onClick={() => open(r.url)} style={{ marginRight: 8 }}>
                          {r.name}
                        </button>
                      ))}
                    </>
                  )}
                </div>
              )}
              {c.verdict === "anonymous_only" && (
                <div className="small muted" style={{ marginTop: 6 }}>{fmt(c.requests_after)} requests since, without an ID Guardian Angel could recognise.</div>
              )}
            </div>
          ))
        )}
      </Card>
    </>
  );
}

function RequestsTab({
  data,
  company,
  setCompany,
  act,
}: {
  data: TrackerActivity;
  company: string;
  setCompany: (c: string) => void;
  act: (method: string, params: unknown) => Promise<void>;
}) {
  const [name, setName] = useState(data.requester.name);
  const [email, setEmail] = useState(data.requester.email);
  const [region, setRegion] = useState<Region>((data.requester.region || "gdpr") as Region);
  const [kind, setKind] = useState<RequestKind>("access");
  const [include, setInclude] = useState<Record<string, boolean>>({});
  const [copied, setCopied] = useState(false);

  const target = data.companies.find((c) => c.company === company) ?? null;
  const ids = (target?.identifiers ?? []).filter((i) => include[i.value] !== false);
  const draft = useMemo(() => (company ? letter(company, kind, region, ids, name, email) : null), [company, kind, region, ids, name, email]);
  const [edited, setEdited] = useState<string | null>(null);
  useEffect(() => setEdited(null), [company, kind, region]);
  const body = edited ?? draft?.body ?? "";
  const contact = target?.contact ?? null;

  const saveRequester = () => act("set_requester", { name, email, region });
  const markSent = () => act("set_data_request", { company, kind, sent: true });
  const copy = async () => {
    await navigator.clipboard.writeText(`${draft?.subject}\n\n${body}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      <Card title="Your details for the letters">
        <p className="small muted" style={{ marginTop: 0 }}>Kept only on this PC, and only put into letters you send yourself.</p>
        <div className="row" style={{ flexWrap: "wrap" }}>
          <input className="text" placeholder="Your name" value={name} onChange={(e) => setName(e.target.value)} />
          <input className="text" placeholder="Your email" value={email} onChange={(e) => setEmail(e.target.value)} />
          <select className="text" value={region} onChange={(e) => setRegion(e.target.value as Region)} aria-label="Where you live">
            {Object.entries(REGION_NAMES).map(([id, label]) => (
              <option key={id} value={id}>{label}</option>
            ))}
          </select>
          <button className="btn" onClick={saveRequester}>Save</button>
        </div>
      </Card>

      <Card title="Write a request">
        <div className="row" style={{ flexWrap: "wrap" }}>
          <select className="text" value={company} onChange={(e) => setCompany(e.target.value)} aria-label="Company">
            <option value="">Choose a company...</option>
            {data.companies.map((c) => (
              <option key={c.company} value={c.company}>{c.company}</option>
            ))}
          </select>
          <select className="text" value={kind} onChange={(e) => setKind(e.target.value as RequestKind)} aria-label="Kind of request">
            {Object.entries(KIND_NAMES).map(([id, label]) => (
              <option key={id} value={id}>{label}</option>
            ))}
          </select>
        </div>

        {company && draft && (
          <>
            {target && target.identifiers.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div className="small"><b>Include these IDs</b> (they help the company find your data):</div>
                {target.identifiers.map((i) => (
                  <label key={i.value} className="row small">
                    <input
                      type="checkbox"
                      checked={include[i.value] !== false}
                      onChange={(e) => setInclude({ ...include, [i.value]: e.target.checked })}
                    />
                    {i.label}: <span className="mono">{i.value}</span>
                  </label>
                ))}
              </div>
            )}
            <div style={{ marginTop: 10 }}>
              <div className="small"><b>Subject:</b> {draft.subject}</div>
              <textarea className="text letter" value={body} onChange={(e) => setEdited(e.target.value)} rows={16} />
            </div>

            <div className="row" style={{ flexWrap: "wrap", marginTop: 8 }}>
              {contact?.email && (
                <>
                  <button className="btn primary" onClick={() => open(mailto(contact.email!, draft.subject, body))}>Open in my mail app</button>
                  <button className="btn" onClick={() => open(gmail(contact.email!, draft.subject, body))}>Gmail</button>
                  <button className="btn" onClick={() => open(outlook(contact.email!, draft.subject, body))}>Outlook.com</button>
                </>
              )}
              {contact?.form && (
                <button className={`btn ${contact.email ? "" : "primary"}`} onClick={() => open(contact.form!)}>Open {company}'s request form</button>
              )}
              <button className="btn" onClick={copy}>{copied ? "Copied" : "Copy letter"}</button>
              <button className="btn" onClick={markSent}>I've sent it</button>
            </div>
            <div className="small muted" style={{ marginTop: 6 }}>
              {contact ? (
                <>
                  {contact.how ?? (contact.email ? `Sends to ${contact.email}.` : "")}{" "}
                  {contact.self_service && (
                    <button className="link" onClick={() => open(contact.self_service!)}>Download your data yourself first</button>
                  )}{" "}
                  <button className="link" onClick={() => open(contact.source)}>Where this contact comes from</button>
                </>
              ) : (
                <>
                  Guardian Angel doesn't have a checked contact for {company}. Copy the letter and send it to the address in their privacy policy.{" "}
                  <button className="link" onClick={() => open(`https://duckduckgo.com/?q=${encodeURIComponent(`${company} privacy policy data request`)}`)}>
                    Search for it
                  </button>
                </>
              )}
            </div>
          </>
        )}
      </Card>

      <Card title="Requests you sent">
        {data.requests.length === 0 ? (
          <Empty>None yet. After sending a request, press "I've sent it" to track the reply deadline ({dueDays(region)} days).</Empty>
        ) : (
          data.requests.map((r) => {
            const late = r.due_unix < data.now;
            return (
              <div key={`${r.company}-${r.kind}`} className="list-item row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
                <div>
                  <b>{r.company}</b> <span className="muted">{KIND_NAMES[r.kind]}</span>
                  <div className="small muted">Sent {date(r.sent_unix)}, reply due {date(r.due_unix)}</div>
                </div>
                <div className="row">
                  <Badge tone={late ? "bad" : "neutral"}>{late ? "Overdue" : `${Math.ceil((r.due_unix - data.now) / 86400)} days left`}</Badge>
                  {late && REGULATORS[region][0] && (
                    <button className="link" onClick={() => open(REGULATORS[region][0].url)}>Complain</button>
                  )}
                  <button className="btn" onClick={() => act("set_data_request", { company: r.company, kind: r.kind, sent: false })}>
                    Done
                  </button>
                </div>
              </div>
            );
          })
        )}
      </Card>
    </>
  );
}

function LatestTab({ data }: { data: TrackerActivity }) {
  if (data.recent.length === 0) return <Card><Empty>Nothing yet.</Empty></Card>;
  return (
    <Card>
      {data.recent.map((s, i) => (
        <div key={`${s.unix}-${i}`} className="list-item">
          <div className="row" style={{ flexWrap: "wrap" }}>
            <b>{s.source ?? s.app ?? "An app"}</b> <span className="muted">sent to</span> <b>{s.company}</b>
            {s.product && <Badge tone="neutral">{s.product}</Badge>}
            <span className="muted small">{ago(s.unix)}</span>
          </div>
          <div>{kindsInWords(s.fields.map((f) => f.kind)) || "nothing readable"}</div>
          {s.consent.length > 0 && <div className="small muted">Your choice in this request: {s.consent.map((c) => c.summary).join("; ")}</div>}
          {s.fields.length > 0 && (
            <details>
              <summary>Show exactly what was sent</summary>
              <div className="fields">
                {s.fields.map((f, j) => (
                  <div key={`${f.key}-${j}`} style={{ display: "contents" }}>
                    <div className="k">{f.label}</div>
                    <div className="v mono">{f.value}</div>
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      ))}
    </Card>
  );
}
