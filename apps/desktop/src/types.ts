// Shapes of the service's JSON replies (see the Rust types in ga-core,
// ga-report and ga-engine). Only the fields the UI uses are listed.

export interface Penalty { reason: string; points: number }
export interface Score { value: number; penalties: Penalty[] }

export interface CompanyExposure {
  company: string;
  categories: string[];
  cookie_count: number;
  domains: string[];
  browsers: string[];
}
export interface ScanWarning { browser: string; profile: string; message: string }
export type CookiePurpose = "tracking" | "login" | "security" | "preferences" | "consent" | "unknown";
export interface OtherCookies {
  by_purpose: { purpose: CookiePurpose; count: number }[];
  hidden_trackers: { tool: string; cookies: number; sites: number; examples: string[] }[];
  top_sites: { site: string; count: number; purposes: CookiePurpose[] }[];
}
export interface CookieReport {
  profiles_scanned: number;
  total_cookies: number;
  tracker_cookies: number;
  companies: CompanyExposure[];
  unclassified_cookies: number;
  unclassified_domains: number;
  other: OtherCookies;
  warnings: ScanWarning[];
}

export interface ScanProgress { percent: number; step: string; detail: string }
export interface RunningApp { exe: string; name: string; path: string; electron: boolean; pids: number[] }

export interface SensitivePermission { permission: string; meaning: string }
export interface BrowserExtension {
  browser: string;
  profile: string;
  id: string;
  name: string;
  version: string;
  enabled: boolean;
  source: string;
  risk: "High" | "Medium" | "Low";
  risk_reasons: string[];
  sensitive_permissions: SensitivePermission[];
}
export interface ExtensionScan { extensions: BrowserExtension[]; warnings: ScanWarning[]; profiles_scanned: number }

export interface PrivacySetting {
  id: string;
  area: string;
  title: string;
  state: string;
  exposure: "Exposed" | "Protected" | "Unknown";
  explanation: string;
  set_by_policy: boolean;
}
export interface AppAccess {
  capability: string;
  app: string;
  identifier: string;
  in_use_now: boolean;
  last_used_start_unix: number | null;
}
export interface PrivacyScan { settings: PrivacySetting[]; app_access: AppAccess[] }

export interface AppFinding {
  sdk: string;
  company: string;
  category: string;
  purpose: string;
  confidence: "High" | "Medium";
  evidence: string[];
}
export interface InstalledApp {
  name: string;
  publisher: string | null;
  version: string | null;
  install_dir: string;
  electron: boolean;
  findings: AppFinding[];
  bytes_scanned: number;
  truncated: boolean;
  skipped: SkippedFile[];
  skipped_count: number;
  skipped_bytes: number;
  too_many_files: boolean;
  full_scan: boolean;
}
export interface SkippedFile { path: string; size: number; reason: "too_large" | "app_limit" | "partly_read" }
export interface AppScan { apps: InstalledApp[] }

export interface CompanyContacts { company: string; categories: string[]; lookups: number; domains: string[]; processes: string[] }
export interface ProcessSummary { process: string; lookups: number; tracker_lookups: number; companies: string[] }
export interface NetworkReport {
  duration_secs: number;
  total_lookups: number;
  tracker_lookups: number;
  companies: CompanyContacts[];
  processes: ProcessSummary[];
}

export interface Overview {
  scanning: boolean;
  progress: ScanProgress | null;
  generated_unix: number | null;
  score: Score;
  unread_alerts: number;
  cookies: CookieReport | null;
  extensions: ExtensionScan | null;
  privacy: PrivacyScan | null;
  apps: AppScan | null;
  network: NetworkReport | null;
}

export interface Alert { id: number; unix: number; severity: "High" | "Medium" | "Info"; title: string; detail: string; read: boolean }

export interface FixWrite { location: string; current: string | null; new: string }
export interface Fix {
  setting_id: string;
  setting: string;
  state: string;
  explanation: string;
  fix: string;
  needs_admin: boolean;
  needs_restart: boolean;
  writes: FixWrite[];
}
export interface ChangeRecord { id: string; setting_id: string; title: string; applied_unix: number }

export interface DecodedField { key: string; label: string; kind: string; value: string }
export interface DecodedPayload { company: string; product: string; request_url: string; fields: DecodedField[] }
export interface InspectedRequest {
  app: string | null;
  host: string;
  method: string;
  path: string;
  status: number | null;
  request_bytes: number;
  payloads: DecodedPayload[];
}
export interface ProxyStatus {
  listening: string | null;
  error: string | null;
  inspected_apps: string[];
  refused_inspection: string[];
  recent_requests: number;
}

export interface CookieDeleteReport {
  deleted: number;
  profiles: { browser: string; profile: string; deleted: number }[];
  skipped: { browser: string; reason: string }[];
}

export type BlockingProfile = "relaxed" | "balanced" | "strict";
export interface BlockingStatus {
  enabled: boolean;
  running: boolean;
  profile: BlockingProfile;
  paused_until: number | null;
  adapters: string[];
  upstreams: string[];
  queries: number;
  blocked: number;
  top_companies: { company: string; blocked: number }[];
  allowed: string[];
  error: string | null;
  notice: string | null;
}
export interface BlockingPreview { adapters: { name: string; current: string }[] }
export interface SystemProxyStatus { on: boolean; other_proxy: boolean; proxy_running: boolean }
export interface ConsentSignal { source: string; summary: string; refused: boolean }
export interface PrivacyContact { name: string; email: string | null; form: string | null; self_service: string | null; source: string; how: string | null }
export interface CompanyActivity {
  company: string;
  category: string | null;
  requests: number;
  products: string[];
  sources: { source: string; requests: number }[];
  source_count: number;
  apps: string[];
  kinds: string[];
  identifiers: { label: string; value: string }[];
  cookies_set: { name: string; from: string[] }[];
  refused_but_identified: number;
  last_unix: number;
  contact: PrivacyContact | null;
}
export interface Sighting {
  unix: number;
  app: string | null;
  source: string | null;
  host: string;
  company: string;
  product: string | null;
  fields: DecodedField[];
  consent: ConsentSignal[];
  set_cookies: string[];
}
export interface SiteChoiceResult {
  site: string;
  refused_unix: number;
  requests_after: number;
  identifying_after: number;
  companies_after: string[];
  verdict: "ignored" | "anonymous_only" | "nothing_seen";
}
export interface DataRequestRecord { company: string; kind: "access" | "delete" | "object"; sent_unix: number; due_unix: number }
export interface Requester { name: string; email: string; region: "gdpr" | "ccpa" | "other" | "" }
export interface TrackerActivity {
  now: number;
  total: number;
  watching: boolean;
  proxy_running: boolean;
  companies: CompanyActivity[];
  sites: { site: string; requests: number; companies: string[] }[];
  choices: SiteChoiceResult[];
  recent: Sighting[];
  requests: DataRequestRecord[];
  requester: Requester;
  network_only?: { process: string; tracker_lookups: number; companies: string[] }[];
}