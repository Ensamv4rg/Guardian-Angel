// Data request letters. The user picks a company, a kind of request and
// their region; the letter names the IDs the company received from their
// devices so it can find the data. The user reviews and sends it themselves.

export type Region = "gdpr" | "ccpa" | "other";
export type RequestKind = "access" | "delete" | "object";

export const KIND_NAMES: Record<RequestKind, string> = {
  access: "Get a copy of my data",
  delete: "Delete my data",
  object: "Stop using my data for ads and tracking",
};

export const REGION_NAMES: Record<Region, string> = {
  gdpr: "EU, EEA or UK (GDPR)",
  ccpa: "California (CCPA)",
  other: "Somewhere else",
};

/** Where to complain if a company ignores the request or keeps tracking. */
export const REGULATORS: Record<Region, { name: string; url: string }[]> = {
  gdpr: [
    { name: "Your country's data protection authority (EU list)", url: "https://www.edpb.europa.eu/about-edpb/about-edpb/members_en" },
    { name: "UK Information Commissioner's Office", url: "https://ico.org.uk/make-a-complaint/" },
  ],
  ccpa: [{ name: "California Attorney General", url: "https://oag.ca.gov/contact/consumer-complaint-against-business-or-company" }],
  other: [],
};

export interface Identifier {
  label: string;
  value: string;
}

export function dueDays(region: Region): number {
  return region === "ccpa" ? 45 : 30;
}

export function letter(
  company: string,
  kind: RequestKind,
  region: Region,
  ids: Identifier[],
  name: string,
  email: string,
): { subject: string; body: string } {
  const law =
    region === "gdpr"
      ? { access: "Article 15", delete: "Article 17", object: "Article 21" }[kind] + " of the General Data Protection Regulation (GDPR)"
      : region === "ccpa"
        ? { access: "the right to know (Cal. Civ. Code § 1798.110)", delete: "the right to delete (Cal. Civ. Code § 1798.105)", object: "the right to opt out of sale and sharing (Cal. Civ. Code § 1798.120)" }[kind] +
          " under the California Consumer Privacy Act (CCPA)"
        : "your privacy policy and applicable data protection law";
  const subject = {
    access: "Request for a copy of my personal data",
    delete: "Request to delete my personal data",
    object: "Objection to processing of my personal data",
  }[kind];

  const what = {
    access: [
      "Please send me:",
      "1. a copy of all personal data you hold about me, including data linked to the identifiers below;",
      "2. the purposes you use it for;",
      "3. who you have shared it with or sold it to;",
      "4. how long you will keep it;",
      "5. where it came from, including the websites and apps that sent it to you;",
      "6. whether you use it for profiling or automated decisions, and how.",
    ],
    delete: [
      "Please delete all personal data you hold about me, including data linked to the identifiers below, and tell any companies you shared it with to delete it too.",
      "Please confirm when this is done.",
    ],
    object: [
      "I object to your use of my personal data for advertising, profiling and tracking, and I withdraw any consent I may have given. Please stop this processing, including for data linked to the identifiers below, and do not sell or share my data.",
      "Please confirm when this is done.",
    ],
  }[kind];

  const deadline =
    region === "gdpr"
      ? "Please reply within one month, as Article 12(3) GDPR requires."
      : region === "ccpa"
        ? "Please reply within 45 days, as the CCPA requires."
        : "Please reply within 30 days.";

  const idLines = ids.length
    ? ["", "These identifiers were sent to you from my devices, so you can find my data:", ...ids.map((i) => `- ${i.label}: ${i.value}`)]
    : [];

  const body = [
    `Dear ${company} privacy team,`,
    "",
    `I am making this request under ${law}.`,
    "",
    ...what,
    ...idLines,
    "",
    deadline,
    "",
    "Kind regards,",
    name || "[your name]",
    email || "[your email]",
  ].join("\n");
  return { subject, body };
}

export function mailto(to: string, subject: string, body: string): string {
  return `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

export function gmail(to: string, subject: string, body: string): string {
  return `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(to)}&su=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

export function outlook(to: string, subject: string, body: string): string {
  return `https://outlook.live.com/mail/0/deeplink/compose?to=${encodeURIComponent(to)}&subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
