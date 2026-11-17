/** Plain words for each kind of data, most sensitive first (matches ga-core DataKind). */
export const KIND: Record<string, string> = {
  Email: "your email address",
  HashedEmail: "your email address (scrambled, but still identifies you)",
  HashedPersonalDetail: "personal details (scrambled)",
  PersonalDetail: "personal details",
  UserId: "your account ID",
  PersistentId: "an ID that recognises your device every time",
  ClickId: "which ad you clicked",
  PageUrl: "what you were looking at",
  PageTitle: "the page title",
  Referrer: "where you came from",
  Event: "what you did",
  Purchase: "what you bought",
  Device: "details about your device",
  TrackerAccount: "the app's tracker account",
  Other: "other details",
};
export const KIND_ORDER = Object.keys(KIND);

export function kindsInWords(kinds: string[]): string {
  return [...new Set(kinds)]
    .sort((a, b) => KIND_ORDER.indexOf(a) - KIND_ORDER.indexOf(b))
    .map((k) => KIND[k] ?? k)
    .join(", ");
}
