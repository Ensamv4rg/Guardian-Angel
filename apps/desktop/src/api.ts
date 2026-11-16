import { invoke } from "@tauri-apps/api/core";

/** True inside the Tauri app; false in a plain browser (development preview). */
const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/**
 * Calls the Guardian Angel service. In the app this goes through the Rust
 * `ipc` command and the service's pipe; during development in a browser it
 * goes through the dev server's bridge to the same running service.
 */
export async function call<T = unknown>(method: string, params?: unknown): Promise<T> {
  if (inTauri) {
    return invoke<T>("ipc", { method, params: params ?? null });
  }
  if (import.meta.env.DEV) {
    const res = await fetch("/__ipc", { method: "POST", body: JSON.stringify({ method, params }) });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? "The Guardian Angel service is not running.");
    return body.result as T;
  }
  throw new Error("Open Guardian Angel from the desktop app.");
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
