import { useCallback, useEffect, useState } from "react";
import { errorText, isDesktopApp, native } from "./api";

interface UpdateInfo {
  /** False for builds made without the release signing key (development). */
  configured: boolean;
  current: string;
  available: { version: string; notes: string | null; date: string | null } | null;
}

type Status = "idle" | "checking" | "installing";

/** Update state shared by the banner and the sidebar. */
export function useUpdates() {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState<string | null>(null);

  const check = useCallback(async (quiet: boolean) => {
    if (!isDesktopApp) return;
    setStatus("checking");
    if (!quiet) setMessage(null);
    try {
      const result = await native<UpdateInfo>("check_update");
      setInfo(result);
      if (!quiet) {
        setMessage(
          !result.configured
            ? "This copy was built without updates. Download new versions from the Releases page."
            : result.available
              ? null
              : "You have the latest version.",
        );
      }
    } catch (e) {
      // A failed check on start-up (offline, say) is not worth interrupting for.
      if (!quiet) setMessage(errorText(e));
    } finally {
      setStatus("idle");
    }
  }, []);

  const install = useCallback(async () => {
    setStatus("installing");
    setMessage(null);
    try {
      // On success the installer closes and reopens the app.
      await native("install_update");
    } catch (e) {
      setMessage(errorText(e));
      setStatus("idle");
    }
  }, []);

  // Check once when the app opens, and then every six hours.
  useEffect(() => {
    check(true);
    const id = setInterval(() => check(true), 6 * 60 * 60 * 1000);
    return () => clearInterval(id);
  }, [check]);

  return { info, status, message, check, install };
}

type Updates = ReturnType<typeof useUpdates>;

export function UpdateBanner({ updates }: { updates: Updates }) {
  const { info, status, install } = updates;
  if (!info?.available) return null;
  return (
    <div className="notice info row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
      <span>
        Guardian Angel {info.available.version} is available. You have {info.current}.
        {status === "installing" && " Downloading... Windows will ask you to allow the update."}
      </span>
      <button className="btn primary" disabled={status !== "idle"} onClick={install}>
        {status === "installing" ? "Updating..." : "Update now"}
      </button>
    </div>
  );
}

export function UpdateFooter({ updates }: { updates: Updates }) {
  const { info, status, message, check } = updates;
  if (!isDesktopApp) return null;
  return (
    <div className="small" style={{ marginTop: 8 }}>
      {info && <div>Version {info.current}</div>}
      <button className="link" disabled={status !== "idle"} onClick={() => check(false)}>
        {status === "checking" ? "Checking..." : "Check for updates"}
      </button>
      {message && <div className="muted">{message}</div>}
    </div>
  );
}
