// Website checks for a URL, run by Verdyx's API (36 checks: DNS, TLS, headers,
// WHOIS, CT logs, page content). Only what that service observed is shown.
//
// There is deliberately no in-browser fallback: one used to fill unreachable
// checks with made-up certificate chains, cipher suites and grades, and claim
// blocklists were checked that never were. A failure is reported as a failure.

export interface SavedOsintScan {
  id: string;
  url: string;
  host: string;
  createdAt: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  intel: Record<string, any>;
}

const STORAGE_KEY = "verdyx_saved_osint_scans";

export function getSavedOsintScans(): SavedOsintScan[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function saveOsintScan(url: string, host: string, intel: Record<string, any>) {
  if (typeof window === "undefined" || !host) return;
  try {
    const existing = getSavedOsintScans().filter((s) => s.host !== host);
    const entry: SavedOsintScan = {
      id: `osint-${host}`,
      url,
      host,
      createdAt: new Date().toISOString(),
      intel,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify([entry, ...existing].slice(0, 15)));
  } catch {
    // Ignore storage quota errors
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function fetchLiveWebsiteIntel(targetUrl: string): Promise<Record<string, any>> {
  const cleaned = targetUrl.trim();
  const normalizedUrl = /^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`;
  try {
    new URL(normalizedUrl);
  } catch {
    throw new Error("That isn't a valid URL or domain name.");
  }

  let res: Response;
  try {
    res = await fetch(`/api/analysis/web-intel?url=${encodeURIComponent(normalizedUrl)}`, {
      credentials: "include",
    });
  } catch {
    throw new Error("Verdyx couldn't be reached to run the website checks. Try again.");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const message = typeof body?.message === "string" ? body.message : null;
    throw new Error(
      message ??
        (res.status === 429
          ? "Too many website checks. Wait a minute and try again."
          : `The website checks failed (HTTP ${res.status}).`),
    );
  }
  const data = await res.json();
  if (!data || !data.host) throw new Error("The website checks returned no result.");
  saveOsintScan(normalizedUrl, data.host, data);
  return data;
}
