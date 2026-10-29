import { QueryClient, QueryFunction } from "@tanstack/react-query";
import { getLocalBundles, resolveOfflineQueryFallback } from "./local-analysis-engine";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (data) headers["Content-Type"] = "application/json";
  const token = localStorage.getItem("token");
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(url, {
    method,
    headers,
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const urlPath = queryKey.join("/") as string;

    // If querying a locally created scan-* or local-* submission, resolve immediately
    if (/\/api\/submissions\/(scan-|local-)/.test(urlPath)) {
      const localResult = await resolveOfflineQueryFallback(urlPath);
      if (localResult !== undefined) return localResult;
    }

    const headers: Record<string, string> = {};
    const token = localStorage.getItem("token");
    if (token) headers["Authorization"] = `Bearer ${token}`;

    try {
      const res = await fetch(urlPath, {
        credentials: "include",
        headers,
      });

      if (unauthorizedBehavior === "returnNull" && res.status === 401) {
        return null;
      }

      if (res.ok) {
        const json = await res.json();
        // Merge local submissions with backend submissions so local scans always show up
        if (urlPath === "/api/submissions" && Array.isArray(json)) {
          const localSubs = getLocalBundles().map((b) => b.submission);
          const backendIds = new Set(json.map((s: { id?: string }) => s.id));
          return [...localSubs.filter((s) => !backendIds.has(s.id)), ...json];
        }
        if (urlPath === "/api/engines" && Array.isArray(json) && json.length === 0) {
          return await resolveOfflineQueryFallback("/api/engines");
        }
        return json;
      }
    } catch {
      // Fall through to offline fallback below
    }

    const fallback = await resolveOfflineQueryFallback(urlPath);
    if (fallback !== undefined) {
      return fallback;
    }

    throw new Error(`Request failed: ${urlPath}`);
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});
