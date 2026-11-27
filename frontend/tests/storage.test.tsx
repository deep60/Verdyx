import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TeamStorage } from "@/components/team-storage";
import { describe as describeEvent } from "@/components/audit-log";
import { engineFacts } from "@/lib/report";
import type { ApiAnalysis } from "@/lib/api-types";
import {
  connectionStatus,
  createBody,
  emptyForm,
  formProblem,
  locationOf,
  objectStatus,
  type StorageConnection,
  type StorageList,
  type StorageObject,
} from "@/lib/storage";

const connection = (over: Partial<StorageConnection> = {}): StorageConnection => ({
  id: "c1",
  name: "Customer uploads",
  provider: "aws",
  endpoint: null,
  region: "eu-west-2",
  bucket: "acme-uploads",
  prefix: "incoming/",
  accessKeyId: "AKIAEXAMPLE",
  analysisType: "full",
  intervalMinutes: 60,
  maxObjectMb: 32,
  enabled: true,
  scanSince: "2026-11-27T00:00:00Z",
  scanRequested: false,
  running: false,
  lastRunAt: "2026-11-27T10:00:00Z",
  lastError: null,
  lastScanned: 3,
  createdAt: "2026-11-27T00:00:00Z",
  stats: { files: 12, flagged: 2, waiting: 1 },
  ...over,
});

const object = (over: Partial<StorageObject> = {}): StorageObject => ({
  key: "incoming/invoice.exe",
  size: 2048,
  lastModified: null,
  status: "queued",
  error: null,
  seenAt: "2026-11-27T10:00:00Z",
  submissionId: "s1",
  analysisStatus: "completed",
  verdict: "malicious",
  ...over,
});

describe("storage connections", () => {
  it("says how each connection is doing", () => {
    const now = Date.parse("2026-11-27T10:05:00Z");
    expect(connectionStatus(connection(), now)).toEqual({ text: "Checked 5 min ago: 3 new files", tone: "ok" });
    expect(connectionStatus(connection({ lastScanned: 0 }), now).text).toBe("Checked 5 min ago: no new files");
    expect(connectionStatus(connection({ enabled: false }), now).text).toBe("Off");
    expect(connectionStatus(connection({ lastError: "couldn't list the bucket: the key has expired" }), now)).toEqual({
      text: "Last run failed: couldn't list the bucket: the key has expired",
      tone: "danger",
    });
    expect(connectionStatus(connection({ lastRunAt: null }), now).text).toBe("Looks for files within a minute");
  });

  it("names the location the way each provider does", () => {
    expect(locationOf(connection())).toBe("s3://acme-uploads/incoming/");
    expect(locationOf(connection({ provider: "gcs", prefix: "" }))).toBe("gs://acme-uploads/");
  });

  it("says what happened to each file", () => {
    expect(objectStatus(object())).toEqual({ text: "Malicious", tone: "danger" });
    expect(objectStatus(object({ verdict: "benign" })).text).toBe("Clean");
    expect(objectStatus(object({ verdict: "unknown" })).text).toBe("No verdict");
    expect(objectStatus(object({ analysisStatus: "pending", verdict: null })).text).toBe("Scanning…");
    expect(objectStatus(object({ status: "too_large", submissionId: null })).text).toBe("Not scanned: over the size limit");
    expect(objectStatus(object({ status: "failed", error: "timed out", submissionId: null })).text).toBe(
      "Couldn't download: timed out",
    );
  });

  it("asks only for what the provider needs, and sends only that", () => {
    const f = { ...emptyForm(), name: "Uploads", bucket: "acme", accessKeyId: "AKIA", secretAccessKey: "k" };
    expect(formProblem(f)).toBe("Enter the bucket's region.");
    expect(formProblem({ ...f, region: "us-east-1" })).toBe("");
    expect(formProblem({ ...f, provider: "r2" })).toBe("Enter the endpoint.");
    expect(formProblem({ ...f, provider: "other", endpoint: "http://minio.example.com", region: "x" })).toBe(
      "The endpoint must use https.",
    );
    expect(formProblem({ ...f, provider: "gcs" })).toBe("");
    const gcs = createBody({ ...f, provider: "gcs", endpoint: "ignored", region: "ignored" });
    expect(gcs.endpoint).toBeUndefined();
    expect(gcs.region).toBeUndefined();
    expect(emptyForm(20).maxObjectMb).toBe(20);
  });

  const render = (data: StorageList) => {
    const client = new QueryClient();
    client.setQueryData(["/api/orgs/t1/storage"], data);
    return renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <TeamStorage teamId="t1" teamName="Blue Team" />
      </QueryClientProvider>,
    );
  };

  it("lists connections without their secret key", () => {
    const html = render({ connections: [connection()], limit: 5, maxObjectMb: 100 });
    expect(html).toContain("Customer uploads");
    expect(html).toContain("s3://acme-uploads/incoming/");
    expect(html).toContain("2 flagged");
    expect(html).toContain("Connect storage");
    expect(html).not.toMatch(/secret/i);
  });

  it("stops offering new connections at the limit", () => {
    const html = render({ connections: [connection()], limit: 1, maxObjectMb: 100 });
    expect(html).toContain("Up to 1 connections");
    expect(html).toMatch(/data-testid="storage-add"[^>]*disabled|disabled[^>]*data-testid="storage-add"/);
  });
});

describe("email reports", () => {
  const links = (meta: Record<string, unknown>): ApiAnalysis => ({
    id: "e",
    engine: { name: "Email links", version: "live" },
    metadata: meta,
  });

  it("lists flagged links first, with who flagged them", () => {
    const facts = engineFacts(
      links({
        linksFound: 9,
        links: [
          { url: "https://ok.example/", verdict: "Unknown", engines: [] },
          { url: "https://evil.example/login", verdict: "Malicious", engines: ["URLhaus", "URL checks"] },
        ],
      }),
    );
    expect(facts[0]).toMatchObject({
      label: "Link",
      value: "https://evil.example/login: malicious by URLhaus, URL checks",
      tone: "danger",
    });
    expect(facts[1]).toMatchObject({ value: "https://ok.example/: not flagged", tone: "muted" });
    expect(facts[2]).toMatchObject({ value: "and 7 more not looked up" });
  });

  it("calls an email's contents attachments", () => {
    const facts = engineFacts({
      id: "a",
      engine: { name: "Archive contents", version: "1" },
      metadata: { format: "email", files: [{ path: "invoice.zip", verdict: "Malicious" }] },
    });
    expect(facts[0]).toMatchObject({ label: "Inside the email", value: "invoice.zip: malicious" });
  });
});

describe("activity log", () => {
  const event = (action: string, details: Record<string, unknown> = {}) =>
    ({ id: 1, action, details, createdAt: "2026-11-27T00:00:00Z" }) as never;
  it("describes the storage events", () => {
    expect(describeEvent(event("team.storage_added", { bucket: "acme", name: "Uploads" }))).toBe(
      "Connected the bucket acme as “Uploads”",
    );
    expect(describeEvent(event("team.storage_changed", { name: "Uploads", changed: "keys, turned off" }))).toBe(
      "Changed the storage connection “Uploads”: keys, turned off",
    );
    expect(describeEvent(event("team.storage_removed", { bucket: "acme" }))).toBe("Disconnected the bucket acme");
    expect(describeEvent(event("team.storage_scan_requested", { name: "Uploads" }))).toBe("Asked for a scan of “Uploads”");
  });
});
