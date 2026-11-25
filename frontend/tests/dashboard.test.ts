import { describe, expect, it } from "vitest";
import type { ApiEngine } from "@/lib/api-types";
import {
  detectInput,
  engineSummary,
  enginesFor,
  formatBytes,
  greeting,
  normalizeUrl,
  toDashboardTab,
  verdictMix,
} from "@/lib/dashboard";

const engine = (engineType: string, status: string): ApiEngine => ({
  id: `${engineType}-${status}-${Math.random()}`,
  name: engineType,
  engineType,
  status,
});

describe("dashboard", () => {
  it("recognises what was pasted into the scan box", () => {
    expect(detectInput("https://paypa1.com/login")).toBe("url");
    expect(detectInput("paypa1-secure.com/verify?x=1")).toBe("url");
    expect(detectInput("44d88612fea8a8f36de82e1278abb02f")).toBe("hash");
    expect(detectInput("a".repeat(64))).toBe("hash");
    expect(detectInput("From: billing@paypa1.com\nSubject: Locked\n\nHi")).toBe("email");
    expect(detectInput("not a url at all")).toBeNull();
    expect(detectInput("   ")).toBeNull();
  });

  it("adds https to a bare domain", () => {
    expect(normalizeUrl(" example.com/a ")).toBe("https://example.com/a");
    expect(normalizeUrl("http://example.com")).toBe("http://example.com");
  });

  it("lists only the engines that vote in each depth", () => {
    const engines = [engine("hash", "online"), engine("static", "online"), engine("ml", "advisory"), engine("clamav", "unavailable")];
    expect(enginesFor("quick", engines).map((e) => e.engineType)).toEqual(["hash", "clamav"]);
    expect(enginesFor("full", engines)).toHaveLength(4);
  });

  it("counts voting, advisory and switched-off engines", () => {
    const sum = engineSummary([engine("hash", "online"), engine("ml", "advisory"), engine("clamav", "disabled"), engine("x", "")]);
    expect(sum).toEqual({ online: 1, advisory: 1, off: 2, total: 4 });
  });

  it("shows the platform verdict mix only once there are verdicts", () => {
    expect(verdictMix(undefined)).toBeNull();
    expect(verdictMix({ maliciousCount: 0, benignCount: 0 })).toBeNull();
    expect(verdictMix({ maliciousCount: 8, suspiciousCount: 1, benignCount: 7 })).toEqual({
      malicious: 8,
      suspicious: 1,
      clean: 7,
      total: 16,
    });
  });

  it("keeps old tab links working", () => {
    expect(toDashboardTab("#yara")).toBe("yara");
    expect(toDashboardTab("web-intel")).toBe("recon");
    expect(toDashboardTab("diff")).toBe("compare");
    expect(toDashboardTab("pipeline")).toBe("overview");
    expect(toDashboardTab("")).toBe("overview");
    expect(toDashboardTab("nonsense")).toBe("overview");
  });

  it("greets by time of day and formats sizes", () => {
    expect(greeting(new Date(2026, 10, 25, 9))).toBe("Good morning");
    expect(greeting(new Date(2026, 10, 25, 20))).toBe("Good evening");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });
});
