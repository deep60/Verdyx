import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { APK_ENGINE_NAME, ApkForensicsPanel, hasApkAnalysis } from "@/components/apk-forensics-panel";
import type { ApiAnalysis } from "@/lib/api-types";

// Shaped like the analysis engine's Android App Analyzer metadata.
const banker: ApiAnalysis = {
  id: "a1",
  engine: { name: APK_ENGINE_NAME },
  verdict: "malicious",
  metadata: {
    summary: "banking-trojan pattern: accessibility control, screen overlays or notification access, and SMS",
    riskScore: 7,
    package: "com.example.app",
    versionName: "1.2",
    minSdk: 24,
    targetSdk: 34,
    permissions: ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"],
    indicators: [
      {
        kind: "accessibility",
        evidence: ".Acc",
        description: "accessibility service: can read the screen and act for the user",
      },
    ],
    apis: [{ kind: "accessibility_abuse", evidence: "performGlobalAction", description: "presses Back/Home/Recents" }],
    components: [
      {
        kind: "service",
        name: ".Acc",
        permission: "android.permission.BIND_ACCESSIBILITY_SERVICE",
        actions: ["android.accessibilityservice.AccessibilityService"],
      },
    ],
    packers: [],
    embeddedPayloads: ["assets/x.apk (packaged app or code)"],
    nativeAbis: [],
    nativeLibraries: [],
    signing: { v1: true, v2_plus: false, debug_certificate: false },
    iocs: ["http://203.0.113.7:8080/gate.php"],
  },
};

describe("ApkForensicsPanel", () => {
  it("only applies when the Android analyzer reported", () => {
    expect(hasApkAnalysis([banker])).toBe(true);
    expect(hasApkAnalysis([{ id: "b", engine: { name: "YARA" } }])).toBe(false);
  });

  it("shows the app, its abilities, permissions and addresses", () => {
    const html = renderToStaticMarkup(<ApkForensicsPanel analyses={[banker]} />);
    expect(html).toContain("com.example.app");
    expect(html).toContain("SDK 24–34");
    expect(html).toContain("Signed (v1)");
    expect(html).toContain("RECEIVE_SMS");
    expect(html).toContain("1 sensitive");
    expect(html).toContain("performGlobalAction");
    expect(html).toContain("assets/x.apk");
    expect(html).toContain("BIND_ACCESSIBILITY_SERVICE");
    expect(html).toContain("http://203.0.113.7:8080/gate.php");
  });

  it("copes with missing metadata", () => {
    const html = renderToStaticMarkup(
      <ApkForensicsPanel analyses={[{ id: "c", engine: { name: APK_ENGINE_NAME } }]} />,
    );
    expect(html).toContain("Unsigned");
    expect(html).toContain("No risky abilities found.");
  });
});
