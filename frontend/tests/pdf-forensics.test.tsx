import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { PDF_ENGINE_NAME, PdfForensicsPanel, hasPdfAnalysis, triggerLabel } from "@/components/pdf-forensics-panel";
import type { ApiAnalysis } from "@/lib/api-types";

// Shaped like the analysis engine's PDF Analyzer metadata.
const dropper: ApiAnalysis = {
  id: "p1",
  engine: { name: PDF_ENGINE_NAME },
  verdict: "malicious",
  metadata: {
    summary: "obfuscated JavaScript runs when the document opens",
    pdfStructure: {
      version: "1.7",
      headerOffset: 0,
      objects: 9,
      objectStreams: 1,
      pages: 1,
      incrementalUpdates: 0,
      trailingBytes: 0,
      encrypted: false,
      polyglot: null,
    },
    pdfKeywords: { JS: 1, JavaScript: 1, OpenAction: 1, ObjStm: 1 },
    hexEscapedNames: ["JavaScript"],
    autoActions: [{ trigger: "OpenAction", action: "JavaScript", target: null }],
    scripts: [{ object: "9 0", automatic: true, bytes: 64, preview: "eval(unescape('<img src=x onerror=alert(1)>'))" }],
    launchActions: [
      { object: "4 0", target: "cmd.exe", parameters: "/c powershell -enc AAAA", automatic: true, runsCommand: true },
    ],
    embeddedFiles: [{ name: "invoice.exe", bytes: 2048, kind: "a Windows program", executable: true }],
    uris: ["https://example.com/login"],
    uncPaths: ["\\\\203.0.113.5\\share\\x.pdf"],
    indicators: [
      { kind: "autorun", keyword: "JavaScript", description: "JavaScript runs when the document opens" },
      { kind: "obfuscation", keyword: "eval(", description: "eval: runs code built at run time" },
    ],
    iocs: ["https://example.com/login"],
  },
};

describe("PDF forensics panel", () => {
  it("finds the PDF engine's row", () => {
    expect(hasPdfAnalysis([dropper])).toBe(true);
    expect(hasPdfAnalysis([{ ...dropper, engine: { name: "Static Analyzer" } }])).toBe(false);
  });

  it("explains triggers in words", () => {
    expect(triggerLabel("OpenAction")).toBe("when the document opens");
    expect(triggerLabel("AA")).toBe("when a page opens");
  });

  it("shows structure, findings, actions, scripts, files and links", () => {
    const html = renderToStaticMarkup(<PdfForensicsPanel analyses={[dropper]} />);
    expect(html).toContain("PDF 1.7");
    expect(html).toContain("1 compressed object stream(s)");
    expect(html).toContain("obfuscated JavaScript runs when the document opens");
    expect(html).toContain("Runs on open");
    expect(html).toContain("cmd.exe /c powershell -enc AAAA");
    expect(html).toContain("invoice.exe");
    expect(html).toContain("network share");
    expect(html).toContain("/JavaScript");
    expect(html).toContain("/OpenAction ×1");
  });

  it("shows script text escaped, never as markup", () => {
    const html = renderToStaticMarkup(<PdfForensicsPanel analyses={[dropper]} />);
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("waits when the engine hasn't reported", () => {
    expect(renderToStaticMarkup(<PdfForensicsPanel analyses={[]} />)).toContain("Waiting for the PDF analyzer");
  });

  it("copes with missing fields", () => {
    const html = renderToStaticMarkup(
      <PdfForensicsPanel analyses={[{ id: "p2", engine: { name: PDF_ENGINE_NAME }, verdict: "benign", metadata: {} }]} />,
    );
    expect(html).toContain("Nothing risky found.");
    expect(html).toContain("Nothing runs on its own");
  });
});
