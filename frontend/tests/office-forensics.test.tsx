import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  OFFICE_ENGINE_NAME,
  OfficeForensicsPanel,
  hasOfficeAnalysis,
} from "@/components/office-forensics-panel";
import type { ApiAnalysis } from "@/lib/api-types";

// Shaped like the analysis engine's Office Document Analyzer metadata.
const dropper: ApiAnalysis = {
  id: "a1",
  engine: { name: OFFICE_ENGINE_NAME },
  verdict: "malicious",
  metadata: {
    format: "ooxml",
    encrypted: false,
    summary: "macro runs when the document opens and downloads or launches code",
    macroModules: [
      {
        project: "word/vbaProject.bin:/VBA",
        module: "ThisDocument",
        lines: 6,
        bytes: 180,
        preview: 'Sub AutoOpen()\r\n  Shell "<script>p.exe"\r\nEnd Sub',
      },
    ],
    indicators: [
      { kind: "autoexec", keyword: "AutoOpen", description: "runs when a Word document opens" },
      { kind: "download", keyword: "XMLHTTP", description: "HTTP requests" },
    ],
    iocs: ["http://203.0.113.9/p.exe"],
    externalLinks: [
      {
        part: "word/_rels/settings.xml.rels",
        relationship: "attachedTemplate",
        target: "http://203.0.113.9/t.dotm",
        dangerous: true,
        reason: "loads a remote template or object when the document opens",
      },
    ],
    dde: [],
    excel4Macros: { macro_sheets: [], hidden_sheets: [], auto_open: false, dangerous_functions: [] },
    embeddedObjects: [],
  },
};

describe("OfficeForensicsPanel", () => {
  it("only applies when the Office analyzer reported", () => {
    expect(hasOfficeAnalysis([dropper])).toBe(true);
    expect(hasOfficeAnalysis([{ id: "b", engine: { name: "YARA" } }])).toBe(false);
  });

  it("shows behaviour, links, indicators and the macro source as text", () => {
    const html = renderToStaticMarkup(<OfficeForensicsPanel analyses={[dropper]} />);
    expect(html).toContain("Office Open XML");
    expect(html).toContain("1 macro module(s)");
    expect(html).toContain("Runs automatically");
    expect(html).toContain("Downloads");
    expect(html).toContain("http://203.0.113.9/t.dotm");
    expect(html).toContain("http://203.0.113.9/p.exe");
    expect(html).toContain("ThisDocument");
    // Macro source is escaped text, never markup.
    expect(html).toContain("&lt;script&gt;p.exe");
    expect(html).not.toContain("<script>");
  });

  it("copes with missing metadata", () => {
    const html = renderToStaticMarkup(
      <OfficeForensicsPanel analyses={[{ id: "c", engine: { name: OFFICE_ENGINE_NAME } }]} />,
    );
    expect(html).toContain("0 macro module(s)");
    expect(html).toContain("No risky macro behaviour found.");
  });
});
