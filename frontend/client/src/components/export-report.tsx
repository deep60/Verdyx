import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Download, FileJson, FileText, Share2, Printer, Shield } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { AttackTechnique } from "@/lib/attack-mapping";
import { buildStixBundle } from "@/lib/stix";
import type { ApiAnalysis, ApiConsensus } from "@/lib/api-types";
import { engineFacts, engineRole, markdownReport, sortEngines } from "@/lib/report";

interface ExportReportProps {
  submissionId: string;
  target: string;
  targetType: string;
  submittedAt?: string;
  consensus?: ApiConsensus | null;
  analyses?: ApiAnalysis[];
  attackTechniques?: AttackTechnique[];
  sha256?: string;
  targetUrl?: string;
}

function download(content: string, type: string, name: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

const csvCell = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;

export function ExportReport({
  submissionId,
  target,
  targetType,
  submittedAt,
  consensus,
  analyses = [],
  attackTechniques = [],
  sha256,
  targetUrl,
}: ExportReportProps) {
  const { toast } = useToast();
  const fileName = target;
  const stamp = () => new Date().toISOString().replace(/[:.]/g, "-");

  const done = (what: string, icon = <FileText className="h-4 w-4 flex-shrink-0 text-success" />) =>
    toast({
      title: "Exported",
      description: (
        <div className="flex items-center gap-2">
          {icon}
          <span>{what}</span>
        </div>
      ),
    });
  const failed = (what: string) =>
    toast({ title: "Export failed", description: `Couldn't export ${what}`, variant: "destructive" });

  const exportAsJSON = () => {
    try {
      const report = {
        scanId: submissionId,
        target,
        targetType,
        sha256: sha256 ?? null,
        submittedAt: submittedAt ?? null,
        exportedAt: new Date().toISOString(),
        consensus: consensus ?? null,
        engines: sortEngines(analyses).map((a) => ({
          name: a.engine?.name,
          version: a.engine?.version,
          result: engineRole(a).label,
          verdict: a.verdict,
          confidence: a.confidence ?? null,
          vote: a.vote ?? null,
          reason: a.reason ?? null,
          processingTimeMs: a.processingTimeMs ?? null,
          evidence: a.metadata ?? {},
          completedAt: a.completedAt,
        })),
      };
      download(JSON.stringify(report, null, 2), "application/json", `verdyx-scan-${submissionId}-${stamp()}.json`);
      done("Report exported as JSON", <FileJson className="h-4 w-4 flex-shrink-0 text-success" />);
    } catch {
      failed("JSON");
    }
  };

  const exportAsMarkdown = () => {
    try {
      const md = markdownReport({ submissionId, target, targetType, sha256, submittedAt, consensus, analyses });
      download(md, "text/markdown", `verdyx-scan-${submissionId}-${stamp()}.md`);
      done("Report exported as Markdown");
    } catch {
      failed("Markdown");
    }
  };

  const exportAsCSV = () => {
    try {
      const rows = [["Engine", "Version", "Result", "Confidence %", "Time ms", "Evidence"].map(csvCell).join(",")];
      for (const a of sortEngines(analyses)) {
        rows.push(
          [
            a.engine?.name,
            a.engine?.version,
            engineRole(a).label,
            a.confidence ?? "",
            a.processingTimeMs ?? "",
            engineFacts(a)
              .map((f) => `${f.label}: ${f.value}`)
              .join("; "),
          ]
            .map(csvCell)
            .join(","),
        );
      }
      download(rows.join("\n") + "\n", "text/csv", `verdyx-engines-${submissionId}-${stamp()}.csv`);
      done("Engine results exported as CSV");
    } catch {
      failed("CSV");
    }
  };

  const exportStix = () => {
    try {
      const verdict = typeof consensus?.finalVerdict === "string" ? consensus.finalVerdict : undefined;
      const bundle = buildStixBundle({
        submissionId,
        fileName,
        sha256,
        targetUrl,
        verdict,
        techniques: attackTechniques,
      });
      const dataBlob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `verdyx-stix-${submissionId}-${Date.now()}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      toast({
        title: "STIX 2.1 exported",
        description: attackTechniques.length
          ? `Bundle includes ${attackTechniques.length} ATT&CK techniques from this scan.`
          : "Bundle includes the indicator. No ATT&CK technique was supported by this scan.",
      });
    } catch {
      toast({
        title: "Export Failed",
        description: "Failed to export STIX 2.1 JSON",
        variant: "destructive",
      });
    }
  };

  const copyShareLink = () => {
    const shareUrl = `${window.location.origin}/analysis/${submissionId}`;
    navigator.clipboard.writeText(shareUrl).then(() => {
      toast({
        title: "Link Copied!",
        description: (
          <div className="flex items-center gap-2">
            <Share2 className="h-4 w-4 text-success flex-shrink-0" />
            <span>Share link copied to clipboard</span>
          </div>
        ),
      });
    }).catch(() => {
      toast({
        title: "Copy Failed",
        description: "Failed to copy share link",
        variant: "destructive",
      });
    });
  };

  const printReport = () => {
    window.print();
    toast({
      title: "Print Dialog Opened",
      description: (
        <div className="flex items-center gap-2">
          <Printer className="h-4 w-4 text-primary flex-shrink-0" />
          <span>Print dialog has been opened</span>
        </div>
      ),
    });
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" className="gap-2">
          <Download className="h-4 w-4" />
          Export Report
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>Export Options</DropdownMenuLabel>
        <DropdownMenuSeparator />

        <DropdownMenuItem onClick={exportAsJSON} className="gap-2">
          <FileJson className="h-4 w-4" />
          <span>Export as JSON</span>
        </DropdownMenuItem>

        <DropdownMenuItem onClick={exportStix} className="gap-2">
          <Shield className="h-4 w-4" />
          <span>Export STIX 2.1</span>
        </DropdownMenuItem>

        <DropdownMenuItem onClick={exportAsMarkdown} className="gap-2">
          <FileText className="h-4 w-4" />
          <span>Export as Markdown</span>
        </DropdownMenuItem>

        <DropdownMenuItem onClick={exportAsCSV} className="gap-2">
          <FileText className="h-4 w-4" />
          <span>Export Analysis (CSV)</span>
        </DropdownMenuItem>

        <DropdownMenuSeparator />

        <DropdownMenuItem onClick={copyShareLink} className="gap-2">
          <Share2 className="h-4 w-4" />
          <span>Copy Share Link</span>
        </DropdownMenuItem>

        <DropdownMenuItem onClick={printReport} className="gap-2">
          <Printer className="h-4 w-4" />
          <span>Print Report</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
