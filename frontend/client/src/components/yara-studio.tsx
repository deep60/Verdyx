import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { runYaraSubset, type YaraRuleResult } from "@/lib/yara-subset";
import type { ApiSubmission } from "@/lib/api-types";
import { Binary, Download, Sparkles } from "lucide-react";

const RULE_PRESETS: Record<string, { label: string; rule: string }> = {
  injection: {
    label: "PE Process Injection",
    rule: `rule Suspicious_Process_Injection {
  strings:
    $remote = "CreateRemoteThread" nocase
    $alloc = "VirtualAllocEx" nocase
    $write = "WriteProcessMemory" nocase
    $hex = { 6A 40 ?? 68 }
  condition:
    any of them and filesize < 10MB
}`,
  },
  ransomware: {
    label: "Ransomware & Shadow Copy",
    rule: `rule Ransomware_ShadowCopy_Wipe {
  strings:
    $vss = "vssadmin delete shadows" nocase
    $wmic = "wmic shadowcopy delete" nocase
    $bcd = /bcdedit.*recoveryenabled.*no/i
    $ext = ".encrypted" nocase
  condition:
    any of them
}`,
  },
  phishing_eml: {
    label: "Phishing MIME / Credential Lure",
    rule: `rule Phishing_Urgent_Credential_Lure {
  strings:
    $verify = "verify your account" nocase
    $suspend = "suspended" nocase
    $urgent = /act now|24 hours|immediate action/i
    $spf_fail = "spf=fail" nocase
  condition:
    any of them
}`,
  },
  elf_loader: {
    label: "ELF Memory Loader",
    rule: `rule ELF_Reflective_Loader {
  strings:
    $memfd = "memfd_create"
    $ptrace = "ptrace"
    $sh = "/bin/sh"
  condition:
    uint32(0) == 0x464c457f or any of them
}`,
  },
};

const MAX_SAMPLE = 8 * 1024 * 1024;

export function YaraStudio() {
  const [rule, setRule] = useState(RULE_PRESETS.injection.rule);
  const [fileName, setFileName] = useState("");
  const [sample, setSample] = useState<Uint8Array | null>(null);
  const [selectedSubmissionId, setSelectedSubmissionId] = useState("");
  const [results, setResults] = useState<YaraRuleResult[] | null>(null);
  const [error, setError] = useState("");

  const { data: submissions = [] } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
  });

  const onFile = async (file: File | undefined) => {
    setResults(null);
    setError("");
    setSelectedSubmissionId("");
    if (!file) {
      setSample(null);
      setFileName("");
      return;
    }
    if (file.size > MAX_SAMPLE) {
      setSample(null);
      setFileName(file.name);
      setError("Sample is larger than 8 MB. Choose a smaller file.");
      return;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    setSample(bytes);
    setFileName(`${file.name} · ${bytes.length} bytes`);
  };

  const onSelectSubmission = async (subId: string) => {
    setSelectedSubmissionId(subId);
    setResults(null);
    setError("");
    if (!subId) {
      setSample(null);
      setFileName("");
      return;
    }
    const sub = submissions.find((s) => s.id === subId);
    if (!sub) return;
    try {
      const res = await fetch(`/api/submissions/${subId}/analyses`, { credentials: "include" });
      const analyses = res.ok ? await res.json() : [];
      // Build a synthetic inspection buffer from the submission metadata + extracted static strings/imports/IOCs
      const textCorpus = JSON.stringify({ submission: sub, analyses }, null, 2);
      const bytes = new TextEncoder().encode(textCorpus);
      setSample(bytes);
      const label = sub.originalFilename || sub.filename || sub.url || sub.id;
      setFileName(`${label} (Telemetry corpus · ${bytes.length} bytes)`);
    } catch {
      const fallback = new TextEncoder().encode(JSON.stringify(sub));
      setSample(fallback);
      setFileName(`${sub.originalFilename || sub.id} (${fallback.length} bytes)`);
    }
  };

  const run = () => {
    setError("");
    if (!sample) {
      setError("Upload a local sample or select a scanned submission before running the rule.");
      setResults(null);
      return;
    }
    try {
      setResults(runYaraSubset(rule, sample));
    } catch (err) {
      setResults(null);
      setError(err instanceof Error ? err.message : "Could not parse the rule");
    }
  };

  const exportRule = () => {
    const blob = new Blob([rule], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "verdyx-custom-rule.yar";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <Card className="bento-card">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 font-display">
              <Binary className="h-5 w-5 text-primary" />
              YARA Studio
            </CardTitle>
            <CardDescription className="mt-1">
              Supports ASCII/wide/nocase strings, hex wildcards (<span className="font-mono">??</span>), regex literals (<span className="font-mono">/pattern/i</span>), <span className="font-mono">filesize</span>, and PE/ELF magic (<span className="font-mono">uint16(0) == 0x5A4D</span>, <span className="font-mono">uint32(0) == 0x464c457f</span>).
            </CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {Object.entries(RULE_PRESETS).map(([key, preset]) => (
              <Button
                key={key}
                type="button"
                variant="outline"
                size="sm"
                className="text-xs h-8"
                onClick={() => {
                  setRule(preset.rule);
                  setResults(null);
                }}
              >
                <Sparkles className="h-3 w-3 mr-1 text-primary" />
                {preset.label}
              </Button>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-3">
          <Textarea
            value={rule}
            onChange={(event) => setRule(event.target.value)}
            className="min-h-[280px] font-mono text-xs"
            spellCheck={false}
          />
          <div className="grid gap-2 sm:grid-cols-2">
            <div>
              <span className="block text-[11px] text-muted-foreground mb-1">Upload local binary / file</span>
              <input
                type="file"
                className="w-full text-xs file:mr-2 file:rounded-md file:border file:border-border file:bg-background file:px-2.5 file:py-1"
                onChange={(event) => void onFile(event.target.files?.[0])}
              />
            </div>
            <div>
              <span className="block text-[11px] text-muted-foreground mb-1">Or test against scan history</span>
              <select
                className="w-full rounded-md border border-border bg-background px-2.5 py-1.5 text-xs"
                value={selectedSubmissionId}
                onChange={(e) => void onSelectSubmission(e.target.value)}
                data-testid="select-yara-submission"
              >
                <option value="">Select scanned artifact…</option>
                {submissions.map((sub) => (
                  <option key={sub.id} value={sub.id}>
                    {sub.originalFilename || sub.filename || sub.url || sub.id}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button type="button" onClick={run} data-testid="button-test-yara">
              Test rule
            </Button>
            <Button type="button" variant="outline" onClick={exportRule}>
              <Download className="h-3.5 w-3.5 mr-1.5" />
              Export .yar
            </Button>
          </div>
          {fileName && <p className="font-mono text-xs text-muted-foreground">{fileName}</p>}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <div className="space-y-3">
          {!results && !error && (
            <p className="text-sm text-muted-foreground">
              Matches show the exact byte offset (decimal and hex) and a 16-byte hex/ASCII dump from the target artifact.
            </p>
          )}
          {results?.map((result) => (
            <div key={result.rule} className="rounded-lg border border-border/70 p-3 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm font-semibold">{result.rule}</span>
                <Badge variant={result.error ? "destructive" : result.matched ? "default" : "outline"}>
                  {result.error ? "Error" : result.matched ? "Match" : "No match"}
                </Badge>
              </div>
              {result.error && <p className="text-xs text-destructive">{result.error}</p>}
              {result.matches.length === 0 && result.matched && (
                <p className="text-xs text-muted-foreground">Condition matched via header magic or filesize check.</p>
              )}
              <ul className="space-y-1">
                {result.matches.map((match, index) => (
                  <li key={`${match.stringId}-${match.offset}-${index}`} className="font-mono text-[11px] break-all">
                    <span className="text-primary">{match.stringId}</span>{" "}
                    <span className="text-muted-foreground">
                      @ {match.offset} (0x{match.offset.toString(16)})
                    </span>
                    <div className="text-muted-foreground">{match.preview}</div>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
