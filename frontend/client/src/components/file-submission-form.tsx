import { useLocation } from "wouter";
import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, ChevronDown, CloudUpload, FileText, Globe, Loader2, Mail, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/auth-context";
import { canScan, type TeamSummary } from "@/lib/teams";
import { cn } from "@/lib/utils";
import type { ApiEngine } from "@/lib/api-types";
import {
  ANALYSIS_TYPES,
  URL_CHECKS,
  type AnalysisType,
  detectInput,
  engineState,
  enginesFor,
  formatBytes,
  normalizeUrl,
} from "@/lib/dashboard";

type Mode = "file" | "url" | "email";

const MODES: { value: Mode; label: string; icon: typeof Globe }[] = [
  { value: "file", label: "File", icon: CloudUpload },
  { value: "url", label: "URL", icon: Globe },
  { value: "email", label: "Email", icon: Mail },
];

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

/** Engine chips shown before "more engines". */
const CHIP_LIMIT = 5;

const STATE_DOT = {
  online: "bg-success",
  advisory: "bg-warning",
  off: "bg-muted-foreground/50",
} as const;

function Chip({ children, dot, title }: { children: React.ReactNode; dot?: string; title?: string }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded border border-border bg-background/40 px-2 py-1 text-[11px] text-muted-foreground"
      title={title}
    >
      {dot && <span className={cn("h-1.5 w-1.5 rounded-full", dot)} aria-hidden />}
      {children}
    </span>
  );
}

/** The scan box on the dashboard: one file, link or email, and how hard to look at it. */
export function FileSubmissionForm() {
  const [mode, setMode] = useState<Mode>("file");
  const [file, setFile] = useState<File | null>(null);
  const [emailSource, setEmailSource] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [analysisType, setAnalysisType] = useState<AnalysisType>("full");
  const [description, setDescription] = useState("");
  const [showNote, setShowNote] = useState(false);
  const [priority, setPriority] = useState(false);
  const [saveTo, setSaveTo] = useState("personal");
  const [isDragging, setIsDragging] = useState(false);
  const [showAllEngines, setShowAllEngines] = useState(false);
  const emlInput = useRef<HTMLInputElement>(null);

  const { isAuthenticated } = useAuth();
  const { data: teams = [] } = useQuery<TeamSummary[]>({ queryKey: ["/api/orgs"], enabled: isAuthenticated });
  const scanTeams = teams.filter((t) => canScan(t.role));
  const { data: engines = [] } = useQuery<ApiEngine[]>({ queryKey: ["/api/engines"], staleTime: 60_000 });

  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();

  const submitMutation = useMutation({
    mutationFn: async (body: FormData) => {
      let response: Response;
      try {
        response = await fetch("/api/submissions/file", { method: "POST", body, credentials: "include" });
      } catch {
        throw new Error("Verdyx is temporarily unavailable, so this was not analyzed. Please try again.");
      }
      if (response.status === 429) {
        const data = await response.json().catch(() => null);
        throw new Error(
          typeof data?.message === "string" ? data.message : "You've reached the scan limit for now. Please wait and try again.",
        );
      }
      if (!response.ok) {
        throw new Error(
          response.status >= 500
            ? "Verdyx is temporarily unavailable, so this was not analyzed. Please try again."
            : `Submission rejected (${response.status}). Please check it and try again.`,
        );
      }
      return (await response.json()) as { id?: string };
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/analysis/stats"] });
      setFile(null);
      setEmailSource("");
      setTargetUrl("");
      setDescription("");
      setPriority(false);
      if (data?.id) setLocation(`/analysis/${data.id}`);
      else toast({ title: "Submitted for analysis" });
    },
    onError: (err) => {
      toast({
        title: "Submission failed",
        description: err instanceof Error ? err.message : "Please try again",
        variant: "destructive",
      });
    },
  });

  const pastedKind = detectInput(targetUrl);
  const tooBig = file !== null && file.size > MAX_UPLOAD_BYTES;
  const ready =
    mode === "file"
      ? file !== null && !tooBig
      : mode === "url"
        ? pastedKind === "url"
        : file !== null || emailSource.trim().length >= 20;

  const chooseFile = (next: File | undefined | null) => setFile(next ?? null);

  const switchMode = (next: Mode) => {
    if (next !== mode) setFile(null);
    setMode(next);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready || submitMutation.isPending) return;
    const body = new FormData();
    if (mode === "file" && file) {
      body.append("file", file);
    } else if (mode === "email") {
      body.append("file", file ?? new File([emailSource.trim()], "message.eml", { type: "message/rfc822" }));
      body.append("submissionType", "email");
    } else {
      body.append("url", normalizeUrl(targetUrl));
    }
    body.append("analysisType", analysisType);
    body.append("priority", String(priority));
    if (description.trim()) body.append("description", description.trim());
    if (saveTo !== "personal" && scanTeams.some((t) => t.id === saveTo)) body.append("organizationId", saveTo);
    submitMutation.mutate(body);
  };

  const type = ANALYSIS_TYPES.find((t) => t.value === analysisType) ?? ANALYSIS_TYPES[1];
  const voting = enginesFor(analysisType, engines);
  const submitLabel = mode === "file" ? "Scan file" : mode === "url" ? "Scan URL" : "Scan email";

  return (
    <form
      onSubmit={handleSubmit}
      onKeyDown={(e) => {
        if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) handleSubmit(e);
      }}
      className="space-y-5"
      data-testid="scan-composer"
    >
      {/* What to scan */}
      <div className="inline-flex rounded-md border border-border bg-background/40 p-0.5" role="tablist" aria-label="What to scan">
        {MODES.map(({ value, label, icon: Icon }) => (
          <button
            key={value}
            type="button"
            role="tab"
            aria-selected={mode === value}
            onClick={() => switchMode(value)}
            data-testid={`tab-submit-${value}`}
            className={cn(
              "inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-sm transition-colors",
              mode === value ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="h-3.5 w-3.5" aria-hidden />
            {label}
          </button>
        ))}
      </div>

      {mode === "file" &&
        (file ? (
          <div className="flex items-center gap-3 rounded-lg border border-border bg-background/40 p-4" data-testid="text-filename">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-border bg-foreground/[0.04]">
              <FileText className="h-4 w-4" aria-hidden />
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium" title={file.name}>
                {file.name}
              </p>
              <p className={cn("text-xs", tooBig ? "text-destructive" : "text-muted-foreground")}>
                {formatBytes(file.size)}
                {tooBig && " · over the 100 MB limit"}
              </p>
            </div>
            <Button type="button" variant="ghost" size="icon" onClick={() => setFile(null)} aria-label="Remove file">
              <X className="h-4 w-4" />
            </Button>
          </div>
        ) : (
          <label
            htmlFor="file-upload"
            className={cn(
              "group flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed px-6 py-10 text-center transition-colors",
              isDragging ? "border-foreground bg-foreground/[0.06]" : "border-border hover:border-foreground/50 hover:bg-foreground/[0.02]",
            )}
            data-testid="label-file-upload"
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setIsDragging(false);
              chooseFile(e.dataTransfer.files?.[0]);
            }}
          >
            <span className="flex h-11 w-11 items-center justify-center rounded-full border border-border transition-transform group-hover:-translate-y-0.5">
              <CloudUpload className="h-5 w-5" aria-hidden />
            </span>
            <span className="mt-3 text-sm font-medium">Drop a file, or click to choose</span>
            <span className="mt-1 text-xs text-muted-foreground">Programs, documents, archives, scripts, APKs · up to 100 MB</span>
          </label>
        ))}

      <input
        id="file-upload"
        type="file"
        className="hidden"
        onChange={(e) => {
          chooseFile(e.target.files?.[0]);
          e.target.value = "";
        }}
        data-testid="input-file"
      />
      <input
        ref={emlInput}
        type="file"
        accept=".eml,.mime,message/rfc822"
        className="hidden"
        onChange={(e) => {
          chooseFile(e.target.files?.[0]);
          e.target.value = "";
        }}
        data-testid="input-eml"
      />

      {mode === "url" && (
        <div className="space-y-2">
          <label className="sr-only" htmlFor="url-input">
            URL to scan
          </label>
          <div className="relative">
            <Globe className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <Input
              id="url-input"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder="paypa1-secure-login.com/verify"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="h-12 pl-9 font-mono text-sm"
              data-testid="input-url"
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {pastedKind === "hash"
              ? "That looks like a file hash. Search it with ⌘K to open an earlier scan."
              : targetUrl.trim() && pastedKind !== "url"
                ? "Enter a web address, like example.com/login."
                : "Redirects are followed and every page on the way is checked."}
          </p>
        </div>
      )}

      {mode === "email" && (
        <div className="space-y-2">
          <label className="sr-only" htmlFor="email-source">
            Raw email, with headers
          </label>
          {file ? (
            <div className="flex items-center gap-3 rounded-lg border border-border bg-background/40 p-4">
              <Mail className="h-4 w-4 shrink-0" aria-hidden />
              <p className="min-w-0 flex-1 truncate text-sm">{file.name}</p>
              <Button type="button" variant="ghost" size="icon" onClick={() => setFile(null)} aria-label="Remove email file">
                <X className="h-4 w-4" />
              </Button>
            </div>
          ) : (
            <Textarea
              id="email-source"
              rows={7}
              className="resize-none font-mono text-xs"
              placeholder={"Paste the full message, headers included.\n\nFrom: billing@paypa1.com\nSubject: Your account is locked\n…"}
              value={emailSource}
              onChange={(e) => setEmailSource(e.target.value)}
              data-testid="textarea-email-source"
            />
          )}
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
            <span>Checks SPF, DKIM and DMARC, forged senders, pressure language, links and attachments.</span>
            {!file && (
              <button
                type="button"
                className="underline underline-offset-4 hover:text-foreground"
                onClick={() => emlInput.current?.click()}
              >
                Upload a .eml instead
              </button>
            )}
          </div>
        </div>
      )}

      {/* How hard to look */}
      {mode !== "url" ? (
        <fieldset className="space-y-3">
          <legend className="mb-2 text-xs font-medium uppercase tracking-[0.14em] text-muted-foreground">Depth</legend>
          <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4" role="radiogroup" data-testid="select-analysis-type">
            {ANALYSIS_TYPES.map((t) => (
              <button
                key={t.value}
                type="button"
                role="radio"
                aria-checked={analysisType === t.value}
                onClick={() => setAnalysisType(t.value)}
                className={cn(
                  "rounded-md border px-3 py-2 text-left transition-colors",
                  analysisType === t.value
                    ? "border-foreground bg-foreground/[0.07]"
                    : "border-border text-muted-foreground hover:border-foreground/40 hover:text-foreground",
                )}
              >
                <span className="block text-sm font-medium">{t.label}</span>
                <span className="block text-[11px] text-muted-foreground">{t.time}</span>
              </button>
            ))}
          </div>
          <p className="text-xs text-muted-foreground" data-testid="analysis-type-description">
            {type.description}
          </p>
          <div className="flex flex-wrap gap-1.5" aria-label="Engines that will vote" data-testid="engine-chips">
            {(showAllEngines ? voting : voting.slice(0, CHIP_LIMIT)).map((e) => (
              <Chip key={e.id} dot={STATE_DOT[engineState(e)]} title={`${e.name}: ${e.status ?? "unknown"}`}>
                {e.name}
              </Chip>
            ))}
            {voting.length > CHIP_LIMIT && (
              <button
                type="button"
                onClick={() => setShowAllEngines((v) => !v)}
                className="rounded border border-dashed border-border px-2 py-1 text-[11px] text-muted-foreground hover:text-foreground"
              >
                {showAllEngines ? "Show fewer" : `${voting.length - CHIP_LIMIT} more engines`}
              </button>
            )}
            {type.extras.map((x) => (
              <Chip key={x}>+ {x}</Chip>
            ))}
          </div>
          {analysisType === "behavioral" && (
            <p className="flex gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs text-warning" data-testid="behavioral-notice">
              <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
              If VirusTotal hasn't seen this file, it's uploaded there to run, and VirusTotal's users can then download it.
              Don't use this for private documents.
            </p>
          )}
        </fieldset>
      ) : (
        <div className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-[0.14em] text-muted-foreground">Checks</p>
          <div className="flex flex-wrap gap-1.5" data-testid="engine-chips">
            {URL_CHECKS.map((c) => (
              <Chip key={c}>{c}</Chip>
            ))}
          </div>
        </div>
      )}

      {/* Options */}
      <div className="flex flex-col gap-3 border-t border-border pt-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-3">
          <label className="flex items-center gap-2 text-sm" htmlFor="priority">
            <Switch id="priority" checked={priority} onCheckedChange={setPriority} data-testid="checkbox-priority" />
            Jump the queue
          </label>
          {scanTeams.length > 0 && (
            <Select value={saveTo} onValueChange={setSaveTo}>
              <SelectTrigger className="h-8 w-auto gap-2 text-xs" data-testid="select-save-to" aria-label="Who can see this scan">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="personal">Only me</SelectItem>
                {scanTeams.map((t) => (
                  <SelectItem key={t.id} value={t.id}>
                    Team: {t.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          <button
            type="button"
            onClick={() => setShowNote((v) => !v)}
            aria-expanded={showNote}
            className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            Add a note
            <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", showNote && "rotate-180")} aria-hidden />
          </button>
        </div>

        <Button type="submit" disabled={!ready || submitMutation.isPending} className="gap-2 sm:min-w-36" data-testid="button-submit-analysis">
          {submitMutation.isPending ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              Uploading
            </>
          ) : (
            <>
              {submitLabel}
              <ArrowRight className="h-4 w-4" aria-hidden />
            </>
          )}
        </Button>
      </div>

      {showNote && (
        <Textarea
          rows={2}
          placeholder="Where did this come from? The note is saved with the scan."
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="resize-none text-sm"
          data-testid="textarea-description"
        />
      )}
    </form>
  );
}
