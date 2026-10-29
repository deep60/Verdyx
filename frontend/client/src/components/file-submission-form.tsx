import { useLocation } from "wouter";
import { createAutonomousLocalSubmission } from "@/lib/local-analysis-engine";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { CloudUpload, Globe, Mail, Rocket } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";

export function FileSubmissionForm() {
  const [submissionMode, setSubmissionMode] = useState<"file" | "url" | "email">("file");
  const [file, setFile] = useState<File | null>(null);
  const [emailSource, setEmailSource] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [analysisType, setAnalysisType] = useState("full");
  const [bountyAmount, setBountyAmount] = useState("0.1");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();

  const submitMutation = useMutation({
    mutationFn: async (body: FormData) => {
      try {
        const headers: Record<string, string> = {};
        const token = localStorage.getItem("token");
        if (token) headers.Authorization = `Bearer ${token}`;
        const response = await fetch("/api/submissions/file", {
          method: "POST",
          headers,
          body,
          credentials: "include",
        });
        if (response.ok) {
          return await response.json();
        }
      } catch {
        // Fall back to autonomous local 8-engine execution below
      }
      const bundle = await createAutonomousLocalSubmission({
        submissionMode,
        file,
        targetUrl,
        emailSource,
        analysisType,
        bountyAmount,
        priority,
        description,
      });
      return bundle.submission;
    },
    onSuccess: (data) => {
      toast({
        title:
          submissionMode === "url"
            ? "URL analyzed across 8 engines & 36+ OSINT modules"
            : submissionMode === "email"
              ? "Email analyzed for SPF/DKIM/DMARC & phishing"
              : "File analyzed across 8 security engines",
        description: `Opening report: ${data.id}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/analysis/stats"] });
      setFile(null);
      setEmailSource("");
      setTargetUrl("");
      setDescription("");
      setBountyAmount("0.1");
      setPriority(false);
      if (data?.id) {
        setLocation(`/analysis/${data.id}`);
      }
    },
    onError: (err) => {
      toast({
        title: "Submission failed",
        description: err instanceof Error ? err.message : "Please try again",
        variant: "destructive",
      });
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFile(e.target.files?.[0] ?? null);
  };

  const selectFile = (next: File | undefined) => {
    setFile(next ?? null);
  };

  const handleDrop = (e: React.DragEvent<HTMLLabelElement>) => {
    e.preventDefault();
    setIsDragging(false);
    selectFile(e.dataTransfer.files?.[0]);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (submissionMode === "file" && !file) {
      toast({
        title: "No file selected",
        description: "Please select a file to analyze",
        variant: "destructive",
      });
      return;
    }

    if (submissionMode === "url" && !targetUrl.trim()) {
      toast({
        title: "No URL entered",
        description: "Please enter a valid URL to analyze",
        variant: "destructive",
      });
      return;
    }

    if (submissionMode === "email" && !file && emailSource.trim().length < 20) {
      toast({
        title: "No email provided",
        description: "Paste the raw message, including headers, or upload a .eml file",
        variant: "destructive",
      });
      return;
    }

    const parsedBounty = parseFloat(bountyAmount);
    if (Number.isNaN(parsedBounty) || parsedBounty < 0) {
      toast({
        title: "Invalid bounty amount",
        description: "Please enter a valid, non-negative bounty amount",
        variant: "destructive",
      });
      return;
    }

    const body = new FormData();
    if (submissionMode === "file" && file) {
      body.append("file", file);
    } else if (submissionMode === "email") {
      const emailFile =
        file ??
        new File([emailSource.trim()], "message.eml", {
          type: "message/rfc822",
        });
      body.append("file", emailFile);
      body.append("submissionType", "email");
    } else if (submissionMode === "url") {
      body.append("url", targetUrl.trim());
    }
    body.append("analysisType", analysisType);
    body.append("bountyAmount", priority ? (parsedBounty + 0.05).toString() : parsedBounty.toString());
    body.append("priority", String(priority));
    if (description) body.append("description", description);
    submitMutation.mutate(body);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="grid grid-cols-3 gap-2 p-1 bg-muted/30 rounded-lg border border-border">
        <Button
          type="button"
          variant={submissionMode === "file" ? "default" : "ghost"}
          size="sm"
          onClick={() => setSubmissionMode("file")}
          data-testid="tab-submit-file"
        >
          <CloudUpload className="w-4 h-4 mr-2" />
          File
        </Button>
        <Button
          type="button"
          variant={submissionMode === "url" ? "default" : "ghost"}
          size="sm"
          onClick={() => setSubmissionMode("url")}
          data-testid="tab-submit-url"
        >
          <Globe className="w-4 h-4 mr-2" />
          URL
        </Button>
        <Button
          type="button"
          variant={submissionMode === "email" ? "default" : "ghost"}
          size="sm"
          onClick={() => setSubmissionMode("email")}
          data-testid="tab-submit-email"
        >
          <Mail className="w-4 h-4 mr-2" />
          Email
        </Button>
      </div>

      {submissionMode === "file" ? (
        <div className="text-center">
          <label
            htmlFor="file-upload"
            className="cursor-pointer block rounded-xl border border-dashed border-border p-6 transition-colors hover:border-primary/50"
            data-testid="label-file-upload"
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
          >
            <div
              className={`w-20 h-20 mx-auto rounded-full flex items-center justify-center mb-4 transition-colors ${
                isDragging ? "bg-primary/30 ring-2 ring-primary" : "bg-primary/10"
              }`}
            >
              <CloudUpload className="w-7 h-7 text-primary" />
            </div>
            <p className="font-semibold">Drop files here or click to browse</p>
            <p className="text-xs text-muted-foreground mt-1">EXE, DLL, APK, PDF, DOC, ZIP · Max 100MB</p>
          </label>
          <input
            id="file-upload"
            type="file"
            className="hidden"
            onChange={handleFileChange}
            accept=".exe,.dll,.apk,.zip,.pdf,.doc,.docx,.bin,.elf,.py,.js,.sh"
            data-testid="input-file"
          />
          {file && (
            <p className="text-sm text-primary mt-2 truncate" data-testid="text-filename">
              Selected: {file.name} ({file.size} bytes)
            </p>
          )}
        </div>
      ) : submissionMode === "email" ? (
        <div className="space-y-3">
          <label className="block text-sm font-medium" htmlFor="email-source">
            Raw email (headers + body)
          </label>
          <Textarea
            id="email-source"
            rows={8}
            className="font-mono text-xs"
            placeholder={"Received: from mail.example\nFrom: billing@paypa1.com\nSubject: Your account is locked\n\nPaste the full message, or upload a .eml below."}
            value={emailSource}
            onChange={(e) => setEmailSource(e.target.value)}
            data-testid="textarea-email-source"
          />
          <label className="block text-sm font-medium" htmlFor="eml-upload">
            Or upload a .eml file
          </label>
          <Input
            id="eml-upload"
            type="file"
            accept=".eml,.mime,message/rfc822"
            onChange={handleFileChange}
            data-testid="input-eml"
          />
          <p className="text-xs text-muted-foreground">
            The email scanner checks SPF, DKIM, and DMARC alignment, forged From headers, urgency language, and suspicious attachments.
          </p>
        </div>
      ) : (
        <div>
          <label className="block text-sm font-medium mb-2" htmlFor="url-input">
            Suspicious URL
          </label>
          <Input
            id="url-input"
            type="url"
            placeholder="https://example-phishing-domain.com/login"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            data-testid="input-url"
          />
          <p className="text-xs text-muted-foreground mt-1">
            Enter a full HTTP or HTTPS URL to scan for phishing, malware payloads, or C2 indicators.
          </p>
        </div>
      )}

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-2">Analysis Type</label>
          <Select value={analysisType} onValueChange={setAnalysisType}>
            <SelectTrigger data-testid="select-analysis-type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="full">Full Analysis</SelectItem>
              <SelectItem value="quick">Quick Scan</SelectItem>
              <SelectItem value="deep">Deep Inspection</SelectItem>
              <SelectItem value="behavioral">Behavioral Analysis</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="block text-sm font-medium mb-2">Bounty Amount (ETH)</label>
          <Input
            type="number"
            step="0.001"
            placeholder="0.1"
            value={bountyAmount}
            onChange={(e) => setBountyAmount(e.target.value)}
            data-testid="input-bounty-amount"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium mb-2">Description (Optional)</label>
        <Textarea
          rows={3}
          placeholder="Describe where you found this artifact or why it's suspicious..."
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="resize-none"
          data-testid="textarea-description"
        />
      </div>

      <div className="flex items-center space-x-3">
        <Checkbox
          id="priority"
          checked={priority}
          onCheckedChange={(checked) => setPriority(checked as boolean)}
          data-testid="checkbox-priority"
        />
        <label htmlFor="priority" className="text-sm">
          Priority Analysis (+0.05 ETH)
        </label>
      </div>

      <Button
        type="submit"
        className="w-full glow-effect"
        disabled={submitMutation.isPending}
        data-testid="button-submit-analysis"
      >
        <Rocket className="w-4 h-4 mr-2" />
        {submitMutation.isPending ? "Submitting..." : "Submit for Analysis"}
      </Button>
    </form>
  );
}
