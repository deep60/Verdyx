import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { CloudUpload, Rocket } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";

export function FileSubmissionForm() {
  const [file, setFile] = useState<File | null>(null);
  const [analysisType, setAnalysisType] = useState("full");
  const [bountyAmount, setBountyAmount] = useState("0.1");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  const { toast } = useToast();
  const queryClient = useQueryClient();

  const submitMutation = useMutation({
    mutationFn: async (body: FormData) => {
      const headers: Record<string, string> = {};
      const token = localStorage.getItem("token");
      if (token) headers.Authorization = `Bearer ${token}`;
      const response = await fetch("/api/submissions/file", {
        method: "POST",
        headers,
        body,
        credentials: "include",
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || response.statusText);
      }
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "File submitted for analysis",
        description: `Analysis ID: ${data.id}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/submissions"] });
      // Reset form
      setFile(null);
      setDescription("");
      setBountyAmount("0.1");
      setPriority(false);
    },
    onError: () => {
      toast({
        title: "Submission failed",
        description: "Please try again",
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
    if (!file) {
      toast({
        title: "No file selected",
        description: "Please select a file to analyze",
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
    body.append("file", file);
    body.append("analysisType", analysisType);
    body.append("bountyAmount", priority ? (parsedBounty + 0.05).toString() : parsedBounty.toString());
    body.append("priority", String(priority));
    if (description) body.append("description", description);
    submitMutation.mutate(body);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="text-center">
        <label
          htmlFor="file-upload"
          className="cursor-pointer block rounded-xl border border-dashed border-border p-6 transition-colors hover:border-primary/50"
          data-testid="label-file-upload"
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
        >
          <div className={`w-20 h-20 mx-auto rounded-full flex items-center justify-center mb-4 transition-colors ${isDragging ? "bg-primary/30 ring-2 ring-primary" : "bg-primary/10"}`}>
            <CloudUpload className="w-7 h-7 text-primary" />
          </div>
          <p className="font-semibold">Drop files here or click to browse</p>
          <p className="text-xs text-muted-foreground mt-1">EXE, DLL, APK, URL, ZIP · Max 100MB</p>
        </label>
        <input
          id="file-upload"
          type="file"
          className="hidden"
          onChange={handleFileChange}
          accept=".exe,.dll,.apk,.zip,.pdf,.doc,.docx"
          data-testid="input-file"
        />
        {file && (
          <p className="text-sm text-primary mt-2 truncate" data-testid="text-filename">
            Selected: {file.name} ({file.size} bytes)
          </p>
        )}
      </div>

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
          placeholder="Describe where you found this file or why it's suspicious..."
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
