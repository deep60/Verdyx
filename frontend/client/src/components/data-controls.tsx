import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { serverMessage } from "@/lib/teams";
import { Database, Download, Trash2 } from "lucide-react";
import { BOUNTIES_ENABLED } from "@/lib/features";

export interface RetentionPolicy {
  scanRetentionDays: number | null;
  sampleRetentionDays: number | null;
  guestScanRetentionDays: number | null;
  choices: number[];
}

export const RETENTION_CHOICES = [30, 90, 180, 365];

/** "30 days", "1 year", or "Keep" for null. */
export function retentionLabel(days: number | null | undefined): string {
  if (!days) return "Keep until deleted";
  if (days === 365) return "Delete after 1 year";
  return `Delete after ${days} days`;
}

/** Select value <-> days (Radix selects need strings). */
export const toValue = (days: number | null | undefined) => (days ? String(days) : "keep");
export const fromValue = (v: string) => (v === "keep" ? null : Number(v));

export function RetentionSelect({
  value,
  onChange,
  disabled,
  label,
}: {
  value: number | null | undefined;
  onChange: (days: number | null) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <Select value={toValue(value)} onValueChange={(v) => onChange(fromValue(v))} disabled={disabled}>
      <SelectTrigger className="w-full sm:w-[240px]" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="keep">{retentionLabel(null)}</SelectItem>
        {RETENTION_CHOICES.map((d) => (
          <SelectItem key={d} value={String(d)}>
            {retentionLabel(d)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** One sentence on what Verdyx deletes by itself. */
export function policySentence(p?: Pick<RetentionPolicy, "sampleRetentionDays" | "guestScanRetentionDays">): string {
  const parts: string[] = [];
  if (p?.sampleRetentionDays) {
    parts.push(`Uploaded files are deleted ${p.sampleRetentionDays} days after a scan; its results stay.`);
  }
  if (p?.guestScanRetentionDays) {
    parts.push(`Scans made while signed out are deleted after ${p.guestScanRetentionDays} days.`);
  }
  if (BOUNTIES_ENABLED) parts.push("Scans that carry a bounty are kept.");
  return parts.join(" ");
}

const MINE = "/api/users/me/retention";

/** Profile → Data: retention choice and export. */
export function DataControls() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: policy } = useQuery<RetentionPolicy>({ queryKey: [MINE] });
  const save = useMutation({
    mutationFn: async (days: number | null) => (await apiRequest("PUT", MINE, { scanRetentionDays: days })).json(),
    onSuccess: (p: RetentionPolicy) => {
      queryClient.setQueryData([MINE], p);
      toast({ title: "Saved", description: retentionLabel(p.scanRetentionDays) + "." });
    },
    onError: (err) =>
      toast({ title: "Couldn't save", description: serverMessage(err, "Please try again."), variant: "destructive" }),
  });

  return (
    <div className="space-y-6" data-testid="data-controls">
      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" /> Keep my scans
          </CardTitle>
          <CardDescription>
            Choose how long your own scans are kept. Older ones, with their results, are deleted every day. Scans saved
            to a team follow the team&apos;s setting.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <RetentionSelect
            value={policy?.scanRetentionDays}
            onChange={(d) => save.mutate(d)}
            disabled={!policy || save.isPending}
            label="How long to keep my scans"
          />
          <p className="text-xs text-muted-foreground">{policySentence(policy)}</p>
        </CardContent>
      </Card>

      <Card className="glassmorphism">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5 text-primary" /> Download my data
          </CardTitle>
          <CardDescription>
            A JSON file with your account, every scan you made and its results, your API keys (without the keys),
            teams, webhooks and activity log. Uploaded files aren&apos;t included; their hashes are.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline">
            <a href="/api/users/me/export" download data-testid="link-export-data">
              <Download className="mr-1.5 h-4 w-4" /> Download
            </a>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

/** Deletes one scan after confirming. The server decides who may. */
export function DeleteScanButton({ submissionId, onDeleted }: { submissionId: string; onDeleted: () => void }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const remove = useMutation({
    mutationFn: async () => apiRequest("DELETE", `/api/submissions/${submissionId}`),
    onSuccess: () => {
      toast({ title: "Scan deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/submissions"] });
      onDeleted();
    },
    onError: (err) => {
      const msg = err instanceof Error ? err.message : "";
      toast({
        title: "Couldn't delete the scan",
        description: msg.startsWith("404")
          ? "Only the person who made it, or a team owner or admin, can delete it."
          : serverMessage(err, "Please try again."),
        variant: "destructive",
      });
    },
  });
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline" disabled={remove.isPending} data-testid="button-delete-scan">
          <Trash2 className="mr-1.5 h-4 w-4" /> Delete
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this scan?</AlertDialogTitle>
          <AlertDialogDescription>
            The scan, its results and its uploaded file are deleted for everyone who can see it. This can&apos;t be
            undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={() => remove.mutate()}>Delete scan</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
