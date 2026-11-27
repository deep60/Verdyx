import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { serverMessage } from "@/lib/teams";
import type { PrivacySettings as Settings } from "@/lib/privacy";

const DOCS = "https://github.com/deep60/Verdyx/blob/main/docs/privacy.md";
const KEY = ["/api/users/me/privacy"];

function Row({
  id,
  label,
  hint,
  checked,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-3">
      <div>
        <label htmlFor={id} className="text-sm text-foreground">
          {label}
        </label>
        <p className="text-xs text-muted-foreground">{hint}</p>
      </div>
      <Switch id={id} checked={checked} disabled={disabled} onCheckedChange={onChange} data-testid={id} />
    </div>
  );
}

/** Whether Behavioral analysis may upload files to VirusTotal, for you and your teams. */
export function PrivacySettings() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery<Settings>({ queryKey: KEY });

  const mine = useMutation({
    mutationFn: (next: boolean) => apiRequest("PUT", "/api/users/me/privacy", { shareFilesWithVirusTotal: next }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: KEY }),
    onError: (err) => toast({ title: "Couldn't save", description: serverMessage(err, "Please try again."), variant: "destructive" }),
  });
  const team = useMutation({
    mutationFn: ({ id, next }: { id: string; next: boolean }) =>
      apiRequest("PUT", `/api/orgs/${id}/privacy`, { shareFilesWithVirusTotal: next }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: KEY }),
    onError: (err) => toast({ title: "Couldn't save", description: serverMessage(err, "Please try again."), variant: "destructive" }),
  });

  return (
    <Card className="glassmorphism border-primary/20" data-testid="privacy-settings">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-primary" aria-hidden />
          Privacy
        </CardTitle>
        <CardDescription>
          Your files stay with Verdyx. Scans look files up elsewhere by hash only, unless you allow an upload below.
          Reports are private to you, or to the team they're saved to, until you share one by link.{" "}
          <a href={DOCS} target="_blank" rel="noreferrer" className="text-primary hover:underline">
            Where your files go
          </a>
        </CardDescription>
      </CardHeader>
      <CardContent className="divide-y divide-border">
        {isLoading || !data ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : (
          <>
            <Row
              id="privacy-share-mine"
              label="Let Behavioral analysis upload my files to VirusTotal"
              hint="Only when VirusTotal has no report for the file yet. VirusTotal shares uploaded files with its customers, so leave this off for anything confidential. Applies to scans you make from now on."
              checked={data.shareFilesWithVirusTotal}
              disabled={mine.isPending}
              onChange={(next) => mine.mutate(next)}
            />
            {data.teams.map((t) => (
              <Row
                key={t.id}
                id={`privacy-share-team-${t.id}`}
                label={`${t.name}: upload the team's files to VirusTotal`}
                hint={
                  t.canEdit
                    ? "For scans saved to this team. Team owners and admins can change it."
                    : "For scans saved to this team. Only its owners and admins can change it."
                }
                checked={t.shareFilesWithVirusTotal}
                disabled={!t.canEdit || team.isPending}
                onChange={(next) => team.mutate({ id: t.id, next })}
              />
            ))}
          </>
        )}
      </CardContent>
    </Card>
  );
}
