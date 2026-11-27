import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link2, Lock } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { serverMessage } from "@/lib/teams";
import { canChangeSharing, whereFileWent, whoCanSee, type ScanAccessInput } from "@/lib/privacy";

/**
 * Who can open this report, where its file went, and (for its owner) a
 * switch to share it by link.
 */
export function ScanAccess({
  submissionId,
  scan,
  userId,
}: {
  submissionId: string;
  scan: ScanAccessInput;
  userId?: string;
}) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const canChange = canChangeSharing(scan, userId);
  const shared = Boolean(scan.sharedByLink);
  const fileLine = whereFileWent(scan);

  const mutation = useMutation({
    mutationFn: async (next: boolean) => {
      await apiRequest("PUT", `/api/submissions/${submissionId}/sharing`, { sharedByLink: next });
      return next;
    },
    onSuccess: (next) => {
      queryClient.invalidateQueries({ queryKey: [`/api/submissions/${submissionId}`] });
      toast({
        title: next ? "Anyone with the link can open this report" : "Link sharing is off",
        description: next ? "Turn it off here at any time." : "Only the people who could see it before can open it.",
      });
    },
    onError: (err) => {
      toast({ title: "Couldn't change sharing", description: serverMessage(err, "Please try again."), variant: "destructive" });
    },
  });

  const copyLink = () => {
    navigator.clipboard?.writeText(window.location.href).then(
      () => toast({ title: "Link copied" }),
      () => undefined,
    );
  };

  return (
    <section
      className="mb-6 flex flex-col gap-3 border border-border bg-card/50 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between"
      aria-label="Who can see this report"
      data-testid="scan-access"
    >
      <div className="flex min-w-0 items-start gap-2.5">
        {shared ? (
          <Link2 className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        ) : (
          <Lock className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        )}
        <div className="min-w-0">
          <p className="text-foreground" data-testid="scan-access-who">
            {whoCanSee(scan)}
          </p>
          {fileLine && (
            <p className="text-xs text-muted-foreground" data-testid="scan-access-file">
              {fileLine}
            </p>
          )}
        </div>
      </div>
      {canChange && (
        <div className="flex shrink-0 items-center gap-3">
          {shared && (
            <Button size="sm" variant="outline" onClick={copyLink}>
              Copy link
            </Button>
          )}
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <Switch
              checked={shared}
              disabled={mutation.isPending}
              onCheckedChange={(next) => mutation.mutate(next)}
              data-testid="switch-share-by-link"
            />
            Share by link
          </label>
        </div>
      )}
    </section>
  );
}
