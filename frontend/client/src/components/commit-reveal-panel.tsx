import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/auth-context";
import { formatConfidence, randomSalt, voteCommitment } from "@/lib/commitment";
import {
  commitVote,
  createDispute,
  fetchGrade,
  fetchVotingPhase,
  revealVote,
} from "@/lib/consensus-api";

const VERDICTS = ["benign", "suspicious", "malicious"] as const;
const SECRET_KEY = (bountyId: string, engineId: string) => `verdyx-commit:${bountyId}:${engineId}`;

interface StoredCommit {
  salt: string;
  verdict: string;
  confidence: string;
}

function readStored(bountyId: string, engineId: string): StoredCommit | null {
  const raw = sessionStorage.getItem(SECRET_KEY(bountyId, engineId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredCommit;
  } catch {
    return null;
  }
}

function normalizeVerdict(value: string | undefined): string {
  const v = (value || "").toLowerCase();
  if (v === "clean") return "benign";
  if (VERDICTS.includes(v as (typeof VERDICTS)[number]) || v === "unknown") return v;
  return "suspicious";
}

interface CommitRevealPanelProps {
  bountyId?: string | null;
  submissionId: string;
  currentVerdict?: string;
  onCommitPhase?: (hidingTally: boolean) => void;
}

export function CommitRevealPanel({
  bountyId,
  submissionId,
  currentVerdict,
  onCommitPhase,
}: CommitRevealPanelProps) {
  const { user, isAuthenticated } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const engineId = user?.id ?? "";
  const [verdict, setVerdict] = useState<(typeof VERDICTS)[number]>("malicious");
  const [confidence, setConfidence] = useState("0.9000");
  const [disputeOpen, setDisputeOpen] = useState(false);
  const [claimed, setClaimed] = useState<(typeof VERDICTS)[number]>("benign");
  const [reason, setReason] = useState("");

  const phaseQuery = useQuery({
    queryKey: ["voting-phase", bountyId],
    enabled: !!bountyId,
    refetchInterval: 15000,
    queryFn: () => fetchVotingPhase(bountyId as string),
  });

  const gradeQuery = useQuery({
    queryKey: ["verdict-grade", bountyId],
    enabled: !!bountyId,
    queryFn: () => fetchGrade(bountyId as string),
  });

  const phase = phaseQuery.data?.phase;
  useEffect(() => {
    onCommitPhase?.(phase === "commit");
  }, [phase, onCommitPhase]);

  const stored = bountyId && engineId ? readStored(bountyId, engineId) : null;

  const commitMutation = useMutation({
    mutationFn: async () => {
      if (!bountyId || !engineId) throw new Error("Sign in to commit a verdict");
      const salt = randomSalt();
      const confidenceFixed = formatConfidence(confidence);
      const commitment = await voteCommitment({
        bountyId,
        engineId,
        verdict,
        confidence: confidenceFixed,
        salt,
      });
      await commitVote(bountyId, engineId, commitment);
      sessionStorage.setItem(
        SECRET_KEY(bountyId, engineId),
        JSON.stringify({ salt, verdict, confidence: confidenceFixed } satisfies StoredCommit),
      );
    },
    onSuccess: () => {
      toast({
        title: "Verdict sealed",
        description: "Only the hash was published. Reveal it from this browser after the commit window closes.",
      });
      queryClient.invalidateQueries({ queryKey: ["voting-phase", bountyId] });
    },
    onError: (err) => {
      toast({
        title: "Commit failed",
        description: err instanceof Error ? err.message : "Could not seal the vote",
        variant: "destructive",
      });
    },
  });

  const revealMutation = useMutation({
    mutationFn: async () => {
      if (!bountyId || !engineId || !stored) throw new Error("No sealed vote in this browser");
      await revealVote({
        bountyId,
        engineId,
        verdict: stored.verdict,
        confidence: stored.confidence,
        salt: stored.salt,
      });
    },
    onSuccess: () => {
      toast({
        title: "Verdict revealed",
        description: `Your ${stored?.verdict} vote is now public and can be checked against the hash.`,
      });
      queryClient.invalidateQueries({ queryKey: ["voting-phase", bountyId] });
    },
    onError: (err) => {
      toast({
        title: "Reveal failed",
        description: err instanceof Error ? err.message : "The window may be closed, or this is not the browser that committed.",
        variant: "destructive",
      });
    },
  });

  const disputeMutation = useMutation({
    mutationFn: async () => {
      if (!bountyId) throw new Error("This sample has no bounty to dispute");
      if (reason.trim().length < 8) throw new Error("Give a short reason for the challenge");
      return createDispute({
        bountyId,
        submissionId,
        disputedVerdict: normalizeVerdict(currentVerdict),
        claimedVerdict: claimed,
        reason: reason.trim(),
      });
    },
    onSuccess: (data) => {
      toast({
        title: "Challenge opened",
        description: `Dispute ${data.dispute_id} is open for review.`,
      });
      setDisputeOpen(false);
      setReason("");
    },
    onError: (err) => {
      toast({
        title: "Could not open dispute",
        description: err instanceof Error ? err.message : "Try again",
        variant: "destructive",
      });
    },
  });

  const grade = gradeQuery.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {grade ? (
          <Badge variant={grade.verdict_changed ? "destructive" : "secondary"} data-testid="badge-ground-truth">
            30-day ground truth: {grade.graded_verdict}
            {grade.verdict_changed ? " (crowd overturned)" : " (crowd held)"}
          </Badge>
        ) : (
          <Badge variant="outline" data-testid="badge-grade-pending">
            30-day delayed ground-truth grade pending
          </Badge>
        )}
        {phase && (
          <Badge variant="outline" className="capitalize">
            Vote phase: {phase}
            {typeof phaseQuery.data?.total_commits === "number"
              ? ` · ${phaseQuery.data.total_commits} sealed`
              : ""}
          </Badge>
        )}
      </div>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-xl">
          <div className="text-sm font-semibold">Commit, then reveal</div>
          <p className="text-xs text-muted-foreground mt-1">
            Your verdict is hashed before it is sent. Other analysts see how many people committed, not which way they voted, until the reveal window opens.
          </p>
        </div>
        {!bountyId ? (
          <p className="text-xs text-muted-foreground max-w-sm">
            Voting opens when this upload has a bounty. The seal is stored against that bounty, not the file id.
          </p>
        ) : !isAuthenticated ? (
          <p className="text-xs text-muted-foreground">Sign in to seal a verdict.</p>
        ) : phase === "reveal" || phase === "closed" ? (
          <div className="flex flex-col items-end gap-2">
            <p className="text-xs text-muted-foreground text-right max-w-xs">
              {stored
                ? `Sealed ${stored.verdict} at ${stored.confidence}. Reveal publishes that exact vote.`
                : "No sealed vote in this browser. A commit cannot be revealed without its salt."}
            </p>
            <Button
              size="sm"
              disabled={!stored || phase === "closed" || revealMutation.isPending}
              onClick={() => revealMutation.mutate()}
              data-testid="button-reveal-vote"
            >
              {phase === "closed" ? "Reveal window closed" : "Reveal verdict"}
            </Button>
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            {VERDICTS.map((option) => (
              <Button
                key={option}
                type="button"
                size="sm"
                variant={verdict === option ? "default" : "outline"}
                className="capitalize"
                onClick={() => setVerdict(option)}
                data-testid={`button-commit-${option}`}
              >
                {option === "benign" ? "Clean / Benign" : option}
              </Button>
            ))}
            <label className="text-xs text-muted-foreground" htmlFor="commit-confidence">
              Confidence
              <input
                id="commit-confidence"
                className="ml-2 w-20 rounded border border-border bg-background px-2 py-1 text-foreground"
                value={confidence}
                onChange={(e) => setConfidence(e.target.value)}
                data-testid="input-commit-confidence"
              />
            </label>
            <Button
              size="sm"
              disabled={commitMutation.isPending || phaseQuery.isLoading}
              onClick={() => commitMutation.mutate()}
              data-testid="button-commit-vote"
            >
              {commitMutation.isPending ? "Sealing..." : "Commit hash"}
            </Button>
          </div>
        )}
      </div>

      <div className="flex justify-end">
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!bountyId || !isAuthenticated}
          onClick={() => setDisputeOpen(true)}
          data-testid="button-challenge-verdict"
        >
          Challenge verdict
        </Button>
      </div>

      <Dialog open={disputeOpen} onOpenChange={setDisputeOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Challenge this verdict</DialogTitle>
            <DialogDescription>
              Tell the regrader what you believe the sample is. The current call is{" "}
              {normalizeVerdict(currentVerdict)}. A 30-day ground-truth grade can overturn it.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Your claimed verdict</Label>
              <div className="flex gap-2">
                {VERDICTS.map((option) => (
                  <Button
                    key={option}
                    type="button"
                    size="sm"
                    variant={claimed === option ? "default" : "outline"}
                    className="capitalize"
                    onClick={() => setClaimed(option)}
                  >
                    {option}
                  </Button>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="dispute-reason">Reason</Label>
              <Textarea
                id="dispute-reason"
                rows={4}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="What did the engines miss, and what should the grade be?"
                data-testid="textarea-dispute-reason"
              />
            </div>
            <Button
              className="w-full"
              disabled={disputeMutation.isPending}
              onClick={() => disputeMutation.mutate()}
              data-testid="button-submit-dispute"
            >
              {disputeMutation.isPending ? "Opening..." : "Open dispute"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
