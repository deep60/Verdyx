function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = localStorage.getItem("token");
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function readJson<T>(res: Response): Promise<T> {
  const text = await res.text();
  if (!res.ok) {
    let message = text || res.statusText;
    try {
      const body = JSON.parse(text) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      /* keep the raw body */
    }
    throw new Error(message);
  }
  return text ? (JSON.parse(text) as T) : ({} as T);
}

export interface VotingPhase {
  bounty_id: string;
  phase: "commit" | "reveal" | "closed";
  total_commits: number;
  revealed: number;
  phase_ends_at?: string | null;
}

export interface VerdictGrade {
  bounty_id: string;
  original_verdict: string;
  graded_verdict: string;
  verdict_changed: boolean;
  grade_source: string;
  graded_at: string;
  notes?: string | null;
}

export async function fetchVotingPhase(bountyId: string): Promise<VotingPhase> {
  const res = await fetch(`/api/voting/bounty/${bountyId}/phase`, {
    headers: authHeaders(),
    credentials: "include",
  });
  return readJson(res);
}

export async function fetchGrade(bountyId: string): Promise<VerdictGrade | null> {
  const res = await fetch(`/api/grades/${bountyId}`, {
    headers: authHeaders(),
    credentials: "include",
  });
  if (res.status === 404) return null;
  return readJson(res);
}

export async function commitVote(bountyId: string, engineId: string, commitment: string) {
  const res = await fetch(`/api/voting/bounty/${bountyId}/commit`, {
    method: "POST",
    headers: authHeaders(),
    credentials: "include",
    body: JSON.stringify({ engine_id: engineId, commitment }),
  });
  return readJson(res);
}

export async function revealVote(input: {
  bountyId: string;
  engineId: string;
  verdict: string;
  confidence: string;
  salt: string;
}) {
  const res = await fetch(`/api/voting/bounty/${input.bountyId}/reveal`, {
    method: "POST",
    headers: authHeaders(),
    credentials: "include",
    body: JSON.stringify({
      engine_id: input.engineId,
      verdict: input.verdict,
      confidence: input.confidence,
      salt: input.salt,
    }),
  });
  return readJson(res);
}

export async function createDispute(input: {
  bountyId: string;
  submissionId: string;
  disputedVerdict: string;
  claimedVerdict: string;
  reason: string;
}) {
  const res = await fetch("/api/disputes/create", {
    method: "POST",
    headers: authHeaders(),
    credentials: "include",
    body: JSON.stringify({
      bounty_id: input.bountyId,
      submission_id: input.submissionId,
      disputed_verdict: input.disputedVerdict,
      claimed_verdict: input.claimedVerdict,
      reason: input.reason,
    }),
  });
  return readJson<{ dispute_id: string; status: string }>(res);
}
