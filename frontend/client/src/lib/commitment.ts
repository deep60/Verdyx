/**
 * Commit-reveal preimage. Must match consensus-service `commitment::preimage`:
 * `{bounty_id}:{engine_id}:{verdict}:{confidence:.4}:{salt}`
 * hashed with SHA-256 and hex-encoded in lowercase.
 */
export async function voteCommitment(input: {
  bountyId: string;
  engineId: string;
  verdict: string;
  confidence: string;
  salt: string;
}): Promise<string> {
  const preimage = [
    input.bountyId,
    input.engineId.trim(),
    input.verdict.trim().toLowerCase(),
    formatConfidence(input.confidence),
    input.salt,
  ].join(":");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(preimage));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** Four decimal places, matching `Decimal` formatting at precision 4. */
export function formatConfidence(value: string | number): string {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(parsed)) return "0.0000";
  return parsed.toFixed(4);
}

export function randomSalt(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
