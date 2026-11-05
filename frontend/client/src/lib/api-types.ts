/**
 * API Response Types
 *
 * These interfaces describe the shape of JSON objects returned by the backend
 * API. They are intentionally looser than the Drizzle schema types to handle
 * both the gateway's camelCase re-mapping and optional fields.
 */



export interface ApiSubmission {
  id: string;
  submitterId?: string;
  userId?: string;
  fileHash?: string;
  url?: string;
  filename?: string;
  originalFilename?: string;
  fileName?: string;
  fileSize?: number;
  mimeType?: string;
  filePath?: string;
  submissionType?: string;
  analysisType?: string;
  isMalicious?: boolean;
  confidenceScore?: string;
  status?: string;
  analysisStatus?: string;
  description?: string;
  bountyAmount?: string | number;
  bountyId?: string | null;
  priority?: boolean;
  metadata?: Record<string, unknown>;
  createdAt?: string;
  updatedAt?: string;
  completedAt?: string;
}

export interface ApiEngine {
  id: string;
  name: string;
  type?: string;
  engineType?: string;
  description?: string | null;
  ownerId?: string | null;
  apiEndpoint?: string | null;
  isActive?: boolean | null;
  accuracy?: string;
  accuracyRate?: string;
  totalAnalyses?: number;
  correctAnalyses?: number;
  stakeAmount?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface ApiAnalysis {
  id: string;
  engineId?: string;
  engine?: { name?: string; type?: string; version?: string; description?: string };
  submissionId?: string;
  verdict?: string;
  /** Percent, only when the engine gave a verdict. */
  confidence?: number | null;
  /** How the engine took part: "counted", "no_record", "advisory", "unavailable". */
  vote?: string;
  /** Why it didn't vote, when it didn't. */
  reason?: string | null;
  severity?: string | null;
  processingTimeMs?: number | null;
  metadata?: Record<string, unknown>;
  status?: string;
  analysisStatus?: string;
  createdAt?: string;
  completedAt?: string;
}

export interface ApiConsensus {
  id?: string;
  submissionId?: string;
  finalVerdict?: string;
  /** Share of voting engines that agree with the top verdict (0-1). */
  agreementScore?: number;
  maliciousVotes?: number;
  suspiciousVotes?: number;
  cleanVotes?: number;
  totalVotes?: number;
  flaggedVotes?: number;
  engineCount?: number;
  participatingEngines?: string[];
  unavailableEngines?: Array<{
    engineName: string;
    engineType?: string;
    reason: string;
    kind?: "unavailable" | "no_record" | "advisory";
  }>;
  explanation?: string;
  voteDistribution?: {
    malicious: number;
    benign: number;
    suspicious: number;
    unknown: number;
    totalParticipating: number;
    totalEngines: number;
  };
  verdictHistory?: Array<{
    verdict: string;
    confidence: number;
    reason: string;
    changedBy: string;
    changedAt: string;
  }>;
}

export interface ApiStats {
  totalSubmissions?: number;
  totalEngines?: number;
  totalAnalyses?: number;
  threatsDetected?: number;
  maliciousCount?: number;
  benignCount?: number;
  suspiciousCount?: number;
  completed?: number;
  pending?: number;
  activeAnalyses?: number;
  completedToday?: number;
  totalActiveBounties?: string | number;
  avgResponseTime?: string;
  totalRewardsPaid?: string;
  pendingSubmissions?: number;
  completedAnalyses?: number;
  analyzingCount?: number;
  [key: string]: unknown;
}
