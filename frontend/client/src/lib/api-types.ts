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
  engine?: { name?: string; type?: string; description?: string };
  submissionId?: string;
  verdict?: string;
  confidence?: number;
  confidenceScore?: string;
  status?: string;
  analysisStatus?: string;
  stakeAmount?: string;
  createdAt?: string;
  completedAt?: string;
}

export interface ApiConsensus {
  id?: string;
  submissionId?: string;
  finalVerdict?: string;
  confidenceScore?: number | string;
  agreementScore?: number;
  confidenceNote?: string;
  maliciousVotes?: number;
  suspiciousVotes?: number;
  cleanVotes?: number;
  benignVotes?: number;
  totalVotes?: number;
  participatingEngines?: string[];
  unavailableEngines?: Array<{
    engineName: string;
    engineType?: string;
    reason: string;
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
