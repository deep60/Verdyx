import type { AttackTechnique } from "@/lib/attack-mapping";

export interface StixExportInput {
  submissionId: string;
  fileName: string;
  sha256?: string;
  targetUrl?: string;
  verdict?: string;
  techniques: AttackTechnique[];
}

function stixUuid(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function escapePattern(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function indicatorType(verdict?: string): string {
  switch ((verdict || "").toLowerCase()) {
    case "malicious":
      return "malicious-activity";
    case "suspicious":
      return "anomalous-activity";
    case "clean":
    case "benign":
      return "benign";
    default:
      return "unknown";
  }
}

export function buildStixBundle(input: StixExportInput): Record<string, unknown> {
  const now = new Date().toISOString();
  const identityId = `identity--${stixUuid()}`;
  const objects: Record<string, unknown>[] = [
    {
      type: "identity",
      spec_version: "2.1",
      id: identityId,
      created: now,
      modified: now,
      name: "Verdyx",
      identity_class: "system",
    },
  ];

  const indicatorIds: string[] = [];
  const addIndicator = (name: string, pattern: string) => {
    const id = `indicator--${stixUuid()}`;
    indicatorIds.push(id);
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id,
      created: now,
      modified: now,
      name,
      description: `Exported from Verdyx submission ${input.submissionId}`,
      pattern,
      pattern_type: "stix",
      pattern_version: "2.1",
      valid_from: now,
      indicator_types: [indicatorType(input.verdict)],
      created_by_ref: identityId,
    });
  };

  if (input.sha256 && /^[a-fA-F0-9]{64}$/.test(input.sha256)) {
    addIndicator(
      input.fileName || input.sha256,
      `[file:hashes.'SHA-256' = '${input.sha256.toLowerCase()}']`,
    );
  }
  if (input.targetUrl && /^https?:\/\//i.test(input.targetUrl)) {
    addIndicator(input.targetUrl, `[url:value = '${escapePattern(input.targetUrl)}']`);
  }
  if (indicatorIds.length === 0) {
    const name = input.fileName || input.submissionId;
    addIndicator(name, `[file:name = '${escapePattern(name)}']`);
  }

  for (const technique of input.techniques) {
    const patternId = `attack-pattern--${stixUuid()}`;
    objects.push({
      type: "attack-pattern",
      spec_version: "2.1",
      id: patternId,
      created: now,
      modified: now,
      name: technique.name,
      description: technique.evidence.join("; "),
      created_by_ref: identityId,
      external_references: [
        {
          source_name: "mitre-attack",
          external_id: technique.id,
          url: technique.url,
        },
      ],
    });
    for (const sourceRef of indicatorIds) {
      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: `relationship--${stixUuid()}`,
        created: now,
        modified: now,
        relationship_type: "indicates",
        source_ref: sourceRef,
        target_ref: patternId,
        created_by_ref: identityId,
      });
    }
  }

  return {
    type: "bundle",
    id: `bundle--${stixUuid()}`,
    objects,
  };
}
