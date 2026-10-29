export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
  evidence: string[];
}

interface StringHit {
  content: string;
  category: string;
  severity: number;
}

interface EvidenceBag {
  imports: string[];
  strings: StringHit[];
  packed: boolean;
  packers: string[];
  highEntropySections: string[];
  registry: string[];
  urls: string[];
  ips: string[];
  bitcoin: string[];
  ethereum: string[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function parseMeta(raw: unknown): Record<string, unknown> | null {
  if (typeof raw === "string") {
    try {
      return asRecord(JSON.parse(raw));
    } catch {
      return null;
    }
  }
  return asRecord(raw);
}

function field(obj: Record<string, unknown> | null, ...keys: string[]): unknown {
  if (!obj) return undefined;
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) return obj[key];
  }
  return undefined;
}

function asStrings(value: unknown, cap: number): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") continue;
    const trimmed = item.trim().slice(0, 160);
    if (!trimmed || out.includes(trimmed)) continue;
    out.push(trimmed);
    if (out.length >= cap) break;
  }
  return out;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) {
    return Number(value);
  }
  return null;
}

function pushUnique(list: string[], value: string, cap: number) {
  const trimmed = value.trim().slice(0, 160);
  if (!trimmed || list.includes(trimmed) || list.length >= cap) return;
  list.push(trimmed);
}

function collect(analyses: readonly unknown[]): EvidenceBag {
  const bag: EvidenceBag = {
    imports: [],
    strings: [],
    packed: false,
    packers: [],
    highEntropySections: [],
    registry: [],
    urls: [],
    ips: [],
    bitcoin: [],
    ethereum: [],
  };

  for (const item of analyses) {
    const meta = parseMeta(asRecord(item)?.metadata);
    if (!meta) continue;

    const entropy = asRecord(field(meta, "entropy_analysis", "entropyAnalysis"));
    if (entropy?.is_likely_packed === true || entropy?.isLikelyPacked === true) bag.packed = true;
    const overall = asNumber(field(entropy, "overall_entropy", "overallEntropy"));
    if (overall !== null && overall >= 7) bag.packed = true;

    for (const key of ["pe_analysis", "peAnalysis", "elf_analysis", "elfAnalysis"] as const) {
      const binary = asRecord(meta[key]);
      if (!binary) continue;
      if (binary.is_packed === true || binary.isPacked === true) bag.packed = true;
      for (const name of asStrings(field(binary, "packer_signatures", "packerSignatures"), 8)) {
        pushUnique(bag.packers, name, 8);
      }
      for (const name of asStrings(field(binary, "imports"), 80)) pushUnique(bag.imports, name, 80);
      for (const name of asStrings(field(binary, "suspicious_imports", "suspiciousImports"), 40)) {
        pushUnique(bag.imports, name, 80);
      }
      const sections = field(binary, "sections");
      if (Array.isArray(sections)) {
        for (const section of sections) {
          const row = asRecord(section);
          if (!row) continue;
          const ent = asNumber(field(row, "entropy"));
          if (ent === null || ent < 7) continue;
          const name = typeof row.name === "string" && row.name ? row.name : "section";
          pushUnique(bag.highEntropySections, `${name} entropy ${ent.toFixed(2)}`, 8);
        }
      }
    }

    const stringsBlock = asRecord(field(meta, "string_analysis", "stringAnalysis"));
    if (!stringsBlock) continue;
    const suspicious = field(stringsBlock, "suspicious_strings", "suspiciousStrings");
    if (Array.isArray(suspicious)) {
      for (const entry of suspicious) {
        const row = asRecord(entry);
        if (!row || typeof row.content !== "string" || bag.strings.length >= 40) continue;
        bag.strings.push({
          content: row.content.slice(0, 160),
          category: typeof row.category === "string" ? row.category : "",
          severity: asNumber(row.severity) ?? 0,
        });
      }
    }
    for (const url of asStrings(field(stringsBlock, "urls"), 8)) pushUnique(bag.urls, url, 8);
    for (const ip of asStrings(field(stringsBlock, "ips"), 8)) pushUnique(bag.ips, ip, 8);
    for (const key of asStrings(field(stringsBlock, "registry_keys", "registryKeys"), 8)) {
      pushUnique(bag.registry, key, 8);
    }
    for (const address of asStrings(field(stringsBlock, "bitcoin_addresses", "bitcoinAddresses"), 4)) {
      pushUnique(bag.bitcoin, address, 4);
    }
    for (const address of asStrings(field(stringsBlock, "ethereum_addresses", "ethereumAddresses"), 4)) {
      pushUnique(bag.ethereum, address, 4);
    }
  }

  return bag;
}

function importHits(bag: EvidenceBag, needles: string[]): string[] {
  const lowered = needles.map((needle) => needle.toLowerCase());
  return bag.imports.filter((name) => lowered.some((needle) => name.toLowerCase().includes(needle)));
}

function stringHits(
  bag: EvidenceBag,
  pred: (hit: StringHit) => boolean,
): string[] {
  return bag.strings.filter(pred).map((hit) => `${hit.category || "string"}: ${hit.content}`);
}

function techniqueUrl(id: string): string {
  const path = id.replace(".", "/");
  return `https://attack.mitre.org/techniques/${path}/`;
}

export function mapAttackTechniques(analyses: readonly unknown[]): AttackTechnique[] {
  const bag = collect(analyses);
  const found = new Map<string, AttackTechnique>();

  const add = (id: string, name: string, tactic: string, evidence: string[]) => {
    const unique = evidence.filter((item, index) => item && evidence.indexOf(item) === index).slice(0, 6);
    if (unique.length === 0) return;
    const prev = found.get(id);
    if (prev) {
      for (const item of unique) {
        if (!prev.evidence.includes(item) && prev.evidence.length < 6) prev.evidence.push(item);
      }
      return;
    }
    found.set(id, { id, name, tactic, url: techniqueUrl(id), evidence: unique });
  };

  const packEvidence = [
    ...bag.packers.map((packer) => `Packer signature: ${packer}`),
    ...bag.highEntropySections.map((section) => `High-entropy section: ${section}`),
    ...(bag.packed && bag.packers.length === 0 && bag.highEntropySections.length === 0
      ? ["Static analysis marked the file packed or above the entropy threshold (7.0)"]
      : []),
    ...stringHits(bag, (hit) => hit.category === "Obfuscation"),
  ];
  add("T1027", "Obfuscated Files or Information", "Defense Evasion", packEvidence);

  add("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", stringHits(bag, (hit) => {
    return hit.category === "Obfuscation" && /unpack|decode|deobfuscate|base64/i.test(hit.content);
  }));

  add(
    "T1055",
    "Process Injection",
    "Defense Evasion",
    [
      ...importHits(bag, [
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "NtCreateThreadEx",
        "process_vm_writev",
        "QueueUserAPC",
      ]).map((name) => `Import: ${name}`),
      ...stringHits(bag, (hit) => {
        return hit.category === "ProcessInjection"
          || /createremotethread|writeprocessmemory|virtualallocex|ntcreatethreadex|process_vm_writev/i.test(hit.content);
      }),
    ],
  );

  add(
    "T1055.012",
    "Process Hollowing",
    "Defense Evasion",
    [
      ...importHits(bag, ["ZwUnmapViewOfSection", "NtUnmapViewOfSection"]).map((name) => `Import: ${name}`),
      ...stringHits(bag, (hit) => /hollow/i.test(hit.content)),
    ],
  );

  add(
    "T1620",
    "Reflective Code Loading",
    "Defense Evasion",
    [
      ...importHits(bag, ["memfd_create"]).map((name) => `Import: ${name}`),
      ...stringHits(bag, (hit) => /reflective/i.test(hit.content)),
    ],
  );

  add(
    "T1622",
    "Debugger Evasion",
    "Defense Evasion",
    [
      ...importHits(bag, ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "ptrace", "OutputDebugString"]).map(
        (name) => `Import: ${name}`,
      ),
      ...stringHits(bag, (hit) => {
        return hit.category === "AntiAnalysis"
          || /isdebuggerpresent|checkremotedebuggerpresent|\bptrace\b/i.test(hit.content);
      }),
    ],
  );

  add(
    "T1056.001",
    "Keylogging",
    "Collection",
    [
      ...importHits(bag, ["SetWindowsHookEx", "GetAsyncKeyState"]).map((name) => `Import: ${name}`),
      ...stringHits(bag, (hit) => {
        return hit.category === "Keylogging" || /setwindowshookex|getasynckeystate|wh_keyboard/i.test(hit.content);
      }),
    ],
  );

  const ransomware = stringHits(bag, (hit) => {
    return hit.category === "Ransomware" || /decrypt_instructions|\.encrypted|\.locked/i.test(hit.content);
  });
  if (ransomware.length > 0) {
    add("T1486", "Data Encrypted for Impact", "Impact", [
      ...ransomware,
      ...bag.bitcoin.map((address) => `Bitcoin address: ${address}`),
      ...bag.ethereum.map((address) => `Ethereum address: ${address}`),
    ]);
  }

  add(
    "T1496",
    "Resource Hijacking",
    "Impact",
    stringHits(bag, (hit) => hit.category === "CryptoMining"),
  );

  add(
    "T1003",
    "OS Credential Dumping",
    "Credential Access",
    stringHits(bag, (hit) => {
      return (hit.category === "CredentialTheft" && hit.severity >= 8)
        || /mimikatz|lsass|procdump/i.test(hit.content);
    }),
  );

  add(
    "T1112",
    "Modify Registry",
    "Defense Evasion",
    bag.registry.map((key) => `Registry key: ${key}`),
  );

  add(
    "T1547.001",
    "Registry Run Keys / Startup Folder",
    "Persistence",
    bag.registry
      .filter((key) => /currentversion\\run|\\run(\\|$)/i.test(key))
      .map((key) => `Run key: ${key}`),
  );

  add(
    "T1105",
    "Ingress Tool Transfer",
    "Command and Control",
    [
      ...importHits(bag, ["URLDownloadToFile", "URLDownloadToCacheFile", "WinHttpSendRequest", "HttpSendRequest"]).map(
        (name) => `Import: ${name}`,
      ),
      ...stringHits(bag, (hit) => /urldownloadtofile|winhttpsendrequest|httpsendrequest/i.test(hit.content)),
    ],
  );

  add(
    "T1059.001",
    "PowerShell",
    "Execution",
    stringHits(bag, (hit) => /powershell|pwsh\.exe/i.test(hit.content)),
  );

  add(
    "T1059.003",
    "Windows Command Shell",
    "Execution",
    stringHits(bag, (hit) => /cmd\.exe|cmd\s+\/c/i.test(hit.content)),
  );

  add(
    "T1059.004",
    "Unix Shell",
    "Execution",
    [
      ...importHits(bag, ["execve", "posix_spawn"]).map((name) => `Import: ${name}`),
      ...stringHits(bag, (hit) => /\/bin\/(sh|bash|zsh)\b/.test(hit.content)),
    ],
  );

  add(
    "T1071",
    "Application Layer Protocol",
    "Command and Control",
    stringHits(bag, (hit) => hit.category === "C2Communication"),
  );

  return Array.from(found.values()).sort((a, b) => a.id.localeCompare(b.id));
}

export function extractStaticIndicators(analyses: readonly unknown[]): { urls: string[]; ips: string[] } {
  const bag = collect(analyses);
  return { urls: bag.urls, ips: bag.ips };
}
