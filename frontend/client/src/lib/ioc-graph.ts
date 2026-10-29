import { extractStaticIndicators } from "@/lib/attack-mapping";
import type { ApiSubmission } from "@/lib/api-types";

export type IocKind = "artifact" | "hash" | "ip" | "asn" | "cert" | "host" | "submission" | "url" | "ports";

export interface IocNode {
  id: string;
  label: string;
  kind: IocKind;
  href?: string;
}

export interface IocEdge {
  source: string;
  target: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function hostOf(value?: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    return new URL(withScheme).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function labelOf(submission: Pick<ApiSubmission, "originalFilename" | "filename" | "fileName" | "url" | "id">): string {
  return submission.originalFilename || submission.filename || submission.fileName || submission.url || submission.id;
}

export function buildIocGraph(input: {
  submission: ApiSubmission;
  analyses: readonly unknown[];
  webIntel?: Record<string, unknown> | null;
  submissions: ApiSubmission[];
}): { nodes: IocNode[]; edges: IocEdge[] } {
  const nodes: IocNode[] = [];
  const edges: IocEdge[] = [];
  const seen = new Set<string>();

  const addNode = (node: IocNode) => {
    if (seen.has(node.id) || nodes.length >= 32) return false;
    seen.add(node.id);
    nodes.push(node);
    return true;
  };
  const link = (source: string, target: string) => {
    if (source === target || !seen.has(source) || !seen.has(target)) return;
    if (edges.some((edge) => edge.source === source && edge.target === target)) return;
    edges.push({ source, target });
  };

  const center = "artifact";
  addNode({
    id: center,
    label: labelOf(input.submission),
    kind: "artifact",
  });

  const hash = input.submission.fileHash?.trim();
  if (hash) {
    addNode({ id: `hash:${hash}`, label: hash.slice(0, 16), kind: "hash" });
    link(center, `hash:${hash}`);
  }

  const intel = input.webIntel ?? null;
  const ipInfo = asRecord(intel?.ipInfo);
  const serverInfo = asRecord(intel?.serverInfo);
  const cert = asRecord(intel?.sslCertificate);
  const hosts = asRecord(intel?.associatedHosts);
  const ports = asRecord(intel?.openPorts);
  const primaryIp = typeof ipInfo?.primaryIp === "string" ? ipInfo.primaryIp : "";
  const ips = new Set<string>();
  if (primaryIp && primaryIp !== "N/A" && primaryIp !== "Unresolved") ips.add(primaryIp);
  if (Array.isArray(ipInfo?.ipv4Addresses)) {
    for (const ip of ipInfo.ipv4Addresses) {
      if (typeof ip === "string" && ip) ips.add(ip);
    }
  }
  const staticIocs = extractStaticIndicators(input.analyses);
  for (const ip of staticIocs.ips) ips.add(ip);

  ips.forEach((ip) => {
    if (addNode({ id: `ip:${ip}`, label: ip, kind: "ip" })) link(center, `ip:${ip}`);
  });

  const asn = typeof serverInfo?.asn === "string" ? serverInfo.asn : "";
  if (asn && asn !== "N/A") {
    if (addNode({ id: `asn:${asn}`, label: asn, kind: "asn" })) {
      const anchor = primaryIp ? `ip:${primaryIp}` : center;
      link(anchor, `asn:${asn}`);
    }
  }

  const serial = typeof cert?.serialNumber === "string" ? cert.serialNumber : "";
  const issuer = typeof cert?.issuer === "string" ? cert.issuer : "";
  if (serial && serial !== "N/A") {
    const certLabel = issuer ? `${serial.slice(0, 18)} · ${issuer.slice(0, 28)}` : serial.slice(0, 24);
    if (addNode({ id: `cert:${serial}`, label: certLabel, kind: "cert" })) link(center, `cert:${serial}`);
  }

  const pageHost = hostOf(typeof intel?.host === "string" ? intel.host : input.submission.url);
  if (pageHost) {
    if (addNode({ id: `host:${pageHost}`, label: pageHost, kind: "host" })) {
      link(center, `host:${pageHost}`);
      if (primaryIp) link(`host:${pageHost}`, `ip:${primaryIp}`);
    }
  }

  const associated = Array.isArray(hosts?.hostnames) ? hosts.hostnames : [];
  for (const host of associated) {
    if (typeof host !== "string" || !host || host === pageHost) continue;
    if (addNode({ id: `host:${host}`, label: host, kind: "host" })) {
      link(pageHost ? `host:${pageHost}` : center, `host:${host}`);
      if (primaryIp) link(`host:${host}`, `ip:${primaryIp}`);
    }
  }

  const portList = Array.isArray(ports?.ports)
    ? ports.ports.filter((port): port is number => typeof port === "number")
    : [];
  if (portList.length > 0) {
    const label = `ports ${portList.slice(0, 8).join(", ")}`;
    if (addNode({ id: "ports", label, kind: "ports" })) {
      link(primaryIp ? `ip:${primaryIp}` : center, "ports");
    }
  }

  for (const url of staticIocs.urls) {
    if (addNode({ id: `url:${url}`, label: url.slice(0, 42), kind: "url" })) link(center, `url:${url}`);
  }

  const selfHost = hostOf(input.submission.url);
  for (const other of input.submissions) {
    if (!other.id || other.id === input.submission.id) continue;
    const sameHash = Boolean(hash && other.fileHash && other.fileHash === hash);
    const otherHost = hostOf(other.url || other.originalFilename || other.filename || other.fileName);
    const sameHost = Boolean(selfHost && otherHost && selfHost === otherHost);
    const sharesAssociated = Boolean(
      otherHost && associated.some((host) => typeof host === "string" && host.toLowerCase() === otherHost),
    );
    if (!sameHash && !sameHost && !sharesAssociated) continue;
    const id = `submission:${other.id}`;
    if (!addNode({ id, label: labelOf(other).slice(0, 32), kind: "submission", href: `/analysis/${other.id}` })) {
      continue;
    }
    if (sameHash && hash) link(id, `hash:${hash}`);
    else if (sameHost && selfHost) link(id, `host:${selfHost}`);
    else if (sharesAssociated && otherHost) link(id, `host:${otherHost}`);
    else link(center, id);
  }

  return { nodes, edges };
}
