import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Mail,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Link2,
  Paperclip,
  FileWarning,
} from "lucide-react";
import type { ApiAnalysis } from "@/lib/api-types";

interface AttachmentRecord {
  filename?: string;
  size?: number;
  mime_type?: string;
  is_suspicious?: boolean;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function authBadgeVariant(status: string): "default" | "destructive" | "secondary" | "outline" {
  const normalized = status.toLowerCase();
  if (normalized === "pass") return "default";
  if (normalized === "fail" || normalized === "permerror") return "destructive";
  if (normalized === "softfail" || normalized === "temperror") return "secondary";
  return "outline";
}

export function EmailForensicsPanel({ analyses }: { analyses: ApiAnalysis[] }) {
  const emailAnalysis = analyses.find((a) =>
    (a.engine?.name || "").toLowerCase().includes("email")
  );
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rawMeta = (emailAnalysis as Record<string, any> | undefined)?.metadata;
  const meta = asRecord(rawMeta) ?? {};

  const from = typeof meta.from === "string" && meta.from ? meta.from : "Not specified in headers";
  const subject = typeof meta.subject === "string" && meta.subject ? meta.subject : "No Subject";
  const replyTo = typeof meta.replyTo === "string" && meta.replyTo ? meta.replyTo : null;
  const returnPath = typeof meta.returnPath === "string" && meta.returnPath ? meta.returnPath : null;
  const messageId = typeof meta.messageId === "string" && meta.messageId ? meta.messageId : null;
  const dateHeader = typeof meta.date === "string" && meta.date ? meta.date : null;

  const spf = typeof meta.spf === "string" ? meta.spf : "none";
  const dkim = typeof meta.dkim === "string" ? meta.dkim : "none";
  const dmarc = typeof meta.dmarc === "string" ? meta.dmarc : "none";
  const forgedHeaders = Boolean(meta.forgedHeaders);
  const receivedHops = typeof meta.receivedHops === "number" ? meta.receivedHops : 0;
  const headerCount = typeof meta.headerCount === "number" ? meta.headerCount : 0;
  const spamScore = typeof meta.spamScore === "string" ? meta.spamScore : "0.0/10";

  const suspiciousHeaders = asStringArray(meta.suspiciousHeaders);
  const suspiciousPatterns = asStringArray(meta.suspiciousPatterns);
  const urgencyIndicators = asStringArray(meta.urgencyIndicators);
  const extractedUrls = asStringArray(meta.extractedUrls);
  const suspiciousAttachments = asStringArray(meta.suspiciousAttachments);
  const attachments: AttachmentRecord[] = Array.isArray(meta.attachments)
    ? (meta.attachments as AttachmentRecord[])
    : [];

  if (!emailAnalysis) {
    return (
      <Card className="glassmorphism">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5 text-primary" />
            Email Header &amp; Phishing Forensics
          </CardTitle>
          <CardDescription>
            Waiting for the MIME Email Scanner engine to complete header, SPF/DKIM/DMARC, and attachment inspection.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Click <strong>Run Scan Now</strong> above or wait a moment for the worker queue to finish parsing the `.eml` payload.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground">SPF Alignment</div>
            <div className="flex items-center justify-between pt-1">
              <span className="font-mono text-sm font-semibold uppercase">{spf}</span>
              <Badge variant={authBadgeVariant(spf)} className="uppercase font-mono text-[10px]">
                {spf}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground">DKIM Signature</div>
            <div className="flex items-center justify-between pt-1">
              <span className="font-mono text-sm font-semibold uppercase">{dkim}</span>
              <Badge variant={authBadgeVariant(dkim)} className="uppercase font-mono text-[10px]">
                {dkim}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground">DMARC Policy</div>
            <div className="flex items-center justify-between pt-1">
              <span className="font-mono text-sm font-semibold uppercase">{dmarc}</span>
              <Badge variant={authBadgeVariant(dmarc)} className="uppercase font-mono text-[10px]">
                {dmarc}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground">Header Forgery</div>
            <div className="flex items-center justify-between pt-1">
              <span className="text-sm font-semibold">
                {forgedHeaders ? "Forgery Detected" : "Consistent"}
              </span>
              {forgedHeaders ? (
                <ShieldAlert className="h-4 w-4 text-destructive" />
              ) : (
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground">Phishing / Spam Risk</div>
            <div className="flex items-center justify-between pt-1">
              <span className="font-mono text-lg font-bold text-primary">{spamScore}</span>
              <Badge variant="outline" className="font-mono text-[10px]">
                {receivedHops} hops · {headerCount} hdrs
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Mail className="h-4 w-4 text-primary" />
              MIME Envelope &amp; Sender Identity
            </CardTitle>
            <CardDescription>
              Compares From, Reply-To, and Return-Path headers to detect display-name and envelope spoofing
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="rounded-lg border border-border/60 bg-muted/20 p-3 space-y-2">
              <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                <span className="text-xs text-muted-foreground">Subject</span>
                <span className="font-semibold break-all">{subject}</span>
              </div>
              <div className="flex flex-col sm:flex-row sm:justify-between gap-1 border-t border-border/40 pt-2">
                <span className="text-xs text-muted-foreground">From</span>
                <span className="font-mono text-xs break-all text-primary">{from}</span>
              </div>
              {replyTo && (
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 border-t border-border/40 pt-2">
                  <span className="text-xs text-muted-foreground">Reply-To</span>
                  <span className="font-mono text-xs break-all">{replyTo}</span>
                </div>
              )}
              {returnPath && (
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 border-t border-border/40 pt-2">
                  <span className="text-xs text-muted-foreground">Return-Path</span>
                  <span className="font-mono text-xs break-all">{returnPath}</span>
                </div>
              )}
              {messageId && (
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 border-t border-border/40 pt-2">
                  <span className="text-xs text-muted-foreground">Message-ID</span>
                  <span className="font-mono text-[11px] break-all text-muted-foreground">{messageId}</span>
                </div>
              )}
              {dateHeader && (
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 border-t border-border/40 pt-2">
                  <span className="text-xs text-muted-foreground">Date Header</span>
                  <span className="font-mono text-xs">{dateHeader}</span>
                </div>
              )}
            </div>

            {suspiciousHeaders.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-destructive flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  Header Anomalies ({suspiciousHeaders.length})
                </div>
                <ul className="space-y-1">
                  {suspiciousHeaders.map((hdr) => (
                    <li
                      key={hdr}
                      className="rounded border border-destructive/30 bg-destructive/10 px-2.5 py-1.5 font-mono text-xs text-destructive"
                    >
                      {hdr}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <FileWarning className="h-4 w-4 text-primary" />
              Social Engineering &amp; Content Triggers
            </CardTitle>
            <CardDescription>
              Urgency coercion phrases, credential harvesting lures, and spam keyword hits
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div>
              <div className="text-xs text-muted-foreground mb-2">
                Urgency &amp; Coercion Triggers ({urgencyIndicators.length})
              </div>
              {urgencyIndicators.length === 0 ? (
                <p className="text-xs text-muted-foreground">No urgency coercion phrases detected.</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {urgencyIndicators.map((kw) => (
                    <Badge key={kw} variant="secondary" className="font-mono text-xs">
                      {kw}
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            <div>
              <div className="text-xs text-muted-foreground mb-2">
                Phishing &amp; Deceptive Patterns ({suspiciousPatterns.length})
              </div>
              {suspiciousPatterns.length === 0 ? (
                <p className="text-xs text-muted-foreground">No known phishing lure phrases matched.</p>
              ) : (
                <ul className="space-y-1.5">
                  {suspiciousPatterns.map((pat) => (
                    <li
                      key={pat}
                      className="rounded border border-border/60 bg-muted/20 px-2.5 py-1.5 font-mono text-xs"
                    >
                      {pat}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Link2 className="h-4 w-4 text-primary" />
              Extracted Body URLs ({extractedUrls.length})
            </CardTitle>
            <CardDescription>Hyperlinks extracted from the MIME message body</CardDescription>
          </CardHeader>
          <CardContent>
            {extractedUrls.length === 0 ? (
              <p className="text-xs text-muted-foreground">No embedded HTTP/HTTPS links found in email body.</p>
            ) : (
              <ul className="space-y-1.5 max-h-48 overflow-y-auto">
                {extractedUrls.map((url) => (
                  <li
                    key={url}
                    className="rounded border border-border/60 bg-muted/20 px-2.5 py-1.5 font-mono text-xs break-all"
                  >
                    {url}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Paperclip className="h-4 w-4 text-primary" />
              MIME Attachments ({attachments.length || suspiciousAttachments.length})
            </CardTitle>
            <CardDescription>Attachments inspected for executable or macro payloads</CardDescription>
          </CardHeader>
          <CardContent>
            {attachments.length === 0 && suspiciousAttachments.length === 0 ? (
              <p className="text-xs text-muted-foreground">No MIME attachments present in this message.</p>
            ) : attachments.length > 0 ? (
              <div className="space-y-2">
                {attachments.map((att, idx) => (
                  <div
                    key={`${att.filename || "att"}-${idx}`}
                    className="flex items-center justify-between rounded border border-border/60 bg-muted/20 px-3 py-2 text-xs"
                  >
                    <span className="font-mono truncate">{att.filename || "attachment"}</span>
                    <Badge variant={att.is_suspicious ? "destructive" : "outline"}>
                      {att.is_suspicious ? "Suspicious Extension" : att.mime_type || "Attachment"}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {suspiciousAttachments.map((name) => (
                  <Badge key={name} variant="destructive" className="font-mono text-xs">
                    {name}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
