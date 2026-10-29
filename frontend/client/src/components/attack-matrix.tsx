import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { AttackTechnique } from "@/lib/attack-mapping";
import { Shield } from "lucide-react";

export function AttackMatrix({ techniques }: { techniques: AttackTechnique[] }) {
  const tactics = Array.from(new Set(techniques.map((technique) => technique.tactic)));

  return (
    <Card className="glassmorphism">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          MITRE ATT&CK
        </CardTitle>
        <CardDescription>
          Techniques are added only when this scan&apos;s PE imports, ELF imports, high-entropy sections, packer signatures, or suspicious strings support them.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {techniques.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No ATT&CK technique is supported by this scan&apos;s static metadata. A clean or unscanned file stays empty here.
          </p>
        ) : (
          tactics.map((tactic) => (
            <div key={tactic} className="space-y-2">
              <div className="text-xs font-mono uppercase tracking-wider text-muted-foreground">{tactic}</div>
              <div className="grid gap-3 md:grid-cols-2">
                {techniques
                  .filter((technique) => technique.tactic === tactic)
                  .map((technique) => (
                    <div key={technique.id} className="rounded-lg border border-border/70 bg-muted/20 p-3 space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline" className="font-mono">
                          {technique.id}
                        </Badge>
                        <a
                          href={technique.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-sm font-semibold hover:underline"
                        >
                          {technique.name}
                        </a>
                      </div>
                      <ul className="space-y-1">
                        {technique.evidence.map((item) => (
                          <li key={item} className="font-mono text-[11px] text-muted-foreground break-all">
                            {item}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}
