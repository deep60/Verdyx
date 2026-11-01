import { useEffect, useMemo, useRef, useState, type PointerEvent } from "react";
import { useLocation } from "wouter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { buildIocGraph, type IocKind, type IocNode } from "@/lib/ioc-graph";
import type { ApiSubmission } from "@/lib/api-types";
import { Share2 } from "lucide-react";

const COLORS: Record<IocKind, string> = {
  artifact: "#7c3aed",
  hash: "#a78bfa",
  ip: "#22d3ee",
  asn: "#fbbf24",
  cert: "#f472b6",
  host: "#34d399",
  submission: "#fb7185",
  url: "#94a3b8",
  ports: "#60a5fa",
};

interface Point {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

export function IocGraph({
  submission,
  analyses,
  webIntel,
  submissions,
}: {
  submission: ApiSubmission;
  analyses: readonly unknown[];
  webIntel?: Record<string, unknown> | null;
  submissions: ApiSubmission[];
}) {
  const graph = useMemo(
    () => buildIocGraph({ submission, analyses, webIntel, submissions }),
    [submission, analyses, webIntel, submissions],
  );
  const points = useRef<Record<string, Point>>({});
  const drag = useRef<string | null>(null);
  const [, navigate] = useLocation();
  const [frame, setFrame] = useState(0);
  const layoutKey = graph.nodes.map((node) => node.id).join("|");

  useEffect(() => {
    const next: Record<string, Point> = {};
    graph.nodes.forEach((node, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(graph.nodes.length, 1);
      const radius = node.kind === "artifact" ? 0 : 180;
      next[node.id] = points.current[node.id] ?? {
        x: 360 + Math.cos(angle) * radius,
        y: 220 + Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
      };
    });
    points.current = next;
    let tick = 0;
    let raf = 0;
    const step = () => {
      const current = points.current;
      const ids = Object.keys(current);
      for (let i = 0; i < ids.length; i++) {
        for (let j = i + 1; j < ids.length; j++) {
          const a = current[ids[i]];
          const b = current[ids[j]];
          let dx = a.x - b.x;
          let dy = a.y - b.y;
          const dist = Math.hypot(dx, dy) || 1;
          const force = 900 / (dist * dist);
          dx = (dx / dist) * force;
          dy = (dy / dist) * force;
          a.vx += dx;
          a.vy += dy;
          b.vx -= dx;
          b.vy -= dy;
        }
      }
      for (const edge of graph.edges) {
        const a = current[edge.source];
        const b = current[edge.target];
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.hypot(dx, dy) || 1;
        const force = (dist - 140) * 0.01;
        a.vx += (dx / dist) * force;
        a.vy += (dy / dist) * force;
        b.vx -= (dx / dist) * force;
        b.vy -= (dy / dist) * force;
      }
      for (const id of ids) {
        const point = current[id];
        if (id === "artifact") {
          point.vx += (360 - point.x) * 0.02;
          point.vy += (220 - point.y) * 0.02;
        }
        if (drag.current === id) {
          point.vx = 0;
          point.vy = 0;
          continue;
        }
        point.vx *= 0.72;
        point.vy *= 0.72;
        point.x = Math.min(700, Math.max(20, point.x + point.vx));
        point.y = Math.min(400, Math.max(20, point.y + point.vy));
      }
      tick += 1;
      setFrame(tick);
      if (tick < 280) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [layoutKey, graph.edges, graph.nodes]);

  const move = (event: PointerEvent<SVGSVGElement>) => {
    if (!drag.current) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const point = points.current[drag.current];
    if (!point) return;
    point.x = ((event.clientX - rect.left) / rect.width) * 720;
    point.y = ((event.clientY - rect.top) / rect.height) * 440;
    setFrame((value) => value + 1);
  };

  return (
    <Card className="glassmorphism">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Share2 className="h-5 w-5 text-primary" />
          IOC relationship graph
        </CardTitle>
        <CardDescription>
          Links come from this scan&apos;s hash, extracted strings, resolved addresses, ASN, certificate serial, Shodan hostnames, and other submissions that share them.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {graph.nodes.length <= 1 ? (
          <p className="text-sm text-muted-foreground">
            No related infrastructure yet. A URL scan adds IPs, ASN, the certificate serial, and Shodan hostnames. A file scan adds the hash and strings the static engine extracted.
          </p>
        ) : (
          <svg
            viewBox="0 0 720 440"
            className="w-full h-[420px] rounded-lg border border-border/70 bg-background/60"
            onPointerMove={move}
            onPointerUp={() => {
              drag.current = null;
            }}
            onPointerLeave={() => {
              drag.current = null;
            }}
          >
            {graph.edges.map((edge) => {
              const a = points.current[edge.source];
              const b = points.current[edge.target];
              if (!a || !b) return null;
              return (
                <line
                  key={`${edge.source}-${edge.target}`}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke="currentColor"
                  strokeOpacity={0.35}
                />
              );
            })}
            {graph.nodes.map((node) => (
              <GraphNodeView
                key={node.id}
                node={node}
                point={points.current[node.id]}
                frame={frame}
                onDrag={(id) => {
                  drag.current = id;
                }}
                onOpen={(href) => navigate(href)}
              />
            ))}
          </svg>
        )}
        <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
          {(Object.keys(COLORS) as IocKind[]).map((kind) => (
            <span key={kind} className="inline-flex items-center gap-1">
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: COLORS[kind] }} />
              {kind}
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function GraphNodeView({
  node,
  point,
  frame,
  onDrag,
  onOpen,
}: {
  node: IocNode;
  point?: Point;
  frame: number;
  onDrag: (id: string) => void;
  onOpen: (href: string) => void;
}) {
  if (!point || frame < 0) return null;
  return (
    <g
      transform={`translate(${point.x}, ${point.y})`}
      onPointerDown={(event) => {
        event.preventDefault();
        onDrag(node.id);
      }}
      onClick={() => {
        if (node.href) onOpen(node.href);
      }}
      className="cursor-grab"
    >
      <circle r={node.kind === "artifact" ? 16 : 11} fill={COLORS[node.kind]} />
      <text y={24} textAnchor="middle" fontSize="10" fill="currentColor">
        {node.label.length > 28 ? `${node.label.slice(0, 28)}…` : node.label}
      </text>
    </g>
  );
}
