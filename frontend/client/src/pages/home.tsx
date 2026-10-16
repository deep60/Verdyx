import { Navigation } from "@/components/navigation";
import { HeroCanvas } from "@/components/animations/HeroCanvas";
import { ArchitectureDiagram } from "@/components/diagrams/ArchitectureDiagram";
import { ComparisonTable } from "@/components/tables/ComparisonTable";
import { Reveal } from "@/components/motion/reveal";
import { KineticText } from "@/components/motion/kinetic-text";
import { Footer } from "@/components/footer";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { Terminal, Shield, Cpu, Zap, Code } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { SEO } from "@/components/seo";
import type { ApiStats } from "@/lib/api-types";

/**
 * Render a numeric platform metric only when the backend has supplied it.
 * Falls back to an em dash while loading rather than inventing figures, so
 * these trust-critical stats never display fabricated marketing numbers.
 */
function formatMetric(value: number | undefined): string {
  return typeof value === "number" ? value.toLocaleString() : "—";
}

export default function Home() {
  const { data: stats } = useQuery<ApiStats>({
    queryKey: ["/api/analysis/stats"],
  });

  return (
    <div className="min-h-screen bg-background text-foreground font-sans selection:bg-primary/30">
      <SEO 
        title="Decentralized Threat Intelligence" 
        description="Verifiable malware analysis, powered by consensus. The first distributed threat intelligence engine utilizing YARA, ClamAV, and ML."
      />
      <Navigation />

      {/* Hero Section */}
      <section id="main-content" tabIndex={-1} className="relative min-h-[92vh] flex items-center justify-center overflow-hidden aurora-bg">
        <div className="absolute inset-0 cyber-grid z-0" />
        <HeroCanvas />
        <div className="absolute inset-0 bg-gradient-to-b from-background/40 via-background/70 to-background z-0" />

        <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center pt-20 animate-fade-up">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs md:text-sm mb-8 backdrop-blur-sm">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full rounded-full bg-primary opacity-60 animate-ping" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
            </span>
            <span className="font-medium tracking-tight">Engine v2.0 Live &mdash; Multi-Engine Consensus</span>
          </div>

          <h1 className="text-5xl md:text-7xl lg:text-[6.4rem] font-extrabold font-display text-foreground tracking-[-0.055em] mb-8 leading-[0.92]">
            <KineticText text="Verifiable malware analysis," stagger={45} /><br />
            <Reveal as="span" className="text-gradient-brand inline-block" delay={340} y={16}>
              powered by consensus.
            </Reveal>
          </h1>

          <p className="text-lg md:text-[1.35rem] font-medium text-muted-foreground max-w-2xl mx-auto mb-10 leading-[1.55] tracking-[-0.015em]">
            The first distributed threat intelligence engine. Submit telemetry via API, let independent nodes run YARA, ClamAV, and ML engines, and receive a cryptographically backed consensus score.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 justify-center items-center">
            <Link href="/dashboard">
              <Button size="lg" variant="gradient">
                <Terminal className="w-5 h-5 mr-2.5" />
                Start Free Query
              </Button>
            </Link>
            <Link href="/api">
              <Button size="lg" variant="outline">
                <Code className="w-5 h-5 mr-2.5" />
                View API Docs
              </Button>
            </Link>
          </div>

          {/* Trust Metrics — sourced live from /api/analysis/stats; no hardcoded claims */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-px mt-24 rounded-2xl border border-border/60 bg-border/40 overflow-hidden">
            {[
              { label: "Files Analyzed", value: formatMetric(stats?.totalSubmissions) },
              { label: "Active Nodes", value: formatMetric(stats?.totalEngines) },
              { label: "Threats Detected", value: formatMetric(stats?.threatsDetected) },
              { label: "Analyses Run", value: formatMetric(stats?.totalAnalyses) }
            ].map((stat, i) => (
              <div key={i} className="flex flex-col gap-1.5 items-center py-7 bg-card/60 backdrop-blur-sm">
                <div className="text-2xl md:text-3xl font-display font-bold text-foreground">{stat.value}</div>
                <div className="text-xs text-muted-foreground uppercase tracking-widest">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works (Diagram) Section */}
      <section className="py-24 relative bg-surface/30 border-y border-border/50">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <Reveal className="text-center mb-16">
            <span className="inline-block text-xs font-medium uppercase tracking-widest text-primary mb-4">Architecture</span>
            <h2 className="text-3xl md:text-5xl font-bold font-display text-foreground tracking-tight mb-4">
              <KineticText text="Architecture Deep Dive" />
            </h2>
            <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
              A transparent pipeline replacing the black box of legacy AVs. Hover over the layers to explore the components.
            </p>
          </Reveal>
          <Reveal delay={120}>
            <ArchitectureDiagram />
          </Reveal>
        </div>
      </section>

      {/* Features Grid */}
      <section className="py-24">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <Reveal className="text-center mb-16">
            <span className="inline-block text-xs font-medium uppercase tracking-widest text-primary mb-4">Why Verdyx</span>
            <h2 className="text-3xl md:text-5xl font-bold font-display text-foreground tracking-tight mb-4">
              <KineticText text="Built for engineers who ship" />
            </h2>
            <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
              Consensus-backed detection that drops straight into your pipeline — no single vendor, no black box.
            </p>
          </Reveal>
          <div className="grid md:grid-cols-3 gap-6">
            {[
              {
                icon: Shield,
                title: "No Single Point of Failure",
                desc: "Don't trust one vendor's heuristics. We aggregate scores from YARA, ClamAV, and custom ONNX models to eliminate blind spots."
              },
              {
                icon: Zap,
                title: "Built for CI/CD",
                desc: "Sub-second gRPC and REST APIs to fail builds automatically when malware is pushed. No tedious dashboard clicks required."
              },
              {
                icon: Cpu,
                title: "Bring Your Own Engine",
                desc: "Deploy a node in your own infrastructure to run proprietary YARA rules without sharing them with the network."
              }
            ].map((Feature, idx) => (
              <Reveal key={idx} delay={idx * 120}>
                <div className="tilt-card relative h-full p-8 rounded-2xl border border-border/60 bg-card/50 hover:border-primary/40 hover:bg-card/80 group">
                  <div className="grid h-12 w-12 place-items-center rounded-xl bg-primary/10 border border-primary/20 mb-6 group-hover:bg-primary/15 transition-colors">
                    <Feature.icon className="w-6 h-6 text-primary group-hover:scale-110 transition-transform duration-300" />
                  </div>
                  <h3 className="text-xl font-bold font-display tracking-tight text-foreground mb-3">{Feature.title}</h3>
                  <p className="text-muted-foreground text-sm leading-relaxed">{Feature.desc}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* Comparison Section */}
      <section className="py-24 relative">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <Reveal>
            <ComparisonTable />
          </Reveal>
        </div>
      </section>
      
      <Footer tag="v2.0-stable" />
    </div>
  );
}
