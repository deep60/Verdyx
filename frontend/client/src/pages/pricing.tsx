import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { KineticText } from "@/components/motion/kinetic-text";
import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { SEO } from "@/components/seo";

export default function Pricing() {
  return (
    <div className="min-h-screen bg-background text-muted-foreground font-sans selection:bg-primary/30">
      <SEO 
        title="Transparent Pricing" 
        description="Pay-as-you-go API credits for developers and enterprise volume tiers for SOCs. Zero hidden fees."
      />
      <Navigation />
      
      <main id="main-content" tabIndex={-1} className="pt-32 pb-24">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-20 max-w-3xl mx-auto animate-fade-up">
            <span className="inline-block text-xs font-medium uppercase tracking-widest text-primary mb-4">Pricing</span>
            <h1 className="text-4xl md:text-6xl font-bold font-display text-foreground tracking-[-0.03em] mb-6">
              <KineticText text="Transparent API Pricing" />
            </h1>
            <p className="text-lg md:text-xl text-muted-foreground leading-relaxed mt-4">
              Pay strictly for the compute you consume. No required sales calls, no artificial rate limits, and zero hidden fees.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
            
            {/* Developer Tier - Pay As You Go */}
            <div className="bg-card/50 border border-border rounded-2xl p-8 hover:border-primary/40 transition-colors relative h-full flex flex-col">
              <div className="mb-8">
                <div className="inline-flex px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-medium mb-4">Pay As You Go</div>
                <h2 className="text-3xl font-bold text-foreground mb-2 font-display">Developer</h2>
                <div className="flex items-baseline gap-1 mt-4">
                  <span className="text-4xl font-bold text-foreground">$0.005</span>
                  <span className="text-muted-foreground font-mono text-sm">/ analysis</span>
                </div>
                <p className="text-muted-foreground mt-4 text-sm leading-relaxed">
                  Perfect for independent researchers, hobbyists, or CI/CD pipelines at small scale. 
                </p>
              </div>
              
              <ul className="space-y-4 mb-8 flex-grow">
                {[
                  "1,000 free requests per month",
                  "Access to standard YARA & ClamAV engines",
                  "Community Discord support",
                  "Max payload size: 50MB",
                  "Standard REST API access"
                ].map((feature, i) => (
                  <li key={i} className="flex gap-3 items-start">
                    <Check className="w-5 h-5 text-primary shrink-0" />
                    <span className="text-foreground/90">{feature}</span>
                  </li>
                ))}
              </ul>

              <Link href="/register">
                <Button className="w-full h-12">
                  Start Building
                </Button>
              </Link>
            </div>

            {/* Enterprise Tier */}
            <div className="border-gradient rounded-2xl p-8 relative glow-effect h-full flex flex-col">
              <div className="absolute top-0 right-0 transform translate-x-2 -translate-y-2">
                 <span className="bg-gradient-brand text-white text-xs font-semibold px-3 py-1 rounded-tl-lg rounded-br-lg shadow-lg">PRODUCTION READY</span>
              </div>
              
              <div className="mb-8">
                <h2 className="text-3xl font-bold text-foreground mb-2 font-display">Enterprise</h2>
                <div className="flex items-baseline gap-1 mt-4">
                  <span className="text-4xl font-bold text-foreground">Custom Volume</span>
                </div>
                <p className="text-muted-foreground mt-4 text-sm leading-relaxed">
                  For SOCs and massive CI footprints. Bring your own private nodes and engines behind the firewall.
                </p>
              </div>
              
              <ul className="space-y-4 mb-8 flex-grow">
                {[
                  "Bulk volumetric discounts (< $0.001/req)",
                  "Access to ML (ONNX) experimental engines",
                  "Deploy private scanning nodes (Bring Your Own Engine)",
                  "Sub-second gRPC stream access",
                  "SLA guarantees and direct engineer support",
                  "Unlimited payload sizes (up to local disk limit)"
                ].map((feature, i) => (
                  <li key={i} className="flex gap-3 items-start">
                    <Check className="w-5 h-5 text-accent shrink-0" />
                    <span className="text-foreground/90">{feature}</span>
                  </li>
                ))}
              </ul>

              <a href="mailto:enterprise@verdyx.io?subject=Verdyx%20Enterprise%20Inquiry">
                <Button variant="outline" className="w-full h-12">
                  Contact Sales
                </Button>
              </a>
            </div>

          </div>
        </div>
      </main>

      <Footer tag="pricing" />
    </div>
  );
}
