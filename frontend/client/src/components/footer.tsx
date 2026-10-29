import { VerdyxLogo } from "@/components/verdyx-logo";
import { Link } from "wouter";
import { ArrowUp } from "lucide-react";
import { Button } from "@/components/ui/button";

interface FooterProps {
  tag?: string;
}

const footerSections = [
  {
    title: "Platform",
    links: [
      { href: "/dashboard", label: "Analysis Dashboard" },
      { href: "/marketplace", label: "Bounty Marketplace" },
      { href: "/#architecture", label: "Architecture & Pipeline" },
      { href: "/pricing", label: "Pricing & Tiers" },
    ],
  },
  {
    title: "Capabilities",
    links: [
      { href: "/#capabilities", label: "8-Engine Malware Sandbox" },
      { href: "/#architecture", label: "Bayesian Consensus" },
      { href: "/marketplace", label: "Security Engines" },
      { href: "/#capabilities", label: "Enterprise Use Cases" },
    ],
  },
  {
    title: "Developers",
    links: [
      { href: "/api", label: "REST & WebSocket API" },
      { href: "/api-docs", label: "API Reference & Keys" },
      { href: "/login", label: "Analyst Sign In" },
      { href: "/register", label: "Register Node" },
    ],
  },
];

export function Footer({ tag = "commit · reveal" }: FooterProps) {
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <footer className="relative mt-auto border-t border-border bg-background">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-14 pb-10">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-12 pb-12 border-b border-border">
          <div className="lg:col-span-5 space-y-4">
            <Link href="/" className="inline-flex items-center gap-2.5">
              <VerdyxLogo size={38} textClassName="text-xl" showSubtitle />
            </Link>

            <p className="text-sm text-muted-foreground max-w-sm leading-relaxed">
              Eight engines on one file. Each vote is sealed, then opened with the quorum.
            </p>

            <p className="font-mono text-xs text-muted-foreground">{tag}</p>
          </div>

          {/* Navigation Columns (6 cols) */}
          <div className="sm:col-span-2 lg:col-span-6 grid grid-cols-2 sm:grid-cols-3 gap-8">
            {footerSections.map((section) => (
              <div key={section.title} className="space-y-3">
                <div className="text-xs font-mono uppercase tracking-widest text-foreground font-bold">
                  {section.title}
                </div>
                <ul className="space-y-2.5">
                  {section.links.map((link) => (
                    <li key={link.href}>
                      <Link
                        href={link.href}
                        className="text-sm text-muted-foreground hover:text-primary transition-colors inline-flex items-center gap-1 group"
                      >
                        <span className="group-hover:translate-x-0.5 transition-transform">
                          {link.label}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Back to Top Column (1 col) */}
          <div className="lg:col-span-1 flex sm:justify-end items-start">
            <Button
              variant="outline"
              size="icon"
              onClick={scrollToTop}
              className="border-border"
              aria-label="Back to top"
            >
              <ArrowUp className="h-4 w-4" />
            </Button>
          </div>
        </div>

        <div className="pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-muted-foreground">
          <p className="font-mono">Eight engines · thirty-six checks · one verdict</p>
          <p className="font-mono">© {new Date().getFullYear()} Verdyx Labs</p>
        </div>
      </div>
    </footer>
  );
}
