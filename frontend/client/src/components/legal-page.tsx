import type { ReactNode } from "react";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { SEO } from "@/components/seo";

/** Where privacy and terms questions go. Change it here and both pages follow. */
export const LEGAL_CONTACT_EMAIL = "privacy@verdyx.dev";

/** Date the current text took effect. Bump it whenever the wording changes. */
export const LEGAL_UPDATED = "14 November 2026";

export function LegalPage({
  title,
  description,
  intro,
  children,
}: {
  title: string;
  description: string;
  intro: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="min-h-screen bg-background text-muted-foreground font-sans selection:bg-primary/30">
      <SEO title={title} description={description} />
      <Navigation />
      <main id="main-content" tabIndex={-1} className="pb-20 pt-12 sm:pt-16">
        <article className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8">
          <h1 className="text-3xl font-medium tracking-[-0.035em] text-foreground sm:text-5xl">{title}</h1>
          <p className="mt-3 font-mono text-xs text-muted-foreground">Last updated {LEGAL_UPDATED}</p>
          <div className="mt-6 text-base leading-relaxed">{intro}</div>
          <div className="mt-10 space-y-10 text-sm leading-relaxed [&_a]:text-foreground [&_a]:underline [&_a]:underline-offset-4 [&_h2]:mb-3 [&_h2]:text-lg [&_h2]:font-medium [&_h2]:text-foreground [&_li]:ml-5 [&_li]:list-disc [&_li]:pl-1 [&_ul]:mt-2 [&_ul]:space-y-1.5 [&_p+p]:mt-3">
            {children}
          </div>
        </article>
      </main>
      <Footer tag="legal" />
    </div>
  );
}

export function ContactLink() {
  return <a href={`mailto:${LEGAL_CONTACT_EMAIL}`}>{LEGAL_CONTACT_EMAIL}</a>;
}
