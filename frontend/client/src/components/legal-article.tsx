import type { ReactNode } from "react";
import { LEGAL_UPDATED } from "@/components/legal-content";

/**
 * The legal text itself, with no app context, so it renders the same inside the
 * app and in the static HTML written by `scripts/prerender-legal.mjs`.
 */
export function LegalArticle({ title, intro, children }: { title: string; intro: ReactNode; children: ReactNode }) {
  return (
    <article className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8">
      <h1 className="text-3xl font-medium tracking-[-0.035em] text-foreground sm:text-5xl">{title}</h1>
      <p className="mt-3 font-mono text-xs text-muted-foreground">Last updated {LEGAL_UPDATED}</p>
      <div className="mt-6 text-base leading-relaxed">{intro}</div>
      <div className="mt-10 space-y-10 text-sm leading-relaxed [&_a]:text-foreground [&_a]:underline [&_a]:underline-offset-4 [&_code]:font-mono [&_code]:text-foreground [&_h2]:mb-3 [&_h2]:text-lg [&_h2]:font-medium [&_h2]:text-foreground [&_li]:ml-5 [&_li]:list-disc [&_li]:pl-1 [&_p+p]:mt-3 [&_strong]:text-foreground [&_ul]:mt-2 [&_ul]:space-y-1.5">
        {children}
      </div>
    </article>
  );
}
