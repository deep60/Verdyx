/**
 * Server-side entry used only at build time by `scripts/prerender-legal.mjs`.
 * Renders the privacy policy and terms to static markup.
 */
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { LegalArticle } from "@/components/legal-article";
import {
  PRIVACY_META,
  PrivacyContent,
  PrivacyIntro,
  TERMS_META,
  TermsContent,
  TermsIntro,
} from "@/components/legal-content";

export interface PrerenderedPage {
  path: string;
  title: string;
  description: string;
  html: string;
}

function page(path: string, meta: { title: string; description: string }, body: ReactElement): PrerenderedPage {
  const html = renderToStaticMarkup(
    <main id="main-content" className="pb-20 pt-12 sm:pt-16">
      <nav className="mx-auto mb-8 max-w-3xl px-4 font-mono text-xs sm:px-6 lg:px-8">
        <a href="/" className="underline underline-offset-4">
          Verdyx
        </a>
      </nav>
      {body}
    </main>,
  );
  return { path, ...meta, html };
}

export function renderLegalPages(): PrerenderedPage[] {
  return [
    page(
      "privacy",
      PRIVACY_META,
      <LegalArticle title={PRIVACY_META.title} intro={<PrivacyIntro />}>
        <PrivacyContent />
      </LegalArticle>,
    ),
    page(
      "terms",
      TERMS_META,
      <LegalArticle title={TERMS_META.title} intro={<TermsIntro />}>
        <TermsContent />
      </LegalArticle>,
    ),
  ];
}
