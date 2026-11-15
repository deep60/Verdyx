import type { ReactNode } from "react";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { SEO } from "@/components/seo";
import { LegalArticle } from "@/components/legal-article";

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
        <LegalArticle title={title} intro={intro}>
          {children}
        </LegalArticle>
      </main>
      <Footer tag="legal" />
    </div>
  );
}
