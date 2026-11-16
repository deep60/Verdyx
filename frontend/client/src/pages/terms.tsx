import { LegalPage } from "@/components/legal-page";
import { TERMS_META, TermsContent, TermsIntro } from "@/components/legal-content";

export default function Terms() {
  return (
    <LegalPage title={TERMS_META.title} description={TERMS_META.description} intro={<TermsIntro />}>
      <TermsContent />
    </LegalPage>
  );
}
