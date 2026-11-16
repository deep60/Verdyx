import { LegalPage } from "@/components/legal-page";
import { PRIVACY_META, PrivacyContent, PrivacyIntro } from "@/components/legal-content";

export default function Privacy() {
  return (
    <LegalPage title={PRIVACY_META.title} description={PRIVACY_META.description} intro={<PrivacyIntro />}>
      <PrivacyContent />
    </LegalPage>
  );
}
