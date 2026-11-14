import { Link } from "wouter";
import { ContactLink, LegalPage } from "@/components/legal-page";

export default function Terms() {
  return (
    <LegalPage
      title="Terms of service"
      description="The rules for using Verdyx during its beta: what you may scan, the limits, what the results mean, and what we can't promise."
      intro={
        <p>
          These terms apply when you use verdyx.dev or its API. By using Verdyx you agree to them. Verdyx is a free beta,
          so they are short; questions go to <ContactLink />.
        </p>
      }
    >
      <section>
        <h2>Your account</h2>
        <p>
          Keep your password and API keys private; you are responsible for what is done with them. Tell us if you think
          someone else has access. One person or organisation per account, please.
        </p>
      </section>

      <section>
        <h2>What you may scan</h2>
        <ul>
          <li>Files and web addresses you are allowed to share with us for analysis.</li>
          <li>
            Malware is expected: that is what Verdyx is for. Submit it for analysis only, never to spread it or to use
            Verdyx as a place to host or hand out files.
          </li>
          <li>
            Don&apos;t submit other people&apos;s personal data, confidential documents or anything illegal to possess.
            Scans made while signed out can be opened by anyone with the link.
          </li>
        </ul>
      </section>

      <section>
        <h2>Fair use</h2>
        <p>
          Scans and website checks have limits, listed on the <Link href="/pricing">pricing page</Link>. Don&apos;t try
          to get around them, overload the service, probe it for weaknesses without permission, or use it to attack
          anyone else. We may suspend accounts or block addresses that do.
        </p>
      </section>

      <section>
        <h2>What results mean</h2>
        <p>
          Verdyx combines several detection engines, and every one of them can be wrong. A clean result does not prove a
          file or site is safe, and a flagged one does not prove it is malicious. Use the results as one input to your own
          judgement, not as the only one.
        </p>
      </section>

      <section>
        <h2>Bounties and tokens</h2>
        <p>
          Staking, bounties and wallet features run on a public test network. Test tokens have no monetary value and
          can&apos;t be exchanged for money.
        </p>
      </section>

      <section>
        <h2>No warranty</h2>
        <p>
          Verdyx is provided as is, during a beta. It may change, be unavailable, or lose data, and we don&apos;t
          guarantee any result. To the extent the law allows, we are not liable for losses that come from using it or
          relying on its results.
        </p>
      </section>

      <section>
        <h2>Your content and privacy</h2>
        <p>
          You keep the rights to what you submit. You let us store and analyse it to provide the service. How we handle
          it is described in the <Link href="/privacy">privacy policy</Link>.
        </p>
      </section>

      <section>
        <h2>Ending use</h2>
        <p>
          You can stop at any time and delete your account from your profile. We may close accounts that break these
          terms.
        </p>
      </section>

      <section>
        <h2>Changes</h2>
        <p>
          If these terms change, the new version is posted here with a new date. Continuing to use Verdyx after that
          means you accept them.
        </p>
      </section>
    </LegalPage>
  );
}
