/**
 * The text of the privacy policy and terms of service.
 *
 * Kept free of router and app context (plain <a> links, no hooks) so the same
 * components render in the app and in `scripts/prerender-legal.mjs`, which
 * writes them into static HTML. Google's OAuth review and other crawlers read
 * that HTML without running JavaScript.
 */

/** Where privacy and terms questions go. Change it here and both pages follow. */
export const LEGAL_CONTACT_EMAIL = "privacy@verdyx.dev";

/** Date the current text took effect. Bump it whenever the wording changes. */
export const LEGAL_UPDATED = "16 November 2026";

export const PRIVACY_META = {
  title: "Privacy policy",
  description:
    "What Verdyx collects when you scan a file or URL or create an account, how Google and GitHub sign-in data is used, where data is stored, who else sees it, and how to delete it.",
};

export const TERMS_META = {
  title: "Terms of service",
  description:
    "The rules for using Verdyx during its beta: what you may scan, the limits, what the results mean, and what we can't promise.",
};

function ContactLink() {
  return <a href={`mailto:${LEGAL_CONTACT_EMAIL}`}>{LEGAL_CONTACT_EMAIL}</a>;
}

export function PrivacyIntro() {
  return (
    <p>
      Verdyx (verdyx.dev) scans files and web addresses for malware and phishing. This policy explains what personal
      data we collect to do that, how we use it, where it is stored, who it is shared with, and how you can delete it.
      Verdyx is in beta and run by a small team; questions go to <ContactLink />.
    </p>
  );
}

export function PrivacyContent() {
  return (
    <>
      <section>
        <h2>What we collect</h2>
        <ul>
          <li>
            <strong>Account details:</strong> your email address, the display name you give us, and a password stored
            only as an Argon2 hash.
          </li>
          <li>
            <strong>Sign-in with Google or GitHub:</strong> if you choose it, the details listed under &ldquo;Google and
            GitHub sign-in&rdquo; below.
          </li>
          <li>
            <strong>What you submit:</strong> the files and web addresses you scan, their hashes, and the results every
            engine produced.
          </li>
          <li>
            <strong>API keys and webhooks</strong> you create. API keys are stored only as SHA-256 hashes.
          </li>
          <li>
            <strong>Technical data:</strong> your IP address, used to enforce scan limits and stop abuse, and standard
            server logs (time, address requested, response status).
          </li>
        </ul>
      </section>

      <section>
        <h2>How we use it</h2>
        <ul>
          <li>To create your account, sign you in and keep you signed in.</li>
          <li>To run the scans you ask for and show you their results.</li>
          <li>To send account emails you ask for, such as password resets.</li>
          <li>To enforce limits, prevent abuse and keep the service secure.</li>
        </ul>
        <p>
          We don&apos;t sell personal data, show ads, or use it to build advertising profiles, and we don&apos;t use it
          to train AI or machine-learning models.
        </p>
      </section>

      <section>
        <h2>Google and GitHub sign-in</h2>
        <p>
          If you sign in with Google, we request only the <code>openid</code>, <code>email</code> and{" "}
          <code>profile</code> scopes. From Google we receive your email address, whether it is verified, your name and
          your Google account ID. If you sign in with GitHub, we receive your email address, name and GitHub account ID.
          We don&apos;t request or receive access to your contacts, files, repositories, mail or anything else in those
          accounts.
        </p>
        <p>
          We use this information only to create your Verdyx account and sign you in. It is stored with your account,
          is not shared with anyone else, and is not used for advertising.
        </p>
        <p>
          Verdyx&apos;s use and transfer of information received from Google APIs adheres to the{" "}
          <a href="https://developers.google.com/terms/api-services-user-data-policy">
            Google API Services User Data Policy
          </a>
          , including the Limited Use requirements.
        </p>
        <p>
          You can remove Verdyx&apos;s access at any time from your{" "}
          <a href="https://myaccount.google.com/permissions">Google account permissions</a> or your{" "}
          <a href="https://github.com/settings/applications">GitHub authorized apps</a>, and delete the data as described
          under &ldquo;Deleting your data&rdquo;.
        </p>
      </section>

      <section>
        <h2>Who can see your scans</h2>
        <p>
          Scans made while signed in are tied to your account and visible only to you. Scans made while signed out have
          no owner: anyone with the link can open the result, so don&apos;t scan anything confidential without signing
          in.
        </p>
      </section>

      <section>
        <h2>Who processes the data</h2>
        <p>We share data only with the service providers that run Verdyx, and only for that purpose:</p>
        <ul>
          <li>Oracle Cloud (India) runs the servers that analyse files.</li>
          <li>Cloudflare serves the website and stores uploaded files (R2).</li>
          <li>Neon hosts the database.</li>
          <li>Brevo sends account emails, such as password resets.</li>
          <li>
            Sentry receives error reports when something breaks: the error, the page address without its query string,
            and your browser and system type. Not your IP address, cookies, form input or files.
          </li>
          <li>Google and GitHub, only if you choose to sign in with them.</li>
          <li>
            abuse.ch (URLhaus, ThreatFox, MalwareBazaar): we send a file&apos;s hash, or the web address you scanned, to
            check it against their lists of known threats. The file itself is not sent, and no account details are.
          </li>
        </ul>
        <p>
          To check a web address, our servers visit it themselves. The site you scan sees a request from our server, not
          from you. We may disclose data if the law requires it.
        </p>
      </section>

      <section>
        <h2>How long we keep it</h2>
        <p>
          Accounts, scans, uploaded files and results are kept until you delete them. Scan-limit counters expire after a
          day. Database backups follow our provider&apos;s retention window.
        </p>
      </section>

      <section>
        <h2>Deleting your data</h2>
        <p>
          You can delete your account from your profile page. That removes your account details, including anything
          received from Google or GitHub, and the scans you made while signed in, along with their files. To remove a
          single scan, or one made while signed out, email <ContactLink /> with its link.
        </p>
      </section>

      <section>
        <h2>Cookies and browser storage</h2>
        <p>
          Verdyx uses no tracking or advertising cookies and no analytics. Signing in keeps your session in your
          browser, and signing in with Google or GitHub sets one short-lived cookie that protects that sign-in and is
          cleared when it finishes.
        </p>
      </section>

      <section>
        <h2>Security</h2>
        <p>
          Connections use HTTPS, passwords and API keys are stored hashed, and the analysis servers are reachable only
          through our API. No service is perfectly secure; if you find a problem, please tell us at <ContactLink />.
        </p>
      </section>

      <section>
        <h2>Children</h2>
        <p>Verdyx is not meant for children under 16, and we don&apos;t knowingly collect their data.</p>
      </section>

      <section>
        <h2>Changes</h2>
        <p>
          If this policy changes, the new version is posted here with a new date. Significant changes are announced on
          the site before they take effect.
        </p>
      </section>

      <section>
        <h2>Contact</h2>
        <p>
          Questions or requests about your data: <ContactLink />.
        </p>
      </section>
    </>
  );
}

export function TermsIntro() {
  return (
    <p>
      These terms apply when you use verdyx.dev or its API. By using Verdyx you agree to them. Verdyx is a free beta, so
      they are short; questions go to <ContactLink />.
    </p>
  );
}

export function TermsContent() {
  return (
    <>
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
          Scans and website checks have limits, listed on the <a href="/pricing">pricing page</a>. Don&apos;t try to get
          around them, overload the service, probe it for weaknesses without permission, or use it to attack anyone
          else. We may suspend accounts or block addresses that do.
        </p>
      </section>

      <section>
        <h2>What results mean</h2>
        <p>
          Verdyx combines several detection engines, and every one of them can be wrong. A clean result does not prove a
          file or site is safe, and a flagged one does not prove it is malicious. Use the results as one input to your
          own judgement, not as the only one.
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
          it is described in the <a href="/privacy">privacy policy</a>.
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
    </>
  );
}
