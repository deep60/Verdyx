import { ContactLink, LegalPage } from "@/components/legal-page";

export default function Privacy() {
  return (
    <LegalPage
      title="Privacy policy"
      description="What Verdyx collects when you scan a file or URL or create an account, where it is stored, who else sees it, and how to delete it."
      intro={
        <p>
          Verdyx scans files and web addresses for malware and phishing. This page says what we collect to do that,
          where it goes, and how to remove it. Verdyx is in beta and run by a small team; questions go to{" "}
          <ContactLink />.
        </p>
      }
    >
      <section>
        <h2>What we collect</h2>
        <ul>
          <li>
            <strong className="text-foreground">Account details:</strong> your email address, the name you give us, and
            a hashed password. If you sign in with Google or GitHub, we receive your email address, name and account ID
            from them, and nothing else (no contacts, files or repositories).
          </li>
          <li>
            <strong className="text-foreground">What you submit:</strong> the files and web addresses you scan, their
            hashes, and the results every engine produced.
          </li>
          <li>
            <strong className="text-foreground">API keys and webhooks</strong> you create. We store keys only in hashed
            form.
          </li>
          <li>
            <strong className="text-foreground">Technical data:</strong> your IP address, used to enforce scan limits and
            stop abuse, and standard server logs (time, address requested, status).
          </li>
        </ul>
        <p>We don&apos;t sell your data, show ads, or use it to build advertising profiles.</p>
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
        <h2>Services that handle the data</h2>
        <ul>
          <li>Oracle Cloud (India) runs the servers that analyse files.</li>
          <li>Cloudflare serves the website and stores uploaded files (R2).</li>
          <li>Neon hosts the database.</li>
          <li>Brevo sends account emails, such as password resets.</li>
          <li>Google and GitHub, only if you choose to sign in with them.</li>
          <li>
            abuse.ch (URLhaus, ThreatFox, MalwareBazaar): we send a file&apos;s hash, or the web address you scanned, to
            check it against their lists of known threats. The file itself is not sent.
          </li>
        </ul>
        <p>
          To check a web address, our servers visit it themselves, the same way a browser would. The site you scan sees a
          request from our server, not from you.
        </p>
      </section>

      <section>
        <h2>How long we keep it</h2>
        <p>
          Accounts, scans, uploaded files and results are kept until you delete them. Scan-limit counters expire after
          a day. Database backups follow our provider&apos;s retention window.
        </p>
      </section>

      <section>
        <h2>Deleting your data</h2>
        <p>
          You can delete your account from your profile page. That removes your account details and the scans you made
          while signed in, along with their files. To remove a single scan, or one made while signed out, email{" "}
          <ContactLink /> with its link.
        </p>
      </section>

      <section>
        <h2>Cookies and browser storage</h2>
        <p>
          Verdyx uses no tracking or advertising cookies. Signing in keeps your session in your browser&apos;s local
          storage, and signing in with Google or GitHub sets one short-lived cookie that protects that sign-in and is
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
        <h2>Changes</h2>
        <p>
          If this policy changes, the new version is posted here with a new date. Significant changes are announced on
          the site before they take effect.
        </p>
      </section>
    </LegalPage>
  );
}
