import { useState } from "react";
import { Building2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { domainOf, ssoStartPath } from "@/lib/sso";

/**
 * "Sign in with SSO": the person types their work email, and the browser
 * goes to their company's identity provider and back.
 */
export function SsoSignIn({
  initialEmail = "",
  onError,
  go = (path: string) => window.location.assign(path),
}: {
  initialEmail?: string;
  onError: (message: string) => void;
  go?: (path: string) => void;
}) {
  const [email, setEmail] = useState(initialEmail);
  const [checking, setChecking] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const domain = domainOf(email);
    if (!domain) {
      onError("Enter your work email address.");
      return;
    }
    onError("");
    setChecking(true);
    try {
      const res = await fetch(`/api/v1/auth/sso/check?domain=${encodeURIComponent(domain)}`);
      const body = res.ok ? await res.json() : null;
      if (body?.sso) {
        go(ssoStartPath(domain));
        return;
      }
      onError(`Single sign-on isn't set up for ${domain}. Sign in another way, or ask your team's admin.`);
    } catch {
      onError("Couldn't check single sign-on right now. Please try again.");
    }
    setChecking(false);
  };

  return (
    <form onSubmit={submit} className="space-y-4" data-testid="sso-form">
      <div className="space-y-2">
        <Label htmlFor="sso-email">Work email</Label>
        <div className="relative">
          <Building2 className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input
            id="sso-email"
            type="email"
            autoComplete="email"
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="pl-10"
            required
            disabled={checking}
          />
        </div>
        <p className="text-xs text-muted-foreground">
          You&apos;ll sign in with your company&apos;s identity provider, such as Okta or Microsoft Entra ID.
        </p>
      </div>
      <Button type="submit" className="w-full glow-effect" disabled={checking}>
        {checking ? "Checking…" : "Continue with SSO"}
      </Button>
    </form>
  );
}
