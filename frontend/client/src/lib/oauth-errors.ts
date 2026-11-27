/** Messages for the fixed codes the API puts in `?oauth_error=` on /login. */
const OAUTH_ERRORS: Record<string, string> = {
  cancelled: "Sign-in was cancelled.",
  expired: "That sign-in link expired. Please try again.",
  two_factor:
    "This account uses two-factor authentication. Sign in with your password and code instead.",
  suspended: "This account is suspended.",
  no_email:
    "That account has no verified email address. Verify one with the provider and try again.",
  sso_required:
    "Your team signs in with single sign-on. Use \"Sign in with SSO\" and your work email.",
  unavailable: "That sign-in option isn't available right now.",
  failed: "Sign-in didn't work. Please try again.",
};

export function oauthErrorFromUrl(): string {
  if (typeof window === "undefined") return "";
  const code = new URLSearchParams(window.location.search).get("oauth_error");
  return code ? (OAUTH_ERRORS[code] ?? OAUTH_ERRORS.failed) : "";
}
