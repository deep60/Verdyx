import type { ComponentType } from "react";
import { useQuery } from "@tanstack/react-query";

type Provider = "google" | "github";

const LABELS: Record<Provider, string> = {
  google: "Google",
  github: "GitHub",
};

function GoogleIcon() {
  return (
    <svg viewBox="0 0 24 24" className="mr-2 h-4 w-4" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M23.5 12.27c0-.85-.08-1.67-.22-2.45H12v4.63h6.45a5.52 5.52 0 0 1-2.4 3.62v3h3.88c2.27-2.09 3.57-5.17 3.57-8.8Z"
      />
      <path
        fill="#34A853"
        d="M12 24c3.24 0 5.96-1.07 7.94-2.9l-3.88-3.02c-1.07.72-2.45 1.15-4.06 1.15-3.12 0-5.77-2.1-6.71-4.94H1.28v3.11A12 12 0 0 0 12 24Z"
      />
      <path
        fill="#FBBC05"
        d="M5.29 14.29a7.2 7.2 0 0 1 0-4.58V6.6H1.28a12 12 0 0 0 0 10.8l4.01-3.11Z"
      />
      <path
        fill="#EA4335"
        d="M12 4.77c1.76 0 3.34.6 4.58 1.8l3.44-3.44A11.5 11.5 0 0 0 12 0 12 12 0 0 0 1.28 6.6l4.01 3.11C6.23 6.87 8.88 4.77 12 4.77Z"
      />
    </svg>
  );
}

function GithubIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="mr-2 h-4 w-4"
      aria-hidden="true"
      fill="currentColor"
    >
      <path d="M12 .3a12 12 0 0 0-3.8 23.38c.6.12.83-.26.83-.58v-2.03c-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.2.08 1.84 1.24 1.84 1.24 1.07 1.83 2.81 1.3 3.5 1 .1-.78.42-1.31.76-1.61-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.13-.3-.54-1.52.12-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.28-1.55 3.29-1.23 3.29-1.23.66 1.66.25 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.62-5.48 5.92.43.37.82 1.1.82 2.22v3.29c0 .32.21.7.82.58A12 12 0 0 0 12 .3Z" />
    </svg>
  );
}

const ICONS: Record<Provider, ComponentType> = {
  google: GoogleIcon,
  github: GithubIcon,
};

/**
 * "Continue with Google / GitHub". Shows only the providers the API has
 * configured, so nothing appears until the client ids and secrets are set.
 * The links are full-page navigations: the API redirects to the provider
 * and back, then sets the session cookies and lands on the dashboard.
 */
export function OAuthButtons() {
  const { data } = useQuery<{ data?: { providers?: string[] } }>({
    queryKey: ["/api/v1/auth/oauth/providers"],
    retry: false,
  });
  const providers = (data?.data?.providers ?? []).filter(
    (p): p is Provider => p === "google" || p === "github",
  );
  if (providers.length === 0) return null;

  return (
    <div className="grid gap-2">
      <div className="relative my-1">
        <div className="absolute inset-0 flex items-center">
          <span className="w-full border-t border-border" />
        </div>
        <div className="relative flex justify-center text-xs uppercase">
          <span className="bg-card px-2 text-muted-foreground">Or continue with</span>
        </div>
      </div>
      {providers.map((p) => {
        const Icon = ICONS[p];
        return (
          <a
            key={p}
            href={`/api/v1/auth/oauth/${p}`}
            className="inline-flex h-10 w-full items-center justify-center rounded-md border border-primary/20 bg-background px-4 text-sm font-medium transition-colors hover:border-primary/40 hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <Icon />
            Continue with {LABELS[p]}
          </a>
        );
      })}
    </div>
  );
}
