import { VerdyxLogo } from "@/components/verdyx-logo";
import { useState } from "react";
import { Link, useLocation } from "wouter";
import { useAuth } from "@/contexts/auth-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Wallet, Mail, Lock, AlertCircle } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { SEO } from "@/components/seo";

export default function Login() {
  const [, setLocation] = useLocation();
  const { login, connectWallet } = useAuth();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  // Return the user to where they were headed before being redirected to login.
  const getRedirectTarget = () => {
    const params = new URLSearchParams(window.location.search);
    const redirect = params.get("redirect");
    return redirect ? decodeURIComponent(redirect) : "/dashboard";
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      await login(identifier, password);
      setLocation(getRedirectTarget());
    } catch (_err) {
      setError("Invalid credentials. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleWalletConnect = async () => {
    try {
      await connectWallet();
      setLocation(getRedirectTarget());
    } catch (_err) {
      setError("Failed to connect wallet. Please try again.");
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex items-center justify-center p-4 aurora-bg">
      <SEO title="Sign In" description="Sign in to your Verdyx account to start submitting and analyzing threats." />

      <Card className="w-full max-w-md glassmorphism border-primary/20 relative z-10 animate-fade-up">
        <CardHeader className="space-y-1">
          <Link href="/" className="flex justify-center items-center gap-2.5 mb-4">
            <VerdyxLogo size={42} textClassName="text-xl text-foreground" showSubtitle />
          </Link>
          <CardTitle className="text-2xl text-center font-display tracking-tight">Welcome back</CardTitle>
          <CardDescription className="text-center">
            Sign in to your account to continue
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="identifier">Email or Username</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  id="identifier"
                  type="text"
                  placeholder="you@example.com or username"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  className="pl-10"
                  required
                  disabled={isLoading}
                />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">Password</Label>
                <a href="/forgot-password" className="text-sm text-primary hover:underline">
                  Forgot password?
                </a>
              </div>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10"
                  required
                  disabled={isLoading}
                />
              </div>
            </div>

            <Button
              type="submit"
              className="w-full glow-effect"
              disabled={isLoading}
            >
              {isLoading ? "Signing in..." : "Sign in"}
            </Button>
          </form>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-border" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-card px-2 text-muted-foreground">Or continue with</span>
            </div>
          </div>

          <Button
            type="button"
            variant="outline"
            className="w-full border-primary/20 hover:border-primary/40"
            onClick={handleWalletConnect}
          >
            <Wallet className="mr-2 h-4 w-4" />
            Connect Wallet (MetaMask)
          </Button>
        </CardContent>

        <CardFooter className="flex flex-col space-y-4">
          <div className="text-sm text-center text-muted-foreground">
            Don't have an account?{" "}
            <Link href="/register" className="text-primary hover:underline font-semibold">
              Sign up
            </Link>
          </div>

          <Link href="/" className="text-sm text-muted-foreground hover:text-primary transition-colors">
            ← Back to home
          </Link>
        </CardFooter>
      </Card>
    </div>
  );
}
