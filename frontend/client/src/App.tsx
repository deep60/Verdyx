import { Suspense, lazy } from "react";
import { Switch, Route, Redirect } from "wouter";
import { Loader2 } from "lucide-react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/contexts/auth-context";
import { ThemeProvider } from "@/contexts/theme-context";
import { NotificationProvider } from "@/components/notification-provider";
import { ProtectedRoute } from "@/components/protected-route";
import { ErrorBoundary } from "@/components/error-boundary";
import { initCsrfToken } from "@/lib/csrf";

// Eagerly load the landing page for a fast first paint; lazy-load the rest so
// heavy dependencies (charts, pdf/xlsx export) stay out of the initial bundle.
import Home from "@/pages/home";
import { PlateRoom } from "@/components/plate-room";
import { CommandPalette } from "@/components/command-palette";

const Dashboard = lazy(() => import("@/pages/dashboard"));
const Marketplace = lazy(() => import("@/pages/marketplace"));
const ApiDocs = lazy(() => import("@/pages/api-docs"));
const Login = lazy(() => import("@/pages/login"));
const Register = lazy(() => import("@/pages/register"));
const Profile = lazy(() => import("@/pages/profile"));
const AnalysisDetails = lazy(() => import("@/pages/analysis-details"));
const NotFound = lazy(() => import("@/pages/not-found"));
const Pricing = lazy(() => import("@/pages/pricing"));
const ForgotPassword = lazy(() => import("@/pages/forgot-password"));
const ResetPassword = lazy(() => import("@/pages/reset-password"));

function PageLoader() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <Loader2 className="h-8 w-8 animate-spin text-primary" aria-label="Loading" />
    </div>
  );
}

function Router() {
  return (
    <Suspense fallback={<PageLoader />}>
      <PlateRoom />
      <Switch>
        <Route path="/" component={Home} />
        {/* Retired marketing pages. Home now carries the architecture, engines, and OSINT story. */}
        <Route path="/how-it-works">{<Redirect to="/#architecture" replace />}</Route>
        <Route path="/features">{<Redirect to="/#capabilities" replace />}</Route>
        <Route path="/features/engines">{<Redirect to="/#capabilities" replace />}</Route>
        <Route path="/features/consensus">{<Redirect to="/#architecture" replace />}</Route>
        <Route path="/use-cases">{<Redirect to="/#capabilities" replace />}</Route>
        <Route path="/pricing" component={Pricing} />
        <Route path="/login" component={Login} />
        <Route path="/register" component={Register} />
        <Route path="/forgot-password" component={ForgotPassword} />
        <Route path="/reset-password" component={ResetPassword} />
        <Route path="/dashboard" component={Dashboard} />
        <Route path="/marketplace" component={Marketplace} />
        <Route path="/analysis/:id" component={AnalysisDetails} />
        <Route path="/api" component={ApiDocs} />
        <Route path="/profile">
          <ProtectedRoute>
            <Profile />
          </ProtectedRoute>
        </Route>
        <Route component={NotFound} />
      </Switch>
    </Suspense>
  );
}

function App() {
  // Initialize CSRF token on app startup
  initCsrfToken();

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <AuthProvider>
            <NotificationProvider>
              <TooltipProvider>
                <div className="relative min-h-screen">
                  <Toaster />
                  <CommandPalette />
                  <Router />
                </div>
              </TooltipProvider>
            </NotificationProvider>
          </AuthProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
