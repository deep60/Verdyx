import { useEffect, useState } from "react";
import { Link } from "wouter";
import { useAuth } from "@/contexts/auth-context";
import { Navigation } from "@/components/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { User, Mail } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { UserAnalyticsDashboard } from "@/components/user-analytics-dashboard";
import { WebhooksManager } from "@/components/webhooks-manager";
import { ApiKeysManager } from "@/components/api-keys-manager";
import { AuditLog } from "@/components/audit-log";
import { DataControls } from "@/components/data-controls";
import { ThreatFeedCard } from "@/components/threat-feed-card";
import { SEO } from "@/components/seo";
import {
  ActivityGrid,
  LatestCatch,
  ProfileHero,
  ProfileStats,
  SubmissionList,
} from "@/components/analyst-profile";
import type { ApiSubmission } from "@/lib/api-types";
import { amount, findStanding, latestCatch, scanCounts, type Standing } from "@/lib/profile";

interface MyStats {
  total_bounties_participated?: number;
  total_rewards_earned?: string;
}

const TABS = ["overview", "submissions", "rewards", "developer", "account"] as const;
type Tab = (typeof TABS)[number];

function tabFromHash(): Tab {
  if (typeof window === "undefined") return "overview";
  const h = window.location.hash.replace("#", "");
  return (TABS as readonly string[]).includes(h) ? (h as Tab) : "overview";
}

export default function Profile() {
  const { user, connectWallet, disconnectWallet, updateProfile, deleteAccount, logout } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [username, setUsername] = useState(user?.username ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  // The tab lives in the address (#submissions), so it survives a reload and can be linked.
  const [tab, setTab] = useState<Tab>(tabFromHash);
  useEffect(() => {
    const onHash = () => setTab(tabFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const changeTab = (next: string) => {
    setTab(next as Tab);
    window.history.replaceState(null, "", next === "overview" ? window.location.pathname : `#${next}`);
  };

  const { data: submissions, isLoading: loadingScans } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
    enabled: !!user,
  });
  const { data: standings } = useQuery<{ analysts?: Standing[] }>({
    queryKey: ["/api/reputation/standings"],
    enabled: !!user,
  });
  const { data: stats } = useQuery<MyStats>({
    queryKey: ["/api/users/me/stats"],
    enabled: !!user,
  });

  if (!user) {
    return null;
  }

  const mine = (submissions ?? []).filter((s) => (s.submitterId || s.userId) === user.id);
  const counts = scanCounts(mine);
  const standing = findStanding(standings?.analysts, user.id);
  const rank = standing ? { rank: standing.rank, of: standing.of } : null;
  const accuracyRaw = amount(standing?.standing.accuracyRate);
  // The reputation service reports accuracy as 0..1 or 0..100.
  const accuracy = accuracyRaw === null ? null : accuracyRaw <= 1 ? accuracyRaw * 100 : accuracyRaw;
  const rewards = amount(stats?.total_rewards_earned) ?? amount(user.totalEarnings);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO
        title="Analyst profile — Verdyx"
        description="Your Verdyx analyst profile: scans, threats caught, reputation, rewards, API keys and webhooks."
      />
      <Navigation />

      <div id="main-content" tabIndex={-1} className="relative z-10 mx-auto max-w-6xl space-y-6 px-4 py-10 sm:px-6 lg:px-8">
        <ProfileHero
          username={user.username}
          email={user.email}
          createdAt={user.createdAt}
          walletAddress={user.walletAddress}
          rank={rank}
          onConnectWallet={connectWallet}
        />

        <Tabs value={tab} onValueChange={changeTab} className="space-y-6">
          <TabsList className="h-auto w-full justify-start gap-1 overflow-x-auto p-1 sm:w-auto">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="submissions" data-testid="tab-profile-submissions">
              Submissions
              <span className="ml-1.5 rounded bg-muted px-1.5 text-[11px] tabular-nums text-muted-foreground">
                {counts.total}
              </span>
            </TabsTrigger>
            <TabsTrigger value="rewards" data-testid="tab-profile-wallet">Rewards</TabsTrigger>
            <TabsTrigger value="developer" data-testid="tab-profile-api-keys">API and webhooks</TabsTrigger>
            <TabsTrigger value="account">Account</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            <ProfileStats
              counts={counts}
              reputation={user.reputationScore}
              rank={rank}
              accuracy={accuracy}
              rewards={rewards}
              bountiesJoined={stats?.total_bounties_participated ?? null}
              loading={loadingScans}
            />
            <div className="grid gap-6 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <ActivityGrid submissions={mine} />
              </div>
              <LatestCatch scan={latestCatch(mine)} />
            </div>
            <SubmissionList
              submissions={mine}
              limit={6}
              title="Recent submissions"
              onShowAll={() => changeTab("submissions")}
            />
          </TabsContent>

          {/* Submissions Tab */}
          <TabsContent value="submissions" className="space-y-6">
            <SubmissionList submissions={mine} />
          </TabsContent>

          {/* Rewards Tab */}
          <TabsContent value="rewards" className="space-y-6">
            <Card data-testid="card-profile-wallet" className="glassmorphism border-primary/20">
              <CardHeader>
                <CardTitle>Wallet and rewards</CardTitle>
                <CardDescription>
                  Your THREAT, stakes and rewards are held by the contracts on the chain, not by
                  Verdyx. You sign every transfer in your own wallet.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                {user.walletAddress ? (
                  <div className="flex flex-wrap items-center gap-3">
                    <code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1 text-xs">
                      {user.walletAddress}
                    </code>
                    <Button variant="outline" size="sm" onClick={disconnectWallet}>
                      Disconnect wallet
                    </Button>
                  </div>
                ) : (
                  <Button variant="outline" onClick={connectWallet}>
                    Connect wallet
                  </Button>
                )}
                <p className="text-muted-foreground">
                  On the marketplace you can see your balance, claim test THREAT, post bounties,
                  stake on a verdict and withdraw what you have won.
                </p>
                <Button asChild>
                  <Link href="/marketplace" data-testid="link-profile-marketplace">
                    Open the marketplace
                  </Link>
                </Button>
              </CardContent>
            </Card>
            <UserAnalyticsDashboard />
          </TabsContent>

          {/* Developer Tab */}
          <TabsContent value="developer" className="space-y-6">
            <ApiKeysManager />
            <WebhooksManager />
            <ThreatFeedCard />
          </TabsContent>

              {/* Account Tab */}
              <TabsContent value="account" className="space-y-6">
                <Card className="glassmorphism border-primary/20">
                  <CardHeader>
                    <CardTitle>Profile Settings</CardTitle>
                    <CardDescription>Update your account information</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="settings-username">Username</Label>
                      <div className="relative">
                        <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="settings-username"
                          value={username}
                          onChange={(e) => setUsername(e.target.value)}
                          className="pl-10"
                          disabled={!isEditing || saving}
                        />
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="settings-email">Email</Label>
                      <div className="relative">
                        <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="settings-email"
                          type="email"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          className="pl-10"
                          disabled={!isEditing || saving}
                        />
                      </div>
                    </div>

                    <div className="flex gap-3 pt-4">
                      {isEditing ? (
                        <>
                          <Button
                            onClick={async () => {
                              setSaving(true);
                              try {
                                await updateProfile({ username, email });
                                setIsEditing(false);
                              } catch (err) {
                                setUsername(user.username);
                                setEmail(user.email);
                                alert(err instanceof Error ? err.message : "Could not save profile");
                              } finally {
                                setSaving(false);
                              }
                            }}
                            className="flex-1"
                            disabled={saving}
                          >
                            {saving ? "Saving..." : "Save Changes"}
                          </Button>
                          <Button
                            variant="outline"
                            onClick={() => setIsEditing(false)}
                            className="flex-1"
                          >
                            Cancel
                          </Button>
                        </>
                      ) : (
                        <Button onClick={() => setIsEditing(true)} className="w-full">
                          Edit Profile
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>

                <DataControls />
                <AuditLog endpoint="/api/users/me/audit" personal viewerId={user.id} />

                <Card className="glassmorphism border-destructive/20">
                  <CardHeader>
                    <CardTitle className="text-destructive">Danger Zone</CardTitle>
                    <CardDescription>Irreversible account actions</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Button
                      variant="destructive"
                      className="w-full"
                      disabled={deleting}
                      onClick={async () => {
                        if (!window.confirm("Delete this account? This cannot be undone.")) {
                          return;
                        }
                        setDeleting(true);
                        try {
                          await deleteAccount();
                          logout();
                        } catch (err) {
                          alert(err instanceof Error ? err.message : "Could not delete account");
                          setDeleting(false);
                        }
                      }}
                    >
                      {deleting ? "Deleting..." : "Delete Account"}
                    </Button>
                  </CardContent>
                </Card>
              </TabsContent>
          </Tabs>
      </div>
    </div>
  );
}
