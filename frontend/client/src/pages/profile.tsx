import { useState } from "react";
import { useAuth } from "@/contexts/auth-context";
import { Navigation } from "@/components/navigation";
import { ParticleBackground } from "@/components/particle-background";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { User, Mail, Wallet, Shield, Award, TrendingUp, FileText, CheckCircle2, BarChart3 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { UserAnalyticsDashboard } from "@/components/user-analytics-dashboard";
import { SEO } from "@/components/seo";
import type { ApiSubmission } from "@/lib/api-types";

export default function Profile() {
  const { user, connectWallet, disconnectWallet, updateProfile, deleteAccount, logout } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [username, setUsername] = useState(user?.username ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // Fetch user submissions
  const { data: submissions } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
  });

  const userSubmissions = submissions?.filter((s) => s.userId === user?.id) || [];
  const completedAnalyses = userSubmissions.filter((s) => s.status === "completed").length;

  if (!user) {
    return null;
  }

  const initials = user.username
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO title="Profile" description="Manage your Verdyx profile, view submissions, and track your reputation." />
      <ParticleBackground />
      <Navigation />

      <div id="main-content" tabIndex={-1} className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid lg:grid-cols-3 gap-8">
          {/* Profile Sidebar */}
          <div className="lg:col-span-1">
            <Card className="glassmorphism border-primary/20">
              <CardHeader className="text-center">
                <div className="flex justify-center mb-4">
                  <Avatar className="h-24 w-24 border-2 border-primary">
                    <AvatarFallback className="text-2xl bg-gradient-to-br from-primary to-secondary">
                      {initials}
                    </AvatarFallback>
                  </Avatar>
                </div>
                <CardTitle className="text-2xl">{user.username}</CardTitle>
                <CardDescription>{user.email}</CardDescription>
                <div className="flex justify-center gap-2 mt-4">
                  <Badge variant="outline" className="border-accent/50 text-accent">
                    <Shield className="w-3 h-3 mr-1" />
                    Security Analyst
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <Separator />
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground flex items-center">
                      <Award className="w-4 h-4 mr-2" />
                      Reputation
                    </span>
                    <span className="font-semibold text-accent">{user.reputationScore}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground flex items-center">
                      <FileText className="w-4 h-4 mr-2" />
                      Submissions
                    </span>
                    <span className="font-semibold">{userSubmissions.length}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground flex items-center">
                      <CheckCircle2 className="w-4 h-4 mr-2" />
                      Completed
                    </span>
                    <span className="font-semibold text-success">{completedAnalyses}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground flex items-center">
                      <TrendingUp className="w-4 h-4 mr-2" />
                      Accuracy
                    </span>
                    <span className="font-semibold text-muted-foreground">—</span>
                  </div>
                </div>
                <Separator />
                <div className="space-y-2">
                  {user.walletAddress ? (
                    <>
                      <Label className="text-xs text-muted-foreground">Wallet Address</Label>
                      <div className="flex items-center gap-2">
                        <code className="text-xs bg-muted px-2 py-1 rounded flex-1 truncate">
                          {user.walletAddress}
                        </code>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full"
                        onClick={disconnectWallet}
                      >
                        Disconnect Wallet
                      </Button>
                    </>
                  ) : (
                    <Button
                      variant="outline"
                      className="w-full border-primary/20"
                      onClick={connectWallet}
                    >
                      <Wallet className="w-4 h-4 mr-2" />
                      Connect Wallet
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Profile Content */}
          <div className="lg:col-span-2">
            <Tabs defaultValue="overview" className="space-y-6">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="analytics">
                  <BarChart3 className="w-4 h-4 mr-2" />
                  Analytics
                </TabsTrigger>
                <TabsTrigger value="submissions">Submissions</TabsTrigger>
                <TabsTrigger value="settings">Settings</TabsTrigger>
              </TabsList>

              {/* Overview Tab */}
              <TabsContent value="overview" className="space-y-6">
                <Card className="glassmorphism border-primary/20">
                  <CardHeader>
                    <CardTitle>Activity Overview</CardTitle>
                    <CardDescription>Your recent activity on the platform</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid md:grid-cols-3 gap-6">
                      <div className="text-center p-4 bg-primary/10 rounded-lg border border-primary/20">
                        <div className="text-3xl font-bold font-display tracking-tight text-primary mb-2">
                          {userSubmissions.length}
                        </div>
                        <div className="text-sm text-muted-foreground">Total Submissions</div>
                      </div>
                      <div className="text-center p-4 bg-accent/10 rounded-lg border border-accent/20">
                        <div className="text-3xl font-bold font-display tracking-tight text-accent mb-2">
                          {completedAnalyses}
                        </div>
                        <div className="text-sm text-muted-foreground">Completed Analyses</div>
                      </div>
                      <div className="text-center p-4 bg-secondary/10 rounded-lg border border-secondary/20">
                        <div className="text-3xl font-bold font-display tracking-tight text-secondary mb-2">
                          {user.reputationScore}
                        </div>
                        <div className="text-sm text-muted-foreground">Reputation Score</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="glassmorphism border-primary/20">
                  <CardHeader>
                    <CardTitle>Account Information</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Member Since</span>
                      <span className="font-medium">
                        {new Date(user.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                    <Separator />
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Account Status</span>
                      <Badge variant="outline" className="border-success text-success">
                        Active
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Analytics Tab */}
              <TabsContent value="analytics" className="space-y-6">
                <UserAnalyticsDashboard />
              </TabsContent>

              {/* Submissions Tab */}
              <TabsContent value="submissions" className="space-y-6">
                <Card className="glassmorphism border-primary/20">
                  <CardHeader>
                    <CardTitle>Your Submissions</CardTitle>
                    <CardDescription>
                      Files and URLs you've submitted for analysis
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {userSubmissions.length > 0 ? (
                      <div className="space-y-3">
                        {userSubmissions.map((submission) => (
                          <div
                            key={submission.id}
                            className="flex items-center justify-between p-3 bg-muted/20 rounded-lg border border-border"
                          >
                            <div className="flex-1">
                              <div className="font-medium">{submission.fileName}</div>
                              <div className="text-sm text-muted-foreground">
                                {new Date(submission.createdAt ?? "").toLocaleDateString()}
                              </div>
                            </div>
                            <Badge
                              variant={
                                submission.status === "completed"
                                  ? "default"
                                  : submission.status === "analyzing"
                                  ? "secondary"
                                  : "outline"
                              }
                            >
                              {submission.status}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-12">
                        <FileText className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                        <p className="text-muted-foreground">No submissions yet</p>
                        <p className="text-sm text-muted-foreground mt-2">
                          Submit your first file for analysis
                        </p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Settings Tab */}
              <TabsContent value="settings" className="space-y-6">
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
      </div>
    </div>
  );
}
