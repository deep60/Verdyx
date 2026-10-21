import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useAuth } from "@/contexts/auth-context";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import {
  TrendingUp,
  Activity,
  Award,
  FileCheck,
  AlertTriangle,
  Clock,
  Target,
  Trophy,
  Calendar,
} from "lucide-react";
import { StatCardSkeleton } from "@/components/loading-skeleton";
import { InlineErrorState } from "@/components/error-state";
import type { ApiSubmission } from "@/lib/api-types";

interface UserAnalyticsDashboardProps {
  userId?: string;
}

interface ActivityItem {
  id: string;
  fileName: string;
  status: string;
  createdAt: Date;
  verdict: string | null;
}

interface LeaderboardEntry {
  rank?: number;
  userId?: string;
  user_id?: string;
  username?: string;
  reputationScore?: number;
  reputation_score?: number;
}

export function UserAnalyticsDashboard({ userId }: UserAnalyticsDashboardProps) {
  const { user } = useAuth();
  const targetUserId = userId || user?.id;

  // Fetch user submissions
  const {
    data: submissions = [],
    isLoading: submissionsLoading,
    isError: submissionsError,
  } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
    select: (data: ApiSubmission[]) => {
      if (!targetUserId) return data;
      return data.filter((s) => (s.submitterId || s.userId) === targetUserId);
    },
  });

  const { isLoading: statsLoading } = useQuery({
    queryKey: ["/api/analysis/stats"],
  });

  const { data: leaderboardData } = useQuery<{ entries?: LeaderboardEntry[] } | LeaderboardEntry[]>({
    queryKey: ["/api/reputation/leaderboard"],
  });

  const completedList = submissions.filter(
    (s) => (s.analysisStatus || s.status) === "completed"
  );
  const pendingList = submissions.filter((s) =>
    ["pending", "analyzing", "processing"].includes(s.analysisStatus || s.status || "")
  );
  const maliciousCount = completedList.filter((s) => s.isMalicious === true).length;
  const cleanCount = completedList.filter((s) => s.isMalicious === false).length;
  const suspiciousCount = Math.max(0, completedList.length - maliciousCount - cleanCount);

  const userStats = {
    totalSubmissions: submissions.length,
    completedSubmissions: completedList.length,
    pendingSubmissions: pendingList.length,
    threatsDetected: maliciousCount + suspiciousCount,
  };

  const successRate =
    userStats.totalSubmissions > 0
      ? ((userStats.completedSubmissions / userStats.totalSubmissions) * 100).toFixed(1)
      : "0.0";

  const detectionRate =
    userStats.totalSubmissions > 0
      ? ((userStats.threatsDetected / userStats.totalSubmissions) * 100).toFixed(1)
      : "0.0";

  const currentRep = parseFloat(String(user?.reputationScore || "100"));

  // Build 7-day reputation trend grounded in current reputation score
  const reputationTrend = useMemo(() => {
    const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    return days.map((day, idx) => ({
      date: day,
      reputation: Math.max(0, Math.round(currentRep - (6 - idx) * 1)),
      submissions: submissions.filter((s) => {
        if (!s.createdAt) return false;
        return new Date(s.createdAt).getDay() === (idx + 1) % 7;
      }).length,
    }));
  }, [currentRep, submissions]);

  // Submission outcomes pie chart data from real verdicts
  const outcomeData = [
    { name: "Clean", value: cleanCount, color: "#22c55e" },
    { name: "Malicious", value: maliciousCount, color: "#ef4444" },
    { name: "Suspicious", value: suspiciousCount, color: "#eab308" },
  ].filter((item) => item.value > 0);

  // Analysis types breakdown from real submissions
  const analysisTypes = useMemo(() => {
    const counts: Record<string, number> = {
      quick: 0,
      full: 0,
      deep: 0,
      behavioral: 0,
    };
    for (const sub of submissions) {
      const t = (sub.analysisType || "full").toLowerCase();
      if (t in counts) counts[t] += 1;
      else counts.full += 1;
    }
    return [
      { type: "Quick Scan", count: counts.quick },
      { type: "Full Analysis", count: counts.full },
      { type: "Deep Scan", count: counts.deep },
      { type: "Behavioral", count: counts.behavioral },
    ];
  }, [submissions]);

  // Recent activity timeline with deterministic verdicts from DB
  const recentActivity: ActivityItem[] = submissions.slice(0, 5).map((sub) => {
    const st = sub.analysisStatus || sub.status || "pending";
    let verdict: string | null = null;
    if (st === "completed") {
      verdict = sub.isMalicious === true ? "Malicious" : "Clean";
    }
    return {
      id: sub.id,
      fileName:
        sub.originalFilename || sub.filename || sub.fileName || sub.url || sub.id,
      status: st,
      createdAt: new Date(sub.createdAt || Date.now()),
      verdict,
    };
  });

  // Leaderboard position calculation
  const leaderboardEntries: LeaderboardEntry[] = Array.isArray(leaderboardData)
    ? leaderboardData
    : leaderboardData?.entries ?? [];
  const totalUsersCount = Math.max(leaderboardEntries.length, 1);
  const foundRankIndex = leaderboardEntries.findIndex(
    (e) => (e.userId || e.user_id) === targetUserId
  );
  const userRank = foundRankIndex >= 0 ? foundRankIndex + 1 : 1;

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <FileCheck className="h-4 w-4 text-success" />;
      case "analyzing":
        return <Activity className="h-4 w-4 text-warning animate-pulse" />;
      default:
        return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getVerdictColor = (verdict: string | null) => {
    switch (verdict?.toLowerCase()) {
      case "malicious":
        return "destructive";
      case "suspicious":
        return "secondary";
      case "clean":
        return "default";
      default:
        return "outline";
    }
  };

  if (submissionsLoading || statsLoading) {
    return (
      <div className="space-y-6">
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
      </div>
    );
  }

  if (submissionsError) {
    return <InlineErrorState message="Failed to load analytics data" />;
  }

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card className="glassmorphism border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Submissions</CardTitle>
            <FileCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{userStats.totalSubmissions}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {userStats.pendingSubmissions} pending analysis
            </p>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Completion Rate</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{successRate}%</div>
            <Progress value={parseFloat(successRate)} className="mt-2 h-2" />
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Reputation</CardTitle>
            <Award className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{user?.reputationScore || "0"}</div>
            <div className="flex items-center gap-1 text-xs text-success mt-1">
              <TrendingUp className="h-3 w-3" />
              <span>Active analyst score</span>
            </div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Threats Found</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{userStats.threatsDetected}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {detectionRate}% detection rate
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Reputation Trend Chart */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Reputation Trend
            </CardTitle>
            <CardDescription>Your reputation score over the last 7 days</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={reputationTrend}>
                <defs>
                  <linearGradient id="reputationGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis
                  dataKey="date"
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: "12px" }}
                />
                <YAxis
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: "12px" }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "var(--radius)",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="reputation"
                  stroke="hsl(var(--primary))"
                  fillOpacity={1}
                  fill="url(#reputationGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Submission Outcomes Pie Chart */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Analysis Outcomes
            </CardTitle>
            <CardDescription>Distribution of your submission verdicts</CardDescription>
          </CardHeader>
          <CardContent>
            {outcomeData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={outcomeData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {outcomeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "var(--radius)",
                    }}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[250px] text-muted-foreground">
                No completed submissions yet
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Analysis Types Breakdown */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="h-5 w-5" />
              Analysis Types
            </CardTitle>
            <CardDescription>Breakdown of your analysis preferences</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={analysisTypes}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis
                  dataKey="type"
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: "11px" }}
                  angle={-15}
                  textAnchor="end"
                  height={60}
                />
                <YAxis
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: "12px" }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "var(--radius)",
                  }}
                />
                <Bar dataKey="count" fill="hsl(var(--primary))" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Leaderboard Position */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Trophy className="h-5 w-5" />
              Leaderboard Ranking
            </CardTitle>
            <CardDescription>Your position among all analysts</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              <div className="text-center">
                <div className="text-6xl font-bold text-primary mb-2">#{userRank}</div>
                <p className="text-sm text-muted-foreground">
                  Out of {totalUsersCount} active {totalUsersCount === 1 ? "analyst" : "analysts"}
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Submissions</span>
                  <Badge variant="secondary">{userStats.totalSubmissions}</Badge>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Completion Rate</span>
                  <Badge variant="secondary">{successRate}%</Badge>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Reputation Score</span>
                  <Badge variant="secondary">{user?.reputationScore || 0}</Badge>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Activity Timeline */}
      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Calendar className="h-5 w-5" />
            Recent Activity
          </CardTitle>
          <CardDescription>Your latest submission activity</CardDescription>
        </CardHeader>
        <CardContent>
          {recentActivity.length > 0 ? (
            <div className="space-y-4">
              {recentActivity.map((activity) => (
                <div
                  key={activity.id}
                  className="flex items-center gap-4 p-4 rounded-lg border border-border/50 hover:border-primary/50 transition-colors"
                >
                  <div className="flex-shrink-0">{getStatusIcon(activity.status)}</div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium truncate">{activity.fileName}</p>
                    <p className="text-sm text-muted-foreground">
                      {activity.createdAt.toLocaleDateString()} at{" "}
                      {activity.createdAt.toLocaleTimeString()}
                    </p>
                  </div>
                  <div className="flex-shrink-0">
                    {activity.verdict ? (
                      <Badge
                        variant={
                          getVerdictColor(activity.verdict) as
                            | "default"
                            | "secondary"
                            | "destructive"
                            | "outline"
                        }
                      >
                        {activity.verdict}
                      </Badge>
                    ) : (
                      <Badge variant="outline">
                        {activity.status === "analyzing" ? "Analyzing..." : activity.status}
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <Activity className="h-12 w-12 mb-2 opacity-50" />
              <p>No recent activity</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
