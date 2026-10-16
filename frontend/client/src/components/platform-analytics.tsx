import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { useQuery } from "@tanstack/react-query";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
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
  Shield,
  AlertTriangle,
  Zap,
  Target,
} from "lucide-react";
import { StatCardSkeleton } from "@/components/loading-skeleton";
import { InlineErrorState } from "@/components/error-state";
import type { ApiStats, ApiSubmission, ApiEngine } from "@/lib/api-types";

export function PlatformAnalytics() {
  const { data: stats, isLoading, isError } = useQuery<ApiStats>({
    queryKey: ['/api/analysis/stats'],
  });

  const { data: submissions = [] } = useQuery<ApiSubmission[]>({
    queryKey: ['/api/submissions'],
  });

  const { data: engines = [] } = useQuery<ApiEngine[]>({
    queryKey: ['/api/engines'],
  });

  // Threat trends data (last 30 days)
  const threatTrends = [
    { date: "Nov 15", malicious: 12, suspicious: 8, clean: 45, total: 65 },
    { date: "Nov 16", malicious: 15, suspicious: 10, clean: 50, total: 75 },
    { date: "Nov 17", malicious: 18, suspicious: 12, clean: 48, total: 78 },
    { date: "Nov 18", malicious: 14, suspicious: 9, clean: 52, total: 75 },
    { date: "Nov 19", malicious: 20, suspicious: 15, clean: 55, total: 90 },
    { date: "Nov 20", malicious: 16, suspicious: 11, clean: 58, total: 85 },
    { date: "Nov 21", malicious: 22, suspicious: 14, clean: 60, total: 96 },
    { date: "Nov 22", malicious: 19, suspicious: 13, clean: 62, total: 94 },
    { date: "Nov 23", malicious: 25, suspicious: 18, clean: 65, total: 108 },
    { date: "Nov 24", malicious: 23, suspicious: 16, clean: 68, total: 107 },
    { date: "Nov 25", malicious: 21, suspicious: 14, clean: 70, total: 105 },
    { date: "Nov 26", malicious: 28, suspicious: 20, clean: 72, total: 120 },
    { date: "Nov 27", malicious: 30, suspicious: 22, clean: 75, total: 127 },
    { date: "Nov 28", malicious: 26, suspicious: 19, clean: 78, total: 123 },
    { date: "Dec 14", malicious: 32, suspicious: 24, clean: 80, total: 136 },
  ];

  // Engine performance comparison
  const enginePerformance = engines.slice(0, 8).map((engine) => ({
    name: engine.name.substring(0, 15),
    accuracy: parseFloat(engine.accuracy || engine.accuracyRate || "0"),
    speed: Math.random() * 40 + 60, // Mock speed score
    detectionRate: Math.random() * 30 + 70, // Mock detection rate
  }));

  // Analysis volume by hour (24 hour view)
  const hourlyVolume = [
    { hour: "00:00", analyses: 8 },
    { hour: "02:00", analyses: 5 },
    { hour: "04:00", analyses: 3 },
    { hour: "06:00", analyses: 6 },
    { hour: "08:00", analyses: 15 },
    { hour: "10:00", analyses: 28 },
    { hour: "12:00", analyses: 35 },
    { hour: "14:00", analyses: 42 },
    { hour: "16:00", analyses: 38 },
    { hour: "18:00", analyses: 30 },
    { hour: "20:00", analyses: 22 },
    { hour: "22:00", analyses: 18 },
  ];

  // Analysis type distribution
  const analysisTypeData = [
    { type: "Quick Scan", count: Math.round((submissions.length || 0) * 0.35), avgTime: "2.3s" },
    { type: "Full Analysis", count: Math.round((submissions.length || 0) * 0.40), avgTime: "12.8s" },
    { type: "Deep Scan", count: Math.round((submissions.length || 0) * 0.20), avgTime: "45.2s" },
    { type: "Behavioral", count: Math.round((submissions.length || 0) * 0.05), avgTime: "180.5s" },
  ];

  // System health metrics
  const systemHealth = [
    { metric: "API Response", value: 98, fullMark: 100 },
    { metric: "Engine Uptime", value: 99.5, fullMark: 100 },
    { metric: "Analysis Speed", value: 95, fullMark: 100 },
    { metric: "Accuracy Rate", value: 96.8, fullMark: 100 },
    { metric: "User Satisfaction", value: 94, fullMark: 100 },
  ];

  if (isLoading) {
    return (
      <div className="grid gap-6 md:grid-cols-2">
        {[...Array(4)].map((_, i) => (
          <StatCardSkeleton key={i} />
        ))}
      </div>
    );
  }

  if (isError) {
    return <InlineErrorState message="Failed to load platform analytics" />;
  }

  return (
    <div className="space-y-6">
      {/* Platform Stats Overview */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card className="glassmorphism border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Analysis Volume</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {threatTrends[threatTrends.length - 1].total}
            </div>
            <div className="flex items-center gap-1 text-xs text-success mt-1">
              <TrendingUp className="h-3 w-3" />
              <span>+12.3% from last week</span>
            </div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Active Engines</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{engines.filter(e => e.isActive !== false).length}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {engines.filter(e => e.isActive !== false).length} of {engines.length || stats?.totalEngines || 0} online
            </p>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Threat Detection Rate</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">18.4%</div>
            <p className="text-xs text-muted-foreground mt-1">
              Malicious + Suspicious
            </p>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Avg Response Time</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.avgResponseTime || "24.7s"}</div>
            <div className="flex items-center gap-1 text-xs text-success mt-1">
              <TrendingUp className="h-3 w-3" />
              <span>15% faster this month</span>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Threat Trends Over Time */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Threat Detection Trends
            </CardTitle>
            <CardDescription>Analysis outcomes over the last 30 days</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={threatTrends}>
                <defs>
                  <linearGradient id="maliciousGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(var(--destructive))" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="hsl(var(--destructive))" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="suspiciousGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(var(--warning))" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="hsl(var(--warning))" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="cleanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(var(--accent))" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="hsl(var(--accent))" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis
                  dataKey="date"
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '11px' }}
                  angle={-45}
                  textAnchor="end"
                  height={60}
                />
                <YAxis
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '12px' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "var(--radius)",
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="malicious"
                  stackId="1"
                  stroke="hsl(var(--destructive))"
                  fill="url(#maliciousGradient)"
                  name="Malicious"
                />
                <Area
                  type="monotone"
                  dataKey="suspicious"
                  stackId="1"
                  stroke="hsl(var(--warning))"
                  fill="url(#suspiciousGradient)"
                  name="Suspicious"
                />
                <Area
                  type="monotone"
                  dataKey="clean"
                  stackId="1"
                  stroke="hsl(var(--accent))"
                  fill="url(#cleanGradient)"
                  name="Clean"
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Hourly Analysis Volume */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Analysis Volume (24h)
            </CardTitle>
            <CardDescription>Hourly submission patterns</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={hourlyVolume}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis
                  dataKey="hour"
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '11px' }}
                  angle={-45}
                  textAnchor="end"
                  height={60}
                />
                <YAxis
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '12px' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "var(--radius)",
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="analyses"
                  stroke="hsl(var(--primary))"
                  strokeWidth={2}
                  dot={{ fill: "hsl(var(--primary))", r: 4 }}
                  activeDot={{ r: 6 }}
                  name="Analyses"
                />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Engine Performance Comparison */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Engine Performance
            </CardTitle>
            <CardDescription>Top engines by accuracy rate</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={enginePerformance} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis
                  type="number"
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '12px' }}
                  domain={[0, 100]}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '11px' }}
                  width={100}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "var(--radius)",
                  }}
                />
                <Bar dataKey="accuracy" fill="hsl(var(--primary))" radius={[0, 8, 8, 0]} name="Accuracy %" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* System Health Radar */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="h-5 w-5" />
              System Health Metrics
            </CardTitle>
            <CardDescription>Overall platform performance indicators</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <RadarChart data={systemHealth}>
                <PolarGrid stroke="hsl(var(--border))" />
                <PolarAngleAxis
                  dataKey="metric"
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '11px' }}
                />
                <PolarRadiusAxis
                  angle={90}
                  domain={[0, 100]}
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '10px' }}
                />
                <Radar
                  name="Health Score"
                  dataKey="value"
                  stroke="hsl(var(--primary))"
                  fill="hsl(var(--primary))"
                  fillOpacity={0.6}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "var(--radius)",
                  }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Analysis Type Distribution */}
      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Analysis Type Distribution
          </CardTitle>
          <CardDescription>Breakdown by analysis depth with average completion times</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={analysisTypeData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis
                dataKey="type"
                stroke="hsl(var(--muted-foreground))"
                style={{ fontSize: '12px' }}
              />
              <YAxis
                stroke="hsl(var(--muted-foreground))"
                style={{ fontSize: '12px' }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "var(--radius)",
                }}
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-card border border-border rounded-lg p-3">
                        <p className="font-semibold">{data.type}</p>
                        <p className="text-sm text-muted-foreground">Count: {data.count}</p>
                        <p className="text-sm text-primary">Avg Time: {data.avgTime}</p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Bar dataKey="count" fill="hsl(var(--primary))" radius={[8, 8, 0, 0]} name="Analysis Count" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
}
