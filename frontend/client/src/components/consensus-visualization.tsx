import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import { CheckCircle2, AlertTriangle, XCircle, TrendingUp } from "lucide-react";

interface ConsensusVisualizationProps {
  consensus: {
    finalVerdict: string;
    confidenceScore: string;
    totalEngines: number;
    maliciousVotes: number;
    cleanVotes: number;
    suspiciousVotes: number;
    participatingEngines?: string[];
    unavailableEngines?: Array<{ engineName: string; reason: string }>;
    explanation?: string;
    confidenceNote?: string;
  };
}

export function ConsensusVisualization({ consensus }: ConsensusVisualizationProps) {
  const { finalVerdict, confidenceScore, maliciousVotes, cleanVotes, suspiciousVotes, totalEngines } = consensus;

  // Data for pie chart
  const pieData = [
    { name: "Malicious", value: maliciousVotes, color: "hsl(var(--destructive))" },
    { name: "Clean", value: cleanVotes, color: "hsl(var(--accent))" },
    { name: "Suspicious", value: suspiciousVotes, color: "hsl(var(--warning))" },
  ].filter(item => item.value > 0);

  const getVerdictIcon = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case "malicious":
        return <XCircle className="h-8 w-8 text-destructive" />;
      case "clean":
        return <CheckCircle2 className="h-8 w-8 text-success" />;
      case "suspicious":
        return <AlertTriangle className="h-8 w-8 text-warning" />;
      default:
        return null;
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict.toLowerCase()) {
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

  const confidence = parseFloat(confidenceScore);
  const confidenceLevel = confidence >= 90 ? "Very High" : confidence >= 75 ? "High" : confidence >= 60 ? "Medium" : "Low";

  return (
    <div className="space-y-6">
      {/* Main Verdict Card */}
      <Card className="glassmorphism neon-border">
        <CardHeader>
          <CardTitle className="text-2xl">Consensus Result</CardTitle>
          <CardDescription>Aggregated verdict from {totalEngines} security engines</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col md:flex-row items-center justify-between gap-8">
            {/* Verdict Display */}
            <div className="flex items-center gap-4">
              {getVerdictIcon(finalVerdict)}
              <div>
                <div className="text-sm text-muted-foreground mb-2">Final Verdict</div>
                <Badge
                  variant={getVerdictColor(finalVerdict) as "default" | "secondary" | "destructive" | "outline"}
                  className="text-xl px-6 py-2 capitalize"
                >
                  {finalVerdict}
                </Badge>
              </div>
            </div>

            {/* Confidence Score */}
            <div className="text-center">
              <div className="relative inline-flex items-center justify-center w-32 h-32">
                <svg className="w-32 h-32 transform -rotate-90">
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    className="text-muted"
                  />
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    strokeDasharray={`${2 * Math.PI * 56}`}
                    strokeDashoffset={`${2 * Math.PI * 56 * (1 - confidence / 100)}`}
                    className="text-primary transition-all duration-1000 ease-out"
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute flex flex-col items-center">
                  <span className="text-3xl font-bold text-primary">{confidenceScore}%</span>
                </div>
              </div>
              <div className="mt-2">
                <div className="text-sm font-medium">Confidence Score</div>
                <div className="text-xs text-muted-foreground">{confidenceLevel} Confidence</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid md:grid-cols-2 gap-6">
        {/* Vote Distribution Pie Chart */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Vote Distribution
            </CardTitle>
            <CardDescription>Breakdown of engine verdicts</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name}: ${value}`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
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
          </CardContent>
        </Card>

        {/* Vote Breakdown Bars */}
        <Card className="glassmorphism border-primary/20">
          <CardHeader>
            <CardTitle>Detailed Breakdown</CardTitle>
            <CardDescription>Individual verdict counts</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Malicious */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-destructive" />
                  <span className="text-sm font-medium">Malicious</span>
                </div>
                <span className="text-sm font-bold">{maliciousVotes} / {totalEngines}</span>
              </div>
              <Progress
                value={(maliciousVotes / totalEngines) * 100}
                className="h-3"
              />
              <div className="text-xs text-muted-foreground mt-1">
                {((maliciousVotes / totalEngines) * 100).toFixed(1)}%
              </div>
            </div>

            {/* Suspicious */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-warning" />
                  <span className="text-sm font-medium">Suspicious</span>
                </div>
                <span className="text-sm font-bold">{suspiciousVotes} / {totalEngines}</span>
              </div>
              <Progress
                value={(suspiciousVotes / totalEngines) * 100}
                className="h-3"
              />
              <div className="text-xs text-muted-foreground mt-1">
                {((suspiciousVotes / totalEngines) * 100).toFixed(1)}%
              </div>
            </div>

            {/* Clean */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-success" />
                  <span className="text-sm font-medium">Clean</span>
                </div>
                <span className="text-sm font-bold">{cleanVotes} / {totalEngines}</span>
              </div>
              <Progress
                value={(cleanVotes / totalEngines) * 100}
                className="h-3"
              />
              <div className="text-xs text-muted-foreground mt-1">
                {((cleanVotes / totalEngines) * 100).toFixed(1)}%
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Consensus Strength Indicator */}
      <Card className="glassmorphism border-primary/20">
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-muted-foreground mb-1">Consensus Strength</div>
              <div className="text-2xl font-bold">
                {confidence >= 90 ? "Strong" : confidence >= 75 ? "Moderate" : "Weak"} Consensus
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm text-muted-foreground mb-1">Agreement Rate</div>
              <div className="text-2xl font-bold text-primary">{confidenceScore}%</div>
            </div>
          </div>
          <Progress value={confidence} className="mt-4 h-2" />
        </CardContent>
      </Card>

      {consensus.explanation && (
        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4">
            <div className="text-xs font-semibold text-primary mb-1">Consensus Formulation Details</div>
            <p className="text-xs text-muted-foreground leading-relaxed">{consensus.explanation}</p>
          </CardContent>
        </Card>
      )}

      <p className="text-xs text-muted-foreground italic text-center">
        {consensus.confidenceNote || "Confidence reflects calibrated engine agreement concordance (0-100%), not a statistical posterior probability."}
      </p>
    </div>
  );
}
