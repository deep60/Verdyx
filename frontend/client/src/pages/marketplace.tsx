import { useState, useMemo } from "react";
import { Navigation } from "@/components/navigation";
import { ParticleBackground } from "@/components/particle-background";
import { EngineCard } from "@/components/engine-card";
import { BountyCard } from "@/components/bounty-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import { EngineCardSkeleton, BountyCardSkeleton } from "@/components/loading-skeleton";
import { ErrorState } from "@/components/error-state";
import { EmptyState } from "@/components/empty-state";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { PlusCircle, Info, Search, FileX, Shield } from "lucide-react";
import { SEO } from "@/components/seo";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/auth-context";
import { useLocation } from "wouter";
import type { ApiEngine, ApiSubmission, ApiStats } from "@/lib/api-types";

type SortOption = "newest" | "oldest" | "highest" | "lowest";
type EngineFilter = "all" | "ml" | "signature" | "human" | "hybrid";
type BountyFilter = "all" | "quick" | "full" | "deep" | "behavioral";

export default function Marketplace() {
  const [engineSearch, setEngineSearch] = useState("");
  const [bountySearch, setBountySearch] = useState("");
  const [engineFilter, setEngineFilter] = useState<EngineFilter>("all");
  const [bountyFilter, setBountyFilter] = useState<BountyFilter>("all");
  const [engineSort, setEngineSort] = useState<SortOption>("newest");
  const [bountySort, setBountySort] = useState<SortOption>("highest");

  // Register Engine modal state
  const [registerOpen, setRegisterOpen] = useState(false);
  const [newEngineName, setNewEngineName] = useState("");
  const [newEngineType, setNewEngineType] = useState("ml");
  const [newEngineEndpoint, setNewEngineEndpoint] = useState("");
  const [newEngineStake, setNewEngineStake] = useState("1.0");
  const [newEngineDescription, setNewEngineDescription] = useState("");

  const { toast } = useToast();
  const { isAuthenticated } = useAuth();
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();

  const {
    data: engines = [],
    isLoading: enginesLoading,
    isError: enginesError,
    refetch: refetchEngines,
  } = useQuery<ApiEngine[]>({
    queryKey: ["/api/engines"],
  });

  const {
    data: submissions = [],
    isLoading: submissionsLoading,
    isError: submissionsError,
    refetch: refetchSubmissions,
  } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
  });

  const { data: stats } = useQuery<ApiStats>({
    queryKey: ["/api/analysis/stats"],
  });

  const registerEngineMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/engines", {
        name: newEngineName.trim(),
        engineType: newEngineType,
        apiEndpoint: newEngineEndpoint.trim() || undefined,
        stakeAmount: newEngineStake,
        description: newEngineDescription.trim() || undefined,
      });
      return res.json();
    },
    onSuccess: (created) => {
      toast({
        title: "Security Engine Registered",
        description: `${created.name} is now active on the network.`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/engines"] });
      queryClient.invalidateQueries({ queryKey: ["/api/analysis/stats"] });
      setRegisterOpen(false);
      setNewEngineName("");
      setNewEngineEndpoint("");
      setNewEngineDescription("");
    },
    onError: (err) => {
      toast({
        title: "Registration failed",
        description: err instanceof Error ? err.message : "Could not register security engine",
        variant: "destructive",
      });
    },
  });

  // Combine submissions with bounties for display
  const activeBountySubmissions = submissions
    .filter((sub) => (sub.status || sub.analysisStatus) === "pending")
    .map((sub) => ({
      submission: sub,
      bounty: { amount: sub.bountyAmount, status: "active" },
    }));

  // Filter and sort engines
  const filteredEngines = useMemo(() => {
    const filtered = engines.filter((engine) => {
      const matchesSearch = engine.name.toLowerCase().includes(engineSearch.toLowerCase());
      const eType = engine.type || engine.engineType || "";
      const matchesFilter = engineFilter === "all" || eType === engineFilter;
      return matchesSearch && matchesFilter;
    });

    filtered.sort((a, b) => {
      switch (engineSort) {
        case "newest":
          return new Date(b.createdAt ?? 0).getTime() - new Date(a.createdAt ?? 0).getTime();
        case "oldest":
          return new Date(a.createdAt ?? 0).getTime() - new Date(b.createdAt ?? 0).getTime();
        case "highest":
          return Number(b.accuracy || b.accuracyRate || 0) - Number(a.accuracy || a.accuracyRate || 0);
        case "lowest":
          return Number(a.accuracy || a.accuracyRate || 0) - Number(b.accuracy || b.accuracyRate || 0);
        default:
          return 0;
      }
    });

    return filtered;
  }, [engines, engineSearch, engineFilter, engineSort]);

  // Filter and sort bounties
  const filteredBounties = useMemo(() => {
    const filtered = activeBountySubmissions.filter(({ submission }) => {
      const nameStr =
        submission.originalFilename ||
        submission.filename ||
        submission.fileName ||
        submission.url ||
        "";
      const matchesSearch = nameStr.toLowerCase().includes(bountySearch.toLowerCase());
      const matchesFilter = bountyFilter === "all" || submission.analysisType === bountyFilter;
      return matchesSearch && matchesFilter;
    });

    filtered.sort((a, b) => {
      switch (bountySort) {
        case "newest":
          return new Date(b.submission.createdAt ?? 0).getTime() - new Date(a.submission.createdAt ?? 0).getTime();
        case "oldest":
          return new Date(a.submission.createdAt ?? 0).getTime() - new Date(b.submission.createdAt ?? 0).getTime();
        case "highest":
          return Number(b.submission.bountyAmount || 0) - Number(a.submission.bountyAmount || 0);
        case "lowest":
          return Number(a.submission.bountyAmount || 0) - Number(b.submission.bountyAmount || 0);
        default:
          return 0;
      }
    });

    return filtered;
  }, [activeBountySubmissions, bountySearch, bountyFilter, bountySort]);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO title="Bounty Marketplace" description="Analyze intelligence reports and claim rewards by staking confidence." />
      <ParticleBackground />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="relative z-10 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          {/* Security Engines Section */}
          <section className="mb-16">
            <div className="text-center mb-12">
              <h1 className="text-4xl md:text-5xl font-bold font-display tracking-[-0.03em] mb-4">Security Engines</h1>
              <p className="text-xl text-muted-foreground">Compete and stake on analysis results</p>
            </div>

            {/* Engine Filters */}
            <div className="mb-8 space-y-4">
              <div className="grid md:grid-cols-3 gap-4">
                <div className="relative">
                  <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search engines..."
                    value={engineSearch}
                    onChange={(e) => setEngineSearch(e.target.value)}
                    className="pl-10"
                  />
                </div>
                <Select value={engineFilter} onValueChange={(value: EngineFilter) => setEngineFilter(value)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Filter by type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="ml">Machine Learning</SelectItem>
                    <SelectItem value="signature">Signature</SelectItem>
                    <SelectItem value="human">Human Expert</SelectItem>
                    <SelectItem value="hybrid">Hybrid</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={engineSort} onValueChange={(value: SortOption) => setEngineSort(value)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Sort by" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="newest">Newest First</SelectItem>
                    <SelectItem value="oldest">Oldest First</SelectItem>
                    <SelectItem value="highest">Highest Accuracy</SelectItem>
                    <SelectItem value="lowest">Lowest Accuracy</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {enginesError ? (
              <ErrorState
                title="Failed to load engines"
                message="Could not fetch security engines. Please try again."
                onRetry={refetchEngines}
              />
            ) : enginesLoading ? (
              <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                {Array.from({ length: 4 }).map((_, i) => (
                  <EngineCardSkeleton key={i} />
                ))}
              </div>
            ) : filteredEngines.length === 0 ? (
              <EmptyState
                icon={Shield}
                title="No engines found"
                description={
                  engineSearch || engineFilter !== "all"
                    ? "No engines match your search criteria. Try adjusting your filters."
                    : "No security engines available at the moment."
                }
              />
            ) : (
              <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                {filteredEngines.map((engine) => (
                  <EngineCard key={engine.id} engine={engine as unknown as import("@shared/schema").SecurityEngine} />
                ))}
              </div>
            )}

            {/* Become an Engine CTA */}
            <div className="text-center">
              <Card className="glassmorphism neon-border max-w-2xl mx-auto">
                <CardContent className="p-8">
                  <h3 className="text-2xl font-bold mb-4">Become a Security Engine</h3>
                  <p className="text-muted-foreground mb-6">
                    Join our network of security experts and automated tools. Stake cryptocurrency on your analysis accuracy and earn rewards for correct verdicts.
                  </p>
                  <div className="flex flex-wrap justify-center gap-4">
                    <Button
                      className="glow-effect"
                      onClick={() => {
                        if (!isAuthenticated) {
                          toast({
                            title: "Sign in required",
                            description: "Please log in to register a security engine.",
                          });
                          setLocation("/login");
                          return;
                        }
                        setRegisterOpen(true);
                      }}
                      data-testid="button-register-engine"
                    >
                      <PlusCircle className="w-4 h-4 mr-2" />
                      Register Engine
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => setLocation("/features/engines")}
                      data-testid="button-learn-more"
                    >
                      <Info className="w-4 h-4 mr-2" />
                      Learn More
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </section>

          {/* Active Bounties Section */}
          <section className="mb-16">
            <div className="text-center mb-12">
              <h2 className="text-4xl font-bold font-display tracking-[-0.03em] mb-4">Active Bounties</h2>
              <p className="text-xl text-muted-foreground">Analyze files and earn cryptocurrency rewards</p>
            </div>

            {/* Bounty Filters */}
            <div className="mb-8 space-y-4">
              <div className="grid md:grid-cols-3 gap-4">
                <div className="relative">
                  <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search bounties..."
                    value={bountySearch}
                    onChange={(e) => setBountySearch(e.target.value)}
                    className="pl-10"
                  />
                </div>
                <Select value={bountyFilter} onValueChange={(value: BountyFilter) => setBountyFilter(value)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Filter by analysis type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="quick">Quick Scan</SelectItem>
                    <SelectItem value="full">Full Analysis</SelectItem>
                    <SelectItem value="deep">Deep Inspection</SelectItem>
                    <SelectItem value="behavioral">Behavioral</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={bountySort} onValueChange={(value: SortOption) => setBountySort(value)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Sort by" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="highest">Highest Bounty</SelectItem>
                    <SelectItem value="lowest">Lowest Bounty</SelectItem>
                    <SelectItem value="newest">Newest First</SelectItem>
                    <SelectItem value="oldest">Oldest First</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {submissionsError ? (
              <ErrorState
                title="Failed to load bounties"
                message="Could not fetch active bounties. Please try again."
                onRetry={refetchSubmissions}
              />
            ) : submissionsLoading ? (
              <div className="grid lg:grid-cols-2 gap-8 mb-12">
                {Array.from({ length: 4 }).map((_, i) => (
                  <BountyCardSkeleton key={i} />
                ))}
              </div>
            ) : filteredBounties.length === 0 ? (
              <EmptyState
                icon={FileX}
                title="No bounties found"
                description={
                  bountySearch || bountyFilter !== "all"
                    ? "No bounties match your search criteria. Try adjusting your filters."
                    : "No active bounties at the moment. Submit a file to create one!"
                }
              />
            ) : (
              <div className="grid lg:grid-cols-2 gap-8 mb-12">
                {filteredBounties.map(({ submission, bounty }) => (
                  <BountyCard key={submission.id} submission={submission} bounty={bounty} />
                ))}
              </div>
            )}

            {/* Bounty Statistics */}
            <div className="grid md:grid-cols-4 gap-6">
              <Card className="glassmorphism text-center">
                <CardContent className="p-6">
                  <div className="text-3xl font-bold font-display tracking-tight text-primary mb-2" data-testid="stat-total-bounties">
                    {stats?.totalActiveBounties || "0"} ETH
                  </div>
                  <div className="text-sm text-muted-foreground">Total Active Bounties</div>
                </CardContent>
              </Card>
              <Card className="glassmorphism text-center">
                <CardContent className="p-6">
                  <div className="text-3xl font-bold font-display tracking-tight text-accent mb-2" data-testid="stat-files-queue">
                    {activeBountySubmissions.length}
                  </div>
                  <div className="text-sm text-muted-foreground">Files in Queue</div>
                </CardContent>
              </Card>
              <Card className="glassmorphism text-center">
                <CardContent className="p-6">
                  <div className="text-3xl font-bold font-display tracking-tight text-secondary mb-2">
                    {stats?.avgResponseTime || "1.2s"}
                  </div>
                  <div className="text-sm text-muted-foreground">Avg Response Time</div>
                </CardContent>
              </Card>
              <Card className="glassmorphism text-center">
                <CardContent className="p-6">
                  <div className="text-3xl font-bold font-display tracking-tight text-primary mb-2">
                    {stats?.totalRewardsPaid || "0"} ETH
                  </div>
                  <div className="text-sm text-muted-foreground">Rewards Paid Out</div>
                </CardContent>
              </Card>
            </div>
          </section>
        </div>
      </main>

      {/* Register Security Engine Modal */}
      <Dialog open={registerOpen} onOpenChange={setRegisterOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Register Security Engine</DialogTitle>
            <DialogDescription>
              Connect your automated scanner or analyst node to participate in bounty consensus.
            </DialogDescription>
          </DialogHeader>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (!newEngineName.trim()) return;
              registerEngineMutation.mutate();
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="engine-name">Engine Name</Label>
              <Input
                id="engine-name"
                placeholder="e.g., SentinelYARA v2"
                value={newEngineName}
                onChange={(e) => setNewEngineName(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label>Engine Type</Label>
              <Select value={newEngineType} onValueChange={setNewEngineType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ml">Machine Learning</SelectItem>
                  <SelectItem value="signature">Signature / YARA</SelectItem>
                  <SelectItem value="hybrid">Hybrid Static + Dynamic</SelectItem>
                  <SelectItem value="human">Human Threat Researcher</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="engine-endpoint">Webhook / API Endpoint (Optional)</Label>
              <Input
                id="engine-endpoint"
                type="url"
                placeholder="https://scanner.example.com/v1/analyze"
                value={newEngineEndpoint}
                onChange={(e) => setNewEngineEndpoint(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="engine-stake">Initial Stake (ETH)</Label>
              <Input
                id="engine-stake"
                type="number"
                step="0.1"
                value={newEngineStake}
                onChange={(e) => setNewEngineStake(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="engine-desc">Description</Label>
              <Textarea
                id="engine-desc"
                rows={3}
                placeholder="Describe detection capabilities and supported file formats..."
                value={newEngineDescription}
                onChange={(e) => setNewEngineDescription(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setRegisterOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={registerEngineMutation.isPending}>
                {registerEngineMutation.isPending ? "Registering..." : "Register Engine"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
