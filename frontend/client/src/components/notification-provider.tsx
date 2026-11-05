import { useEffect } from "react";
import { flaggedSummary } from "@/lib/report";
import { useWebSocket } from "@/hooks/use-websocket";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";
import { CheckCircle2, AlertTriangle, XCircle, FileCheck, Activity, TrendingUp } from "lucide-react";

interface NotificationProviderProps {
  children: React.ReactNode;
}

export function NotificationProvider({ children }: NotificationProviderProps) {
  const { lastMessage } = useWebSocket();
  const { toast } = useToast();
  const [, setLocation] = useLocation();

  useEffect(() => {
    if (!lastMessage) return;

    try {
      const message = JSON.parse(lastMessage.data);

      switch (message.type) {
        case "new_submission":
          toast({
            title: "New Submission Received",
            description: (
              <div className="flex items-center gap-2">
                <FileCheck className="h-4 w-4 text-primary flex-shrink-0" />
                <span>File "{message.data.fileName}" has been submitted for analysis</span>
              </div>
            ),
          });
          break;

        case "analysis_started":
          toast({
            title: "Analysis Started",
            description: (
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-primary animate-pulse flex-shrink-0" />
                <span>Security engines are now analyzing your submission</span>
              </div>
            ),
          });
          break;

        case "analysis_updated":
          // Optional: Only show for important updates
          if (message.data.status === "completed") {
            const verdictIcon = getVerdictIcon(message.data.verdict);
            toast({
              title: "Engine Analysis Complete",
              description: (
                <div className="flex items-center gap-2">
                  {verdictIcon}
                  <span>{message.data.engineName || "An engine"} has completed analysis</span>
                </div>
              ),
            });
          }
          break;

        case "analysis_completed": {
          const { submissionId, consensus } = message.data;
          const isClean = consensus.finalVerdict.toLowerCase() === "clean";
          const isMalicious = consensus.finalVerdict.toLowerCase() === "malicious";
          const _isSuspicious = consensus.finalVerdict.toLowerCase() === "suspicious";

          const verdictIcon = isClean
            ? <CheckCircle2 className="h-5 w-5 text-success flex-shrink-0" />
            : isMalicious
            ? <XCircle className="h-5 w-5 text-destructive flex-shrink-0" />
            : <AlertTriangle className="h-5 w-5 text-warning flex-shrink-0" />;

          toast({
            title: "Analysis Complete!",
            description: (
              <div className="flex gap-3">
                {verdictIcon}
                <div className="space-y-2">
                  <p className="font-semibold">
                    Verdict: <span className={
                      isClean ? "text-success" :
                      isMalicious ? "text-destructive" :
                      "text-warning"
                    }>
                      {consensus.finalVerdict}
                    </span>
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {flaggedSummary(consensus)}
                  </p>
                  <button
                    onClick={() => setLocation(`/analysis/${submissionId}`)}
                    className="text-sm text-primary hover:underline mt-2"
                  >
                    View full report →
                  </button>
                </div>
              </div>
            ),
            duration: 10000, // Show longer for completed analyses
          });
          break;
        }

        case "bounty_claimed":
          toast({
            title: "Bounty Claimed!",
            description: (
              <div className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-success flex-shrink-0" />
                <span>You earned {message.data.amount} ETH for your analysis</span>
              </div>
            ),
          });
          break;

        case "reputation_updated":
          if (message.data.change > 0) {
            toast({
              title: "Reputation Increased!",
              description: (
                <div className="flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-success flex-shrink-0" />
                  <span>+{message.data.change} reputation points</span>
                </div>
              ),
            });
          }
          break;

        case "engine_status":
          if (message.data.status === "offline") {
            toast({
              title: "Engine Offline",
              description: (
                <div className="flex items-center gap-2">
                  <XCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{message.data.engineName} is temporarily unavailable</span>
                </div>
              ),
              variant: "destructive",
            });
          }
          break;

        default:
          // Silently ignore unknown message types
          break;
      }
    } catch (error) {
      console.error("Error parsing WebSocket message:", error);
    }
  }, [lastMessage, toast, setLocation]);

  return <>{children}</>;
}

function getVerdictIcon(verdict: string | null) {
  if (!verdict) return <Activity className="h-5 w-5 text-muted-foreground" />;

  switch (verdict.toLowerCase()) {
    case "malicious":
      return <XCircle className="h-5 w-5 text-destructive" />;
    case "clean":
      return <CheckCircle2 className="h-5 w-5 text-success" />;
    case "suspicious":
      return <AlertTriangle className="h-5 w-5 text-warning" />;
    default:
      return <Activity className="h-5 w-5 text-muted-foreground" />;
  }
}
