import { Card, CardContent } from "@/components/ui/card";
import { Bot, UserCheck, Brain, Fingerprint } from "lucide-react";
import type { SecurityEngine } from "@shared/schema";

interface EngineCardProps {
  engine: SecurityEngine;
}

export function EngineCard({ engine }: EngineCardProps) {
  const getEngineIcon = (type: string) => {
    switch (type) {
      case "automated":
        return <Bot className="w-6 h-6 text-primary" />;
      case "human":
        return <UserCheck className="w-6 h-6 text-accent" />;
      case "ml":
        return <Brain className="w-6 h-6 text-secondary" />;
      case "signature":
        return <Fingerprint className="w-6 h-6 text-primary" />;
      default:
        return <Bot className="w-6 h-6 text-primary" />;
    }
  };



  return (
    <Card className="glassmorphism border-primary/20 hover:border-primary/40 transition-colors group hover:transform hover:-translate-y-1 duration-300">
      <CardContent className="p-6">
        <div className="flex items-center space-x-3 mb-4">
          <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center">
            {getEngineIcon(engine.engineType)}
          </div>
          <div>
            <div className="font-semibold" data-testid={`engine-name-${engine.id}`}>
              {engine.name}
            </div>
            <div className="text-sm text-muted-foreground capitalize">
              {engine.engineType}
            </div>
          </div>
        </div>
        
        <div className="space-y-2 mb-4">
          <div className="flex justify-between text-sm">
            <span>Accuracy</span>
            <span className="text-accent font-medium" data-testid={`accuracy-${engine.id}`}>
              {engine.accuracyRate
                ? `${parseFloat(engine.accuracyRate).toFixed(2)}%`
                : "Not measured"}
            </span>
          </div>
          <div className="flex justify-between text-sm">
            <span>Analyses</span>
            <span className="text-primary font-medium" data-testid={`analyses-${engine.id}`}>
              {engine.totalAnalyses != null ? engine.totalAnalyses.toLocaleString() : "—"}
            </span>
          </div>
          <div className="flex justify-between text-sm">
            <span>Stake</span>
            <span className="text-secondary font-medium" data-testid={`stake-${engine.id}`}>
              {engine.stakeAmount ? `${engine.stakeAmount} ETH` : "—"}
            </span>
          </div>
        </div>
        
        <div className={`text-xs matrix-text ${engine.isActive ? "text-accent" : "text-muted-foreground"}`} data-testid={`status-${engine.id}`}>
          {engine.isActive ? "ONLINE" : "OFFLINE"} • {engine.engineType === "human" ? "ACTIVE" : "READY"}
        </div>
      </CardContent>
    </Card>
  );
}
