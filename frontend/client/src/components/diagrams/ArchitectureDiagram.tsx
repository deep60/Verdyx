import { useState } from "react";
import { Card } from "@/components/ui/card";

export function ArchitectureDiagram() {
  const [activeLayer, setActiveLayer] = useState<string | null>(null);

  const layers = [
    {
      id: "api",
      title: "Submission API & Gateway",
      description: "gRPC & REST endpoints. Handles rate limiting, authentication, and file ingestion.",
      color: "text-primary",
      bgHover: "hover:bg-primary/10",
      borderHover: "hover:border-primary/50",
    },
    {
      id: "orchestrator",
      title: "Distributed Scanner Nodes",
      description: "Parallel execution across YARA, ClamAV, and ML engines (ONNX). Fully containerized and scalable.",
      color: "text-accent",
      bgHover: "hover:bg-accent/10",
      borderHover: "hover:border-accent/50",
    },
    {
      id: "consensus",
      title: "Consensus Engine",
      description: "Aggregates results using a weighted algorithm to eliminate false positives. Optionally logs to blockchain.",
      color: "text-[hsl(var(--chart-3))]",
      bgHover: "hover:bg-[hsl(var(--chart-3))]/10",
      borderHover: "hover:border-[hsl(var(--chart-3))]/50",
    },
  ];

  return (
    <div className="flex flex-col md:flex-row gap-8 items-center justify-center p-6 w-full max-w-6xl mx-auto">
      {/* SVG Diagram Side */}
      <div className="w-full md:w-1/2 relative min-h-[400px] flex items-center justify-center">
        <svg
          viewBox="0 0 400 500"
          className="w-full max-w-sm h-auto"
          xmlns="http://www.w3.org/2000/svg"
          role="img"
          aria-label="Verdyx Architecture Diagram"
        >
          <title>Verdyx Architecture Diagram</title>
          <defs>
            <linearGradient id="cyberGradient" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#23251F" />
              <stop offset="100%" stopColor="#141513" />
            </linearGradient>
            <linearGradient id="emeraldGradient" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#23251F" />
              <stop offset="100%" stopColor="#141513" />
            </linearGradient>
            <linearGradient id="purpleGradient" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#23251F" />
              <stop offset="100%" stopColor="#141513" />
            </linearGradient>
          </defs>

          {/* Lines connecting layers */}
          <path d="M200 130 L200 180" stroke="#32342C" strokeWidth="1" />
          <path d="M200 300 L200 350" stroke="#32342C" strokeWidth="1" />

          {/* Layer 1: API */}
          <g 
            onMouseEnter={() => setActiveLayer("api")}
            onMouseLeave={() => setActiveLayer(null)}
            className="cursor-pointer transition-all duration-300 transform origin-center"
            style={{ transform: activeLayer === "api" ? "scale(1.02)" : "scale(1)" }}
          >
            <rect x="50" y="50" width="300" height="80" rx="2" fill="url(#cyberGradient)" stroke={activeLayer === "api" ? "#F0D83A" : "#32342C"} strokeWidth="1" />
            <text x="200" y="90" textAnchor="middle" fill="#F3F1EA" className="font-mono text-lg">1. Submission API</text>
            <text x="200" y="110" textAnchor="middle" fill="#C8C5BC" className="font-sans text-xs">REST gateway</text>
          </g>

          {/* Layer 2: Scanners */}
          <g 
            onMouseEnter={() => setActiveLayer("orchestrator")}
            onMouseLeave={() => setActiveLayer(null)}
            className="cursor-pointer transition-all duration-300 transform origin-center"
            style={{ transform: activeLayer === "orchestrator" ? "scale(1.02)" : "scale(1)" }}
          >
            <rect x="30" y="180" width="340" height="120" rx="2" fill="url(#emeraldGradient)" stroke={activeLayer === "orchestrator" ? "#F0D83A" : "#32342C"} strokeWidth="1" />
            <text x="200" y="215" textAnchor="middle" fill="#F3F1EA" className="font-mono text-lg">2. Distributed Nodes</text>
            
            {/* Inner boxes for engines */}
            <rect x="50" y="235" width="80" height="40" rx="2" fill="#141513" stroke="#32342C" />
            <text x="90" y="260" textAnchor="middle" fill="#F0D83A" className="font-mono text-xs">YARA</text>
            
            <rect x="160" y="235" width="80" height="40" rx="2" fill="#141513" stroke="#32342C" />
            <text x="200" y="260" textAnchor="middle" fill="#F0D83A" className="font-mono text-xs">ClamAV</text>
            
            <rect x="270" y="235" width="80" height="40" rx="2" fill="#141513" stroke="#32342C" />
            <text x="310" y="260" textAnchor="middle" fill="#F0D83A" className="font-mono text-xs">ML</text>
          </g>

          {/* Layer 3: Consensus */}
          <g 
            onMouseEnter={() => setActiveLayer("consensus")}
            onMouseLeave={() => setActiveLayer(null)}
            className="cursor-pointer transition-all duration-300 transform origin-center"
            style={{ transform: activeLayer === "consensus" ? "scale(1.02)" : "scale(1)" }}
          >
            <rect x="50" y="350" width="300" height="80" rx="2" fill="url(#purpleGradient)" stroke={activeLayer === "consensus" ? "#F0D83A" : "#32342C"} strokeWidth="1" />
            <text x="200" y="390" textAnchor="middle" fill="#F3F1EA" className="font-mono text-lg">3. Consensus</text>
            <text x="200" y="410" textAnchor="middle" fill="#C8C5BC" className="font-sans text-xs">Sealed, then opened</text>
          </g>
        </svg>
      </div>

      {/* Info Panel Side */}
      <div className="w-full md:w-1/2 flex flex-col gap-4">
        {layers.map((layer) => (
          <Card 
            key={layer.id}
            onMouseEnter={() => setActiveLayer(layer.id)}
            onMouseLeave={() => setActiveLayer(null)}
            className={`p-6 transition-all duration-300 border border-border/50 bg-card/50 backdrop-blur-sm cursor-pointer
              ${activeLayer === layer.id ? layer.bgHover + " " + layer.borderHover + " transform scale-[1.02]" : "hover:border-border/80"}
            `}
          >
            <h3 className={`font-mono text-xl font-bold mb-2 flex items-center gap-2 ${activeLayer === layer.id ? layer.color : "text-foreground/90"}`}>
              <span className={`w-2 h-2 rounded-full ${activeLayer === layer.id ? "bg-current animate-pulse" : "bg-muted-foreground/50"}`} />
              {layer.title}
            </h3>
            <p className="text-muted-foreground leading-relaxed">
              {layer.description}
            </p>
          </Card>
        ))}
      </div>
    </div>
  );
}
