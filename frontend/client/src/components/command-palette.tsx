import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import {
  FileSearch,
  Globe,
  Binary,
  GitCompare,
  Award,
  Terminal,
  Wallet,
  Webhook,
  LayoutDashboard,
  Home,
  CreditCard,
  ArrowRight,
  Hash,
  Cpu,
} from "lucide-react";
import type { ApiSubmission } from "@/lib/api-types";

export const OPEN_COMMAND_PALETTE_EVENT = "verdyx:open-command-palette";
export const SWITCH_DASHBOARD_TAB_EVENT = "verdyx:switch-dashboard-tab";

export function triggerCommandPalette() {
  window.dispatchEvent(new CustomEvent(OPEN_COMMAND_PALETTE_EVENT));
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [, setLocation] = useLocation();

  const { data: submissions = [] } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
    enabled: open,
    retry: false,
  });

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    const onCustomOpen = () => setOpen(true);

    window.addEventListener("keydown", onKeyDown);
    window.addEventListener(OPEN_COMMAND_PALETTE_EVENT, onCustomOpen);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener(OPEN_COMMAND_PALETTE_EVENT, onCustomOpen);
    };
  }, []);

  const runCommand = (action: () => void) => {
    setOpen(false);
    setQuery("");
    action();
  };

  const openDashboardTab = (tab: string) => {
    runCommand(() => {
      sessionStorage.setItem("verdyx_dashboard_tab", tab);
      window.dispatchEvent(new CustomEvent(SWITCH_DASHBOARD_TAB_EVENT, { detail: tab }));
      setLocation("/dashboard");
    });
  };

  const trimmed = query.trim();
  const looksLikeHash = /^[a-fA-F0-9]{16,64}$/.test(trimmed);
  const looksLikeDomainOrUrl =
    /^https?:\/\//i.test(trimmed) ||
    (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(trimmed) && !trimmed.includes(" "));

  const matchingHashSubmission = looksLikeHash
    ? submissions.find(
        (s) =>
          (s.fileHash || "").toLowerCase().includes(trimmed.toLowerCase()) ||
          s.id.toLowerCase().startsWith(trimmed.toLowerCase())
      )
    : undefined;

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput
        placeholder="Search tools, enter a domain/URL to scan, or paste a SHA-256 hash…"
        value={query}
        onValueChange={setQuery}
        data-testid="input-command-palette"
      />
      <CommandList>
        <CommandEmpty>No matching commands or artifacts found.</CommandEmpty>

        {(looksLikeDomainOrUrl || looksLikeHash) && (
          <>
            <CommandGroup heading="INSTANT RECON ACTION">
              {looksLikeDomainOrUrl && (
                <CommandItem
                  value={`scan-domain-${trimmed}`}
                  onSelect={() => {
                    const target = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
                    sessionStorage.setItem("verdyx_prefill_osint_url", target);
                    openDashboardTab("web-intel");
                  }}
                >
                  <Globe className="h-4 w-4 text-[#F0D83A]" />
                  <span>
                    Inspect <strong className="font-mono text-[#F0D83A]">{trimmed}</strong> in Website OSINT (36+ Modules)
                  </span>
                  <ArrowRight className="ml-auto h-4 w-4 opacity-60" />
                </CommandItem>
              )}
              {looksLikeHash && (
                <CommandItem
                  value={`lookup-hash-${trimmed}`}
                  onSelect={() =>
                    runCommand(() => {
                      if (matchingHashSubmission) {
                        setLocation(`/analysis/${matchingHashSubmission.id}`);
                      } else {
                        openDashboardTab("scanner");
                      }
                    })
                  }
                >
                  <Hash className="h-4 w-4 text-[#F0D83A]" />
                  <span>
                    {matchingHashSubmission
                      ? `Open matching artifact (${matchingHashSubmission.originalFilename || matchingHashSubmission.id.slice(0, 8)})`
                      : `Search hash ${trimmed.slice(0, 16)}… in Console`}
                  </span>
                  <ArrowRight className="ml-auto h-4 w-4 opacity-60" />
                </CommandItem>
              )}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        <CommandGroup heading="ANALYST CONSOLE WORKSPACE">
          <CommandItem
            value="open-dashboard-scanner-console-file-email-url"
            onSelect={() => openDashboardTab("scanner")}
          >
            <LayoutDashboard className="h-4 w-4" />
            <span>Live Scanner &amp; Feed (File / Email / URL)</span>
            <CommandShortcut>SCAN</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="website-osint-36-modules-recon"
            onSelect={() => openDashboardTab("web-intel")}
          >
            <Globe className="h-4 w-4" />
            <span>Website OSINT Reconnaissance (36+ Live Modules)</span>
            <CommandShortcut>OSINT</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="yara-studio-playground-rules"
            onSelect={() => openDashboardTab("yara")}
          >
            <Binary className="h-4 w-4" />
            <span>YARA Studio · Test Rules, Regex &amp; PE/ELF Magic</span>
            <CommandShortcut>YARA</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="scan-diff-side-by-side-comparison"
            onSelect={() => openDashboardTab("diff")}
          >
            <GitCompare className="h-4 w-4" />
            <span>Scan Diff · Compare Saved Scans or Live Domains</span>
            <CommandShortcut>DIFF</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="backend-pipeline-worker-telemetry"
            onSelect={() => openDashboardTab("pipeline")}
          >
            <Cpu className="h-4 w-4" />
            <span>Backend Pipeline &amp; 9-Service Architecture</span>
            <CommandShortcut>PIPE</CommandShortcut>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="PLATFORM & ACCOUNT">
          <CommandItem
            value="bounty-marketplace-reputation-leaderboard"
            onSelect={() => runCommand(() => setLocation("/marketplace"))}
          >
            <Award className="h-4 w-4" />
            <span>Bounty Marketplace &amp; Reputation Standings</span>
            <CommandShortcut>BOUNTY</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="wallet-ledger-staking-withdrawals-profile"
            onSelect={() => runCommand(() => setLocation("/profile"))}
          >
            <Wallet className="h-4 w-4" />
            <span>Wallet Ledger, Staked Escrow &amp; Withdrawals</span>
            <CommandShortcut>WALLET</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="webhooks-hmac-delivery-logs"
            onSelect={() => runCommand(() => setLocation("/profile"))}
          >
            <Webhook className="h-4 w-4" />
            <span>Outbound HMAC Webhooks &amp; Delivery Logs</span>
            <CommandShortcut>HOOKS</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="developer-api-reference-live-playground"
            onSelect={() => runCommand(() => setLocation("/api"))}
          >
            <Terminal className="h-4 w-4" />
            <span>Developer API Reference &amp; Live Playground</span>
            <CommandShortcut>API</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="home-overview-seven-chapters"
            onSelect={() => runCommand(() => setLocation("/"))}
          >
            <Home className="h-4 w-4" />
            <span>Overview · Public Bench</span>
            <CommandShortcut>HOME</CommandShortcut>
          </CommandItem>
          <CommandItem
            value="pricing-plans-enterprise"
            onSelect={() => runCommand(() => setLocation("/pricing"))}
          >
            <CreditCard className="h-4 w-4" />
            <span>Pricing &amp; Quotas</span>
            <CommandShortcut>PLANS</CommandShortcut>
          </CommandItem>
        </CommandGroup>

        {submissions.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading={`RECENT SCANNED ARTIFACTS (${Math.min(submissions.length, 5)})`}>
              {submissions.slice(0, 5).map((sub) => {
                const label =
                  sub.originalFilename || sub.filename || sub.fileName || sub.url || sub.id;
                const hashPreview = sub.fileHash ? `${sub.fileHash.slice(0, 12)}…` : sub.id.slice(0, 8);
                return (
                  <CommandItem
                    key={sub.id}
                    value={`artifact ${label} ${sub.fileHash || ""} ${sub.id}`}
                    onSelect={() => runCommand(() => setLocation(`/analysis/${sub.id}`))}
                  >
                    <FileSearch className="h-4 w-4 text-[#F0D83A]" />
                    <span className="truncate font-mono text-xs">{label}</span>
                    <CommandShortcut>{hashPreview}</CommandShortcut>
                  </CommandItem>
                );
              })}
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  );
}
