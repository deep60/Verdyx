import { triggerCommandPalette } from "@/components/command-palette";
import { VerdyxLogo } from "@/components/verdyx-logo";
import { useEffect, useState } from "react";
import { Link, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Menu, User, LogOut, Wallet, Search } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";

const navItems = [
  { href: "/", label: "Overview" },
  { href: "/#architecture", label: "Architecture" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/marketplace", label: "Marketplace" },
  { href: "/pricing", label: "Pricing" },
  { href: "/api", label: "API" },
];

export function Navigation() {
  const [location] = useLocation();
  const { user, isAuthenticated, logout, connectWallet } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [hash, setHash] = useState(() =>
    typeof window === "undefined" ? "" : window.location.hash,
  );

  useEffect(() => {
    const sync = () => setHash(window.location.hash);
    window.addEventListener("hashchange", sync);
    window.addEventListener("pushState", sync);
    window.addEventListener("replaceState", sync);
    return () => {
      window.removeEventListener("hashchange", sync);
      window.removeEventListener("pushState", sync);
      window.removeEventListener("replaceState", sync);
    };
  }, [location]);

  const isCurrent = (href: string) => {
    if (href.startsWith("/#")) return location === "/" && hash === href.slice(1);
    if (href === "/") return location === "/" && hash === "";
    return location === href;
  };

  const userInitials =
    user?.username
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase() || "U";

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:bg-mark focus:px-3 focus:py-2 focus:text-[#141513]"
        data-testid="link-skip-to-content"
      >
        Skip to main content
      </a>

      <header className="sticky top-0 z-50 border-b border-[#32342C] bg-[#141513] text-[#F3F1EA]">
        <nav className="mx-auto flex h-12 max-w-7xl items-center justify-between gap-3 px-4 sm:px-6 lg:px-8">
          <Link href="/" data-testid="link-home" className="flex items-center gap-2.5">
            <VerdyxLogo size={28} textClassName="text-[15px]" />
          </Link>

          <div className="hidden items-center gap-5 xl:flex">
            {navItems.map((item) => {
              const isActive = isCurrent(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  data-testid={`link-${item.label.toLowerCase()}`}
                  className={`text-[13px] transition-colors duration-150 ${
                    isActive
                      ? "text-[#F3F1EA] underline decoration-mark decoration-2 underline-offset-8"
                      : "text-[#F3F1EA]/70 hover:text-[#F3F1EA]"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </div>

          <div className="hidden items-center gap-2 md:flex">
            <button
              type="button"
              onClick={triggerCommandPalette}
              data-testid="button-command-palette"
              className="inline-flex h-8 items-center gap-2 rounded-[2px] border border-[#32342C] bg-[#23251F] px-2.5 text-xs text-[#F3F1EA]/80 transition-colors hover:border-[#F0D83A] hover:text-[#F3F1EA]"
              title="Open Analyst Command Palette (⌘K / Ctrl+K)"
            >
              <Search className="h-3.5 w-3.5 text-[#F0D83A]" />
              <span className="hidden lg:inline">Search / Scan…</span>
              <kbd className="ml-1 rounded-[2px] border border-[#32342C] bg-[#141513] px-1.5 py-0.5 font-mono text-[10px] text-[#F3F1EA]/70">
                ⌘K
              </kbd>
            </button>
            {isAuthenticated && user ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    className="relative h-8 w-8 text-[#F3F1EA] hover:bg-[#23251F] hover:text-[#F3F1EA]"
                    aria-label="Account menu"
                  >
                    <Avatar className="h-8 w-8">
                      <AvatarFallback className="bg-[#F3F1EA] text-[11px] font-medium text-[#141513]">
                        {userInitials}
                      </AvatarFallback>
                    </Avatar>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuLabel>
                    <div className="flex flex-col space-y-1">
                      <p className="text-sm font-medium">{user.username}</p>
                      <p className="truncate font-mono text-xs text-muted-foreground">
                        {user.email}
                      </p>
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem asChild>
                    <Link href="/profile" className="flex w-full cursor-pointer items-center">
                      <User className="mr-2 h-4 w-4" />
                      <span>Analyst Profile</span>
                    </Link>
                  </DropdownMenuItem>
                  {!user.walletAddress && (
                    <DropdownMenuItem onClick={connectWallet}>
                      <Wallet className="mr-2 h-4 w-4" />
                      <span>Connect Web3 Wallet</span>
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={logout}>
                    <LogOut className="mr-2 h-4 w-4" />
                    <span>Sign Out</span>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : (
              <div className="flex items-center gap-2">
                <Link href="/login">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-[#F3F1EA] hover:bg-[#23251F] hover:text-[#F3F1EA]"
                    data-testid="button-login"
                  >
                    Sign In
                  </Button>
                </Link>
                <Link href="/register">
                  <Button
                    size="sm"
                    className="bg-[#F3F1EA] text-[#141513] hover:bg-[#F3F1EA]/90"
                    data-testid="button-register"
                  >
                    Get Started
                  </Button>
                </Link>
              </div>
            )}
          </div>

          <div className="flex items-center xl:hidden">
            <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
              <SheetTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-9 w-9 text-[#F3F1EA] hover:bg-[#23251F] hover:text-[#F3F1EA]"
                  aria-label="Open menu"
                  data-testid="button-menu"
                >
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent className="w-[85vw] border-[#32342C] bg-[#141513] text-[#F3F1EA] sm:w-80">
                <div className="mt-8 flex flex-col gap-1">
                  <div className="mb-4 flex items-center gap-2 border-b border-[#32342C] pb-4">
                    <VerdyxLogo size={32} textClassName="text-base" showSubtitle />
                  </div>
                  {navItems.map((item) => {
                    const active = isCurrent(item.href);
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        onClick={() => setMobileOpen(false)}
                        data-testid={`mobile-link-${item.label.toLowerCase()}`}
                        className={`px-1 py-2.5 text-sm ${
                          active ? "underline decoration-mark decoration-2 underline-offset-4" : "text-[#F3F1EA]/75"
                        }`}
                      >
                        {item.label}
                      </Link>
                    );
                  })}
                  <div className="mt-4 space-y-2 border-t border-[#32342C] pt-4">
                    {isAuthenticated && user ? (
                      <>
                        <Link href="/profile" onClick={() => setMobileOpen(false)}>
                          <Button variant="outline" className="w-full justify-start border-[#32342C] text-[#F3F1EA]">
                            <User className="mr-2 h-4 w-4" />
                            Analyst Profile
                          </Button>
                        </Link>
                        {!user.walletAddress && (
                          <Button
                            variant="outline"
                            className="w-full justify-start border-[#32342C] text-[#F3F1EA]"
                            onClick={() => {
                              connectWallet();
                              setMobileOpen(false);
                            }}
                          >
                            <Wallet className="mr-2 h-4 w-4" />
                            Connect Wallet
                          </Button>
                        )}
                        <Button
                          variant="destructive"
                          className="w-full justify-start"
                          onClick={() => {
                            logout();
                            setMobileOpen(false);
                          }}
                        >
                          <LogOut className="mr-2 h-4 w-4" />
                          Sign Out
                        </Button>
                      </>
                    ) : (
                      <>
                        <Link href="/login" onClick={() => setMobileOpen(false)}>
                          <Button
                            variant="outline"
                            className="w-full border-[#32342C] bg-transparent text-[#F3F1EA]"
                            data-testid="mobile-button-login"
                          >
                            Sign In
                          </Button>
                        </Link>
                        <Link href="/register" onClick={() => setMobileOpen(false)}>
                          <Button
                            className="w-full bg-[#F3F1EA] text-[#141513] hover:bg-[#F3F1EA]/90"
                            data-testid="mobile-button-register"
                          >
                            Get Started
                          </Button>
                        </Link>
                      </>
                    )}
                  </div>
                </div>
              </SheetContent>
            </Sheet>
          </div>
        </nav>
      </header>
    </>
  );
}
