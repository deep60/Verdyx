import { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { useToast } from "@/hooks/use-toast";
import { clearAuthCookies } from "@/lib/cookie-auth";

export interface User {
  id: string;
  username: string;
  email: string;
  walletAddress?: string | null;
  reputationScore: number;
  totalEarnings: string;
  isVerified: boolean;
  createdAt: string;
}

/**
 * Removes data written by older versions: a browser-only account list that held
 * plain-text passwords, made-up scan reports, fake sessions, and login tokens
 * kept where page scripts could read them. Sessions now live in HttpOnly cookies
 * set by the API.
 */
function purgeLegacyLocalData() {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem("verdyx_local_users_v1");
    localStorage.removeItem("verdyx_local_submission_bundles_v1");
    Object.keys(localStorage)
      .filter((key) => key.startsWith("verdyx_reset_"))
      .forEach((key) => localStorage.removeItem(key));
    localStorage.removeItem("token");
    localStorage.removeItem("refreshToken");
  } catch {
    // Storage may be blocked; there is nothing to purge in that case.
  }
  clearAuthCookies();
}

const SERVICE_UNAVAILABLE_MESSAGE =
  "Verdyx is temporarily unavailable. Please try again in a few minutes.";

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  connectWallet: () => Promise<void>;
  disconnectWallet: () => void;
  updateProfile: (input: { username: string; email: string }) => Promise<void>;
  deleteAccount: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthResponseData {
  user: User;
  expiresIn: number;
}

/** The signed-in user, renewing the session cookie once if it has expired. */
async function fetchSessionUser(): Promise<Response> {
  const response = await fetch("/api/v1/auth/verify");
  if (response.status !== 401) return response;
  const refreshed = await fetch("/api/v1/auth/refresh", { method: "POST" });
  return refreshed.ok ? fetch("/api/v1/auth/verify") : response;
}

async function parseJsonSafe(response: Response): Promise<{
  isJson: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body: Record<string, any>;
}> {
  const raw = await response.text();
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      return { isJson: true, body: parsed };
    }
  } catch {
    // Non-JSON response (e.g. Cloudflare 502 HTML or static fallback)
  }
  return { isJson: false, body: {} };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    if (typeof window !== "undefined") {
      purgeLegacyLocalData();
      try {
        const cached = localStorage.getItem("user");
        if (cached) return JSON.parse(cached) as User;
      } catch {
        // Ignore
      }
    }
    return null;
  });
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    void checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const response = await fetchSessionUser();

      if (response.ok) {
        const { isJson, body } = await parseJsonSafe(response);
        if (isJson && body.success && body.data) {
          setUser(body.data as User);
        }
      } else if (response.status === 401) {
        localStorage.removeItem("user");
        setUser(null);
      }
    } catch {
      // Keep cached user if offline
    } finally {
      setIsLoading(false);
    }
  };

  // The API sets the session as HttpOnly cookies; only the profile is cached here.
  const persistSession = (authData: AuthResponseData) => {
    setUser(authData.user);
    localStorage.setItem("user", JSON.stringify(authData.user));
  };

  /** Calls an auth endpoint; throws a user-readable error for any failure. */
  const requestAuth = async (path: string, payload: object): Promise<AuthResponseData> => {
    let response: Response;
    try {
      response = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch {
      throw new Error(SERVICE_UNAVAILABLE_MESSAGE);
    }

    const { isJson, body } = await parseJsonSafe(response);
    if (response.ok && isJson && body.success && body.data) {
      return body.data as AuthResponseData;
    }
    if (!isJson || response.status >= 500) {
      throw new Error(SERVICE_UNAVAILABLE_MESSAGE);
    }
    throw new Error(body.message || body.error || "Request failed. Please try again.");
  };

  const login = async (identifier: string, password: string) => {
    try {
      const authData = await requestAuth("/api/v1/auth/login", {
        identifier: identifier.trim(),
        password,
      });
      persistSession(authData);
      toast({
        title: "Welcome back!",
        description: `Logged in as ${authData.user.username}`,
      });
    } catch (err) {
      toast({
        title: "Login failed",
        description: err instanceof Error ? err.message : "Invalid username/email or password",
        variant: "destructive",
      });
      throw err;
    }
  };

  const register = async (username: string, email: string, password: string) => {
    try {
      const authData = await requestAuth("/api/v1/auth/register", {
        username: username.trim().replace(/\s+/g, "_"),
        email: email.trim().toLowerCase(),
        password,
      });
      persistSession(authData);
      toast({
        title: "Account created!",
        description: `Welcome to Verdyx, ${authData.user.username}`,
      });
    } catch (err) {
      toast({
        title: "Registration failed",
        description: err instanceof Error ? err.message : "Please check your details and try again.",
        variant: "destructive",
      });
      throw err;
    }
  };

  const logout = async () => {
    try {
      await fetch("/api/v1/auth/logout", { method: "POST" });
    } catch {
      // Ignore logout network error
    } finally {
      setUser(null);
      localStorage.removeItem("user");
      toast({
        title: "Logged out",
        description: "See you soon!",
      });
    }
  };

  const connectWallet = async () => {
    try {
      if (typeof window.ethereum === "undefined") {
        toast({
          title: "MetaMask not found",
          description: "Please install MetaMask to connect your wallet",
          variant: "destructive",
        });
        return;
      }

      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts",
      });
      const walletAddress = accounts[0];
      const nonce = crypto.randomUUID();
      const expiresAt = Date.now() + 5 * 60 * 1000;

      const message = JSON.stringify({
        action: "connect_wallet",
        wallet: walletAddress,
        nonce,
        expiresAt,
        domain: window.location.hostname,
      });

      const signature = await window.ethereum.request({
        method: "personal_sign",
        params: [message, walletAddress],
      });

      if (!user) throw new Error("Not signed in");
      const response = await fetch("/api/v1/auth/wallet/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          wallet_address: walletAddress,
          signature,
          message,
          nonce,
          expiresAt,
        }),
      });
      if (!response.ok) throw new Error("Wallet connection was rejected");

      const { isJson, body } = await parseJsonSafe(response);
      if (isJson && body.data) {
        const updatedUser = body.data as User;
        setUser(updatedUser);
        localStorage.setItem("user", JSON.stringify(updatedUser));
      }

      toast({
        title: "Wallet connected",
        description: `Connected: ${walletAddress.substring(0, 6)}...${walletAddress.substring(38)}`,
      });
    } catch {
      toast({
        title: "Connection failed",
        description: "Could not connect to wallet",
        variant: "destructive",
      });
    }
  };

  const disconnectWallet = async () => {
    try {
      if (!user) throw new Error("Not signed in");
      const response = await fetch("/api/v1/auth/wallet/disconnect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!response.ok) throw new Error("Wallet disconnect was rejected");
      if (user) {
        const updatedUser: User = { ...user, walletAddress: null };
        setUser(updatedUser);
        localStorage.setItem("user", JSON.stringify(updatedUser));
      }
      toast({
        title: "Wallet disconnected",
        description: "Your wallet has been disconnected",
      });
    } catch {
      toast({
        title: "Error",
        description: "Failed to disconnect wallet",
        variant: "destructive",
      });
    }
  };

  const updateProfile = async (input: { username: string; email: string }) => {
    if (!user) throw new Error("Not signed in");
    const response = await fetch("/api/users/me", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: input.username, email: input.email }),
    });
    if (!response.ok) throw new Error("Could not update your profile. Please try again.");

    const updated = await response.json();
    const next = {
      ...user,
      username: updated.username ?? input.username,
      email: updated.email ?? input.email,
    };
    setUser(next);
    localStorage.setItem("user", JSON.stringify(next));
  };

  const deleteAccount = async () => {
    // Only clear the session once the server confirms, so a failed request
    // can't look like a deleted account.
    const response = await fetch("/api/users/me", { method: "DELETE" });
    if (!response.ok) throw new Error("Could not delete your account. Please try again.");

    setUser(null);
    localStorage.removeItem("user");
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        connectWallet,
        disconnectWallet,
        updateProfile,
        deleteAccount,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

declare global {
  interface Window {
    ethereum?: {
      request: (args: { method: string; params?: unknown[] }) => Promise<string[]>;
    };
  }
}
