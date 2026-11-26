/**
 * The on-chain side of Verdyx (wallet sign-in, the bounty marketplace, staking,
 * commit-reveal review) runs on a test network and is off by default, so the
 * site reads as the scanning product it is. Set VITE_ENABLE_BOUNTIES=true at
 * build time to bring every part of it back.
 */
export const BOUNTIES_ENABLED = String(import.meta.env.VITE_ENABLE_BOUNTIES ?? "") === "true";
