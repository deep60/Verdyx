import { useEffect, useState } from "react";

/** The current time in seconds, ticking so deadlines and buttons stay right on an open page. */
export function useNowSec(intervalMs = 15_000): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}
