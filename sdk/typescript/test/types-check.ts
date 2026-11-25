// Compiled by `npm run typecheck` (never run): checks the public types hold together.
import { Verdyx, VerdyxError, ScanTimeoutError, meetsThreshold, type ScanResult, type Verdict } from "../src/index.js";

async function example(): Promise<void> {
  const client = new Verdyx({ apiKey: "vdx_x", apiUrl: "http://localhost:8080" });
  const sub = await client.submitFile("sample.exe", { teamId: "t", description: "d", priority: true });
  const id: string = sub.id;
  const result: ScanResult = await client.waitForResult(id, { timeoutSeconds: 60, onStatus: (s) => void s });
  const v: Verdict = result.verdict;
  const flagged: number = result.votes.malicious + result.votes.suspicious;
  for (const e of result.engines) {
    const n: string = e.name;
    const c: number | null = e.confidence;
    void n, c;
  }
  const again = await client.scan("https://example.com", { pollIntervalSeconds: 1 });
  void again.reportUrl, flagged, v;
  if (meetsThreshold(result.verdict, "suspicious")) throw new VerdyxError("blocked", { status: 0 });
  try {
    await client.waitForResult(id);
  } catch (e) {
    if (e instanceof ScanTimeoutError) void e.submissionId;
    if (e instanceof VerdyxError) void e.status;
  }
  const engines = await client.listEngines();
  void engines[0]?.status;
}
void example;
