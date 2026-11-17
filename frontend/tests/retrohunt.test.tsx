import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RetrohuntPanel, isActive, progressText, type Hunt } from "@/components/retrohunt-panel";

const base: Hunt = {
  id: "h1",
  status: "completed",
  filesTotal: 40,
  filesScanned: 40,
  filesFailed: 0,
  matches: 3,
  createdAt: "2026-11-17T10:00:00Z",
  ruleNames: ["Inject", "Wipe"],
};

describe("retrohunt", () => {
  it("describes progress", () => {
    expect(progressText({ ...base, status: "queued" })).toBe("Waiting to start");
    expect(progressText({ ...base, status: "running", filesScanned: 10, filesFailed: 2 })).toBe("Scanning: 12 of 40 files");
    expect(progressText(base)).toBe("3 matches in 40 files");
    expect(progressText({ ...base, matches: 1, filesScanned: 1, filesTotal: 1 })).toBe("1 match in 1 file");
    expect(progressText({ ...base, filesScanned: 38, filesFailed: 2 })).toBe("3 matches in 38 files; 2 couldn't be read");
    expect(progressText({ ...base, status: "failed", message: "the rule doesn't compile: x" })).toBe(
      "the rule doesn't compile: x",
    );
    expect(progressText({ ...base, status: "cancelled", filesScanned: 5 })).toBe("Cancelled after 5 of 40 files");
    expect(isActive("running") && isActive("queued") && !isActive("completed")).toBe(true);
  });

  it("lists hunts with their rules and scope", () => {
    const client = new QueryClient();
    client.setQueryData(["/api/orgs"], [{ id: "t1", name: "Blue Team", role: "member", memberCount: 2 }]);
    client.setQueryData(["/api/retrohunts"], [base, { ...base, id: "h2", status: "running", teamName: "Blue Team" }]);
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <RetrohuntPanel rule="rule a { condition: true }" />
      </QueryClientProvider>,
    );
    expect(html).toContain("Retrohunt");
    expect(html).toContain("Inject, Wipe");
    expect(html).toContain("· Blue Team");
    expect(html).toContain("· my uploads");
    expect(html).toContain("Cancel hunt");
    // One hunt at a time: the button is disabled while one runs.
    expect(html).toMatch(/data-testid="button-retrohunt"[^>]*disabled|disabled[^>]*data-testid="button-retrohunt"/);
  });
});
