import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ScanAccess } from "@/components/scan-access";
import { PrivacySettings } from "@/components/privacy-settings";
import { NIL_ID, canChangeSharing, whereFileWent, whoCanSee } from "@/lib/privacy";

const me = "11111111-1111-1111-1111-111111111111";

describe("who can see a scan", () => {
  it("says it plainly, private first", () => {
    expect(whoCanSee({ submitterId: me })).toBe("Private: only you can open it.");
    expect(whoCanSee({ submitterId: me, organizationId: "t" })).toBe("Private to the team it's saved to.");
    expect(whoCanSee({ submitterId: me, bountyId: "b" })).toMatch(/any signed-in analyst/);
    expect(whoCanSee({ submitterId: me, sharedByLink: true, organizationId: "t" })).toMatch(/anyone with this link/);
    expect(whoCanSee({ submitterId: NIL_ID })).toMatch(/^Made while signed out/);
  });

  it("says where the file went", () => {
    expect(whereFileWent({ submissionType: "url" })).toBeNull();
    expect(whereFileWent({ submissionType: "file" })).toMatch(/stays with Verdyx/);
    expect(whereFileWent({ submissionType: "file", mayUploadFile: true })).toMatch(/may upload this file to VirusTotal/);
  });

  it("offers the switch only to people who may change it", () => {
    expect(canChangeSharing({ submitterId: me }, me)).toBe(true);
    expect(canChangeSharing({ submitterId: me }, "someone else")).toBe(false);
    expect(canChangeSharing({ submitterId: me, organizationId: "t" }, "teammate")).toBe(true);
    expect(canChangeSharing({ submitterId: NIL_ID }, me)).toBe(false);
    expect(canChangeSharing({ submitterId: me }, undefined)).toBe(false);
  });
});

const render = (node: React.ReactNode, data?: [unknown[], unknown]) => {
  const client = new QueryClient();
  if (data) client.setQueryData(data[0], data[1]);
  return renderToStaticMarkup(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
};

describe("report access line", () => {
  it("shows the owner a share switch, and others none", () => {
    const scan = { submitterId: me, submissionType: "file" };
    const owner = render(<ScanAccess submissionId="s1" scan={scan} userId={me} />);
    expect(owner).toContain("Private: only you can open it.");
    expect(owner).toContain("The file stays with Verdyx");
    expect(owner).toContain('data-testid="switch-share-by-link"');
    expect(owner).not.toContain("Copy link");

    const shared = render(<ScanAccess submissionId="s1" scan={{ ...scan, sharedByLink: true }} userId={me} />);
    expect(shared).toContain("Copy link");

    const visitor = render(<ScanAccess submissionId="s1" scan={{ ...scan, sharedByLink: true }} />);
    expect(visitor).toContain("anyone with this link");
    expect(visitor).not.toContain("switch-share-by-link");
  });
});

describe("privacy settings", () => {
  it("lists your setting and your teams', editable only where you manage the team", () => {
    const html = render(<PrivacySettings />, [
      ["/api/users/me/privacy"],
      {
        shareFilesWithVirusTotal: false,
        teams: [
          { id: "t1", name: "Blue Team", canEdit: true, shareFilesWithVirusTotal: true },
          { id: "t2", name: "Red Team", canEdit: false, shareFilesWithVirusTotal: false },
        ],
      },
    ]);
    expect(html).toContain("Let Behavioral analysis upload my files to VirusTotal");
    expect(html).toContain("Blue Team: upload the team&#x27;s files to VirusTotal");
    expect(html).toMatch(/data-testid="privacy-share-team-t2"[^>]*disabled|disabled[^>]*data-testid="privacy-share-team-t2"/);
    expect(html).not.toMatch(/data-testid="privacy-share-team-t1"[^>]*disabled=""/);
  });
});
