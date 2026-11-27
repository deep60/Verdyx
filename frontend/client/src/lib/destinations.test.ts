import { describe, expect, it } from "vitest";
import { apiErrorMessage, createBody, destinationSummary, kindOf, missing, type DestinationDraft } from "./destinations";

const draft = (over: Partial<DestinationDraft>): DestinationDraft => ({
  kind: "webhook",
  url: "https://soc.example.com/hook",
  description: "",
  events: ["analysis.completed"],
  credential: "",
  config: {},
  ...over,
});

describe("missing", () => {
  it("asks for what each destination needs", () => {
    expect(missing(draft({}))).toBeNull();
    expect(missing(draft({ url: " " }))).toBe("Enter the endpoint url");
    expect(missing(draft({ events: [] }))).toBe("Choose at least one event");
    expect(missing(draft({ kind: "splunk" }))).toBe("Enter the hec token");
    expect(missing(draft({ kind: "splunk", credential: "t" }))).toBeNull();
    expect(missing(draft({ kind: "sentinel", credential: "k" }))).toBe("Enter the tenant id");
    expect(
      missing(draft({ kind: "sentinel", credential: "k", config: { tenantId: "t", clientId: "c", dcrImmutableId: "d" } })),
    ).toBeNull();
  });
});

describe("createBody", () => {
  it("sends no credential or settings for a plain webhook", () => {
    expect(createBody(draft({ credential: "ignored", config: { index: "x" } }))).toEqual({
      kind: "webhook",
      url: "https://soc.example.com/hook",
      events: ["analysis.completed"],
      description: undefined,
    });
  });

  it("trims and drops empty optional settings", () => {
    expect(
      createBody(draft({ kind: "splunk", url: " https://s.example.com:8088 ", credential: " t ", config: { index: " sec ", sourcetype: "" } })),
    ).toEqual({
      kind: "splunk",
      url: "https://s.example.com:8088",
      events: ["analysis.completed"],
      description: undefined,
      credential: "t",
      config: { index: "sec" },
    });
  });
});

describe("display helpers", () => {
  it("reads the server's error", () => {
    expect(apiErrorMessage(new Error('400: {"error":"enter the HEC token"}'), "x")).toBe("Enter the HEC token");
    expect(apiErrorMessage(new Error("400: Bad Request"), "fallback")).toBe("fallback");
    expect(apiErrorMessage(new Error("Network down"), "fallback")).toBe("Network down");
    expect(apiErrorMessage("nope", "fallback")).toBe("fallback");
  });

  it("summarises destinations", () => {
    expect(kindOf(undefined)).toBe("webhook");
    expect(kindOf("syslog")).toBe("webhook");
    expect(destinationSummary("splunk", { index: "sec" })).toBe("Splunk HEC · index sec · verdyx:event");
    expect(destinationSummary("sentinel", {})).toBe("Microsoft Sentinel · Custom-VerdyxEvents_CL");
    expect(destinationSummary("webhook", null)).toBe("Webhook · signed JSON");
  });
});
