import { describe, expect, it } from "vitest";
import { passwordPolicyError } from "../client/src/lib/password-policy";

describe("passwordPolicyError", () => {
  it("accepts a password meeting every rule", () => {
    expect(passwordPolicyError("LongEnough123!")).toBeNull();
  });

  it.each([
    ["Aa1!", "at least 8"],
    ["aaaaaaaa1!", "uppercase"],
    ["AAAAAAAA1!", "lowercase"],
    ["Aaaaaaaa!", "number"],
    ["Aaaaaaaa1", "special"],
  ])("rejects %s", (password, reason) => {
    expect(passwordPolicyError(password)).toContain(reason);
  });
});
