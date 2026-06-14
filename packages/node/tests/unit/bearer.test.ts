import { describe, expect, it } from "vitest";
import { extractBearerToken } from "../../src/utils/bearer.js";

describe("extractBearerToken", () => {
  it("extracts a token from a well-formed header", () => {
    expect(extractBearerToken("Bearer abc.def.ghi")).toBe("abc.def.ghi");
  });

  it("is case-insensitive on the scheme", () => {
    expect(extractBearerToken("bearer xyz")).toBe("xyz");
    expect(extractBearerToken("BEARER xyz")).toBe("xyz");
  });

  it("tolerates surrounding/internal whitespace", () => {
    expect(extractBearerToken("  Bearer    tok  ")).toBe("tok");
  });

  it("uses the first value when the header is an array", () => {
    expect(extractBearerToken(["Bearer first", "Bearer second"])).toBe("first");
  });

  it.each([
    ["undefined", undefined],
    ["empty", ""],
    ["wrong scheme", "Basic abc"],
    ["scheme only", "Bearer"],
    ["scheme with no token", "Bearer   "],
  ])("returns undefined for %s", (_label, header) => {
    expect(extractBearerToken(header)).toBeUndefined();
  });

  it("returns undefined for a non-string array element", () => {
    expect(extractBearerToken([])).toBeUndefined();
  });
});
