import { beforeEach, describe, expect, it } from "vitest";
import { GoogleProvider } from "../../src/providers/google/google-provider.js";
import {
  ConfigurationError,
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidSignatureError,
  MissingTokenError,
  TokenExpiredError,
  AuthenticationError,
} from "../../src/errors/index.js";
import {
  FakeJwksServer,
  fixedClock,
  generateSigningKey,
  jwksFor,
  mintToken,
  type SigningKey,
} from "../helpers/crypto.js";

const GOOGLE_CLIENT_ID = "1234567890-abc.apps.googleusercontent.com";
const GOOGLE_ISSUER = "https://accounts.google.com";
const GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs";

function makeProvider(server: FakeJwksServer, clock: ReturnType<typeof fixedClock>, overrides = {}) {
  return new GoogleProvider({
    clientId: GOOGLE_CLIENT_ID,
    fetch: server.fetch,
    clock,
    jwks: { uri: GOOGLE_JWKS },
    ...overrides,
  });
}

function googleClaims(extra: Record<string, unknown> = {}) {
  return {
    sub: "108112098765432101234",
    email: "ada@example.com",
    name: "Ada Lovelace",
    ...extra,
  };
}

describe("GoogleProvider", () => {
  let key: SigningKey;
  let server: FakeJwksServer;
  let clock: ReturnType<typeof fixedClock>;

  beforeEach(async () => {
    key = await generateSigningKey("g-kid-1");
    server = new FakeJwksServer(jwksFor(key));
    clock = fixedClock();
  });

  it("authenticates a valid Google ID token", async () => {
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: GOOGLE_ISSUER,
      audience: GOOGLE_CLIENT_ID,
      claims: googleClaims(),
    });
    const user = await makeProvider(server, clock).authenticate(token);
    expect(user.id).toBe("108112098765432101234");
    expect(user.email).toBe("ada@example.com");
    expect(user.name).toBe("Ada Lovelace");
    expect(user.provider).toBe("google");
    expect(user.roles).toEqual([]);
    expect(user.scopes).toEqual([]);
  });

  it("accepts the bare-host issuer form", async () => {
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: "accounts.google.com",
      audience: GOOGLE_CLIENT_ID,
      claims: googleClaims(),
    });
    await expect(makeProvider(server, clock).authenticate(token)).resolves.toMatchObject({
      provider: "google",
    });
  });

  it("rejects a wrong audience", async () => {
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: GOOGLE_ISSUER,
      audience: "someone-elses-client-id",
      claims: googleClaims(),
    });
    await expect(makeProvider(server, clock).authenticate(token)).rejects.toBeInstanceOf(
      InvalidAudienceError,
    );
  });

  it("rejects a wrong issuer", async () => {
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: "https://evil.example.com",
      audience: GOOGLE_CLIENT_ID,
      claims: googleClaims(),
    });
    await expect(makeProvider(server, clock).authenticate(token)).rejects.toBeInstanceOf(
      InvalidIssuerError,
    );
  });

  it("rejects an expired token", async () => {
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: GOOGLE_ISSUER,
      audience: GOOGLE_CLIENT_ID,
      claims: googleClaims(),
      expOffsetSec: -3600,
    });
    await expect(makeProvider(server, clock).authenticate(token)).rejects.toBeInstanceOf(
      TokenExpiredError,
    );
  });

  it("rejects a token signed by an unknown key", async () => {
    const other = await generateSigningKey("g-kid-1"); // same kid, different key material
    const token = await mintToken({
      privateKey: other.privateKey,
      kid: other.kid,
      issuer: GOOGLE_ISSUER,
      audience: GOOGLE_CLIENT_ID,
      claims: googleClaims(),
    });
    await expect(makeProvider(server, clock).authenticate(token)).rejects.toBeInstanceOf(
      InvalidSignatureError,
    );
  });

  it("rejects a missing token", async () => {
    await expect(makeProvider(server, clock).authenticate("")).rejects.toBeInstanceOf(
      MissingTokenError,
    );
  });

  it("rejects a token without sub", async () => {
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: GOOGLE_ISSUER,
      audience: GOOGLE_CLIENT_ID,
      claims: { email: "ada@example.com" },
    });
    await expect(makeProvider(server, clock).authenticate(token)).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it("enforces the hosted-domain allow-list and surfaces hd as tenantId", async () => {
    const provider = makeProvider(server, clock, { hostedDomains: ["example.com"] });

    const noHd = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: GOOGLE_ISSUER,
      audience: GOOGLE_CLIENT_ID,
      claims: googleClaims(),
    });
    await expect(provider.authenticate(noHd)).rejects.toBeInstanceOf(InvalidIssuerError);

    const withHd = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: GOOGLE_ISSUER,
      audience: GOOGLE_CLIENT_ID,
      claims: googleClaims({ hd: "example.com" }),
    });
    const user = await provider.authenticate(withHd);
    expect(user.tenantId).toBe("example.com");
  });

  it("accepts any of multiple configured audiences", async () => {
    const provider = makeProvider(server, clock, { audience: ["web-client", GOOGLE_CLIENT_ID] });
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: GOOGLE_ISSUER,
      audience: "web-client",
      claims: googleClaims(),
    });
    await expect(provider.authenticate(token)).resolves.toMatchObject({ provider: "google" });
  });

  it("fails fast without a clientId", () => {
    expect(() => new GoogleProvider({ clientId: "" })).toThrow(ConfigurationError);
  });
});
