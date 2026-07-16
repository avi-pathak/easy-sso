import { beforeEach, describe, expect, it } from "vitest";
import { GoogleProvider } from "../../src/providers/google/google-provider.js";
import {
  InvalidTokenError,
  MissingTokenError,
  TokenNotYetValidError,
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

describe("GoogleProvider — lifecycle & edge cases", () => {
  let key: SigningKey;
  let server: FakeJwksServer;
  let clock: ReturnType<typeof fixedClock>;

  beforeEach(async () => {
    key = await generateSigningKey("g-kid-1");
    server = new FakeJwksServer(jwksFor(key));
    clock = fixedClock();
  });

  it("primes the JWKS cache on initialize()", async () => {
    const provider = makeProvider(server, clock);
    await provider.initialize();
    expect(server.callCount).toBeGreaterThan(0);
  });

  it("disposes without throwing", async () => {
    const provider = makeProvider(server, clock);
    await expect(provider.dispose()).resolves.toBeUndefined();
  });

  it("rejects a non-string token", async () => {
    await expect(
      makeProvider(server, clock).authenticate(undefined as never),
    ).rejects.toBeInstanceOf(MissingTokenError);
  });

  it("rejects a malformed token", async () => {
    await expect(
      makeProvider(server, clock).authenticate("not.a.jwt"),
    ).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("rejects a not-yet-valid token", async () => {
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: GOOGLE_ISSUER,
      audience: GOOGLE_CLIENT_ID,
      claims: { sub: "1", email: "a@b.com" },
      nbfOffsetSec: 3600, // not valid until an hour from now
    });
    await expect(
      makeProvider(server, clock, { clockToleranceSec: 0 }).authenticate(token),
    ).rejects.toBeInstanceOf(TokenNotYetValidError);
  });

  it("refreshes the JWKS and succeeds after key rotation", async () => {
    // Server starts with an old key; token is signed by the new (rotated) key.
    const rotated = await generateSigningKey("g-kid-2");
    server = new FakeJwksServer(jwksFor(key)); // only the old key initially
    const provider = makeProvider(server, clock);

    const token = await mintToken({
      privateKey: rotated.privateKey,
      kid: rotated.kid,
      issuer: GOOGLE_ISSUER,
      audience: GOOGLE_CLIENT_ID,
      claims: { sub: "42", email: "ada@example.com" },
    });

    // First attempt won't find kid g-kid-2; provider refreshes — now serve both.
    server.setKeys(jwksFor(key, rotated));
    const user = await provider.authenticate(token);
    expect(user.id).toBe("42");
    expect(server.callCount).toBeGreaterThanOrEqual(2);
  });
});
