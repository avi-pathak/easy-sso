import { beforeEach, describe, expect, it } from "vitest";
import { MicrosoftProvider } from "../../src/providers/microsoft/microsoft-provider.js";
import {
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidSignatureError,
  InvalidTokenError,
  MissingTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
  AuthenticationError,
} from "../../src/errors/index.js";
import {
  CLIENT_ID,
  FakeJwksServer,
  OTHER_TENANT_ID,
  TENANT_ID,
  fixedClock,
  generateSigningKey,
  jwksFor,
  mintToken,
  v1Issuer,
  v2Issuer,
  type SigningKey,
} from "../helpers/crypto.js";
import { testConfig } from "../helpers/config.js";
import { type MicrosoftAuthConfig } from "../../src/config/types.js";

interface Harness {
  key: SigningKey;
  server: FakeJwksServer;
  clock: ReturnType<typeof fixedClock>;
  provider: MicrosoftProvider;
}

async function harness(overrides: Partial<MicrosoftAuthConfig> = {}): Promise<Harness> {
  const key = await generateSigningKey("kid-1");
  const server = new FakeJwksServer(jwksFor(key));
  const clock = fixedClock();
  const provider = new MicrosoftProvider(testConfig(server.fetch, clock, overrides));
  return { key, server, clock, provider };
}

const v2Claims = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  tid: TENANT_ID,
  ver: "2.0",
  oid: "user-oid",
  name: "Ada Lovelace",
  preferred_username: "ada@contoso.com",
  roles: ["admin"],
  scp: "User.Read",
  ...extra,
});

describe("MicrosoftProvider / token validation", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
  });

  it("accepts a valid v2.0 token and maps the user", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: v2Claims(),
    });
    const user = await h.provider.authenticate(token);
    expect(user).toMatchObject({
      id: "user-oid",
      email: "ada@contoso.com",
      name: "Ada Lovelace",
      tenantId: TENANT_ID,
      roles: ["admin"],
      scopes: ["User.Read"],
      provider: "microsoft",
    });
  });

  it("accepts the api:// form of the audience", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: `api://${CLIENT_ID}`,
      claims: v2Claims(),
    });
    await expect(h.provider.authenticate(token)).resolves.toMatchObject({ id: "user-oid" });
  });

  it("accepts a valid v1.0 token (sts.windows.net issuer)", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v1Issuer(),
      audience: CLIENT_ID,
      claims: { tid: TENANT_ID, ver: "1.0", oid: "v1-oid", upn: "v1@contoso.com" },
    });
    const user = await h.provider.authenticate(token);
    expect(user).toMatchObject({ id: "v1-oid", email: "v1@contoso.com" });
  });

  it("infers v2 when the `ver` claim is absent but the issuer is v2", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: { tid: TENANT_ID, oid: "no-ver" },
    });
    await expect(h.provider.authenticate(token)).resolves.toMatchObject({ id: "no-ver" });
  });

  it("rejects an expired token", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: v2Claims(),
      expOffsetSec: -120,
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(TokenExpiredError);
  });

  it("rejects a not-yet-valid token (nbf in the future)", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: v2Claims(),
      nbfOffsetSec: 600,
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(TokenNotYetValidError);
  });

  it("rejects a wrong audience", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: "some-other-api",
      claims: v2Claims(),
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(InvalidAudienceError);
  });

  it("rejects a wrong issuer", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(OTHER_TENANT_ID), // iss disagrees with the token's own tid
      audience: CLIENT_ID,
      claims: v2Claims(),
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(InvalidIssuerError);
  });

  it("rejects a bad signature (key present, signature invalid)", async () => {
    const imposter = await generateSigningKey("kid-1"); // same kid, different key
    const token = await mintToken({
      privateKey: imposter.privateKey,
      kid: "kid-1",
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: v2Claims(),
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(InvalidSignatureError);
  });

  it("rejects a token missing the tid claim", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: { ver: "2.0", oid: "x" },
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(InvalidIssuerError);
  });

  it("rejects a malformed token", async () => {
    await expect(h.provider.authenticate("not-a-real-jwt")).rejects.toBeInstanceOf(
      InvalidTokenError,
    );
  });

  it("rejects a missing token", async () => {
    await expect(h.provider.authenticate("")).rejects.toBeInstanceOf(MissingTokenError);
  });

  it("rejects a tenant not matching a GUID-configured provider", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(OTHER_TENANT_ID),
      audience: CLIENT_ID,
      claims: v2Claims({ tid: OTHER_TENANT_ID }),
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(InvalidIssuerError);
  });

  it("rejects a token version that is not accepted", async () => {
    const v2Only = await harness({ acceptedVersions: ["2.0"] });
    const token = await mintToken({
      privateKey: v2Only.key.privateKey,
      kid: v2Only.key.kid,
      issuer: v1Issuer(),
      audience: CLIENT_ID,
      claims: { tid: TENANT_ID, ver: "1.0", oid: "x" },
    });
    await expect(v2Only.provider.authenticate(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("surfaces a JWKS endpoint failure as an authentication error", async () => {
    h.server.failNext = 1;
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: v2Claims(),
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(AuthenticationError);
  });

  it("refreshes the JWKS and retries when the signing key has rotated", async () => {
    await h.provider.initialize(); // warm cache with kid-1
    const rotated = await generateSigningKey("kid-2");
    h.server.setKeys(jwksFor(rotated));
    const token = await mintToken({
      privateKey: rotated.privateKey,
      kid: rotated.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: v2Claims({ oid: "rotated-user" }),
    });
    const user = await h.provider.authenticate(token);
    expect(user.id).toBe("rotated-user");
    expect(h.server.callCount).toBe(2); // initial prime + one rotation refresh
  });

  it("fails with InvalidSignatureError when the key cannot be found after refresh", async () => {
    const stranger = await generateSigningKey("unknown-kid");
    const token = await mintToken({
      privateKey: stranger.privateKey,
      kid: stranger.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: v2Claims(),
    });
    await expect(h.provider.authenticate(token)).rejects.toBeInstanceOf(InvalidSignatureError);
  });

  it("rejects a token whose signature segment is corrupted", async () => {
    const token = await mintToken({
      privateKey: h.key.privateKey,
      kid: h.key.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: v2Claims(),
    });
    const [header, payload] = token.split(".");
    const corrupted = `${header}.${payload}.not-a-valid-signature`;
    await expect(h.provider.authenticate(corrupted)).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it("supports dispose() and initialize() lifecycle", async () => {
    await h.provider.initialize();
    await expect(h.provider.dispose()).resolves.toBeUndefined();
  });
});
