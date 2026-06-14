import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JSONWebKeySet,
  type JWK,
  type KeyLike,
} from "jose";
import { type Clock } from "../../src/cache/clock.js";
import { type FetchLike } from "../../src/config/types.js";

/** A deterministic instant used as "now" across the test suite (2023-11-14T22:13:20Z). */
export const NOW_MS = 1_700_000_000_000;
export const NOW_SEC = Math.floor(NOW_MS / 1000);

export const TENANT_ID = "11111111-1111-1111-1111-111111111111";
export const OTHER_TENANT_ID = "33333333-3333-3333-3333-333333333333";
export const CLIENT_ID = "22222222-2222-2222-2222-222222222222";
export const JWKS_URI = "https://jwks.test/keys";
export const AUTHORITY_HOST = "login.microsoftonline.com";
export const V1_ISSUER_HOST = "sts.windows.net";

/** A fixed clock for deterministic TTL/exp/nbf behavior. */
export function fixedClock(nowMs: number = NOW_MS): Clock & { set(ms: number): void } {
  let current = nowMs;
  return {
    now: () => current,
    set: (ms: number) => {
      current = ms;
    },
  };
}

export interface SigningKey {
  kid: string;
  privateKey: KeyLike;
  publicJwk: JWK;
}

/** Generate an RS256 keypair and the public JWK (with `kid`) for a JWKS. */
export async function generateSigningKey(kid: string): Promise<SigningKey> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = kid;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  return { kid, privateKey, publicJwk };
}

export function jwksFor(...keys: SigningKey[]): JSONWebKeySet {
  return { keys: keys.map((k) => k.publicJwk) };
}

export interface MintOptions {
  privateKey: KeyLike;
  kid: string;
  issuer: string;
  audience: string | string[];
  claims?: Record<string, unknown>;
  /** Expiry offset in seconds from NOW_SEC (default +3600). */
  expOffsetSec?: number;
  /** Not-before offset in seconds from NOW_SEC (default -60). */
  nbfOffsetSec?: number;
  /** Issued-at offset in seconds from NOW_SEC (default -60). */
  iatOffsetSec?: number;
}

/** Mint a signed JWT relative to the fixed test clock. */
export async function mintToken(options: MintOptions): Promise<string> {
  const {
    privateKey,
    kid,
    issuer,
    audience,
    claims = {},
    expOffsetSec = 3600,
    nbfOffsetSec = -60,
    iatOffsetSec = -60,
  } = options;

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(NOW_SEC + iatOffsetSec)
    .setNotBefore(NOW_SEC + nbfOffsetSec)
    .setExpirationTime(NOW_SEC + expOffsetSec)
    .sign(privateKey);
}

export function v2Issuer(tenantId: string = TENANT_ID): string {
  return `https://${AUTHORITY_HOST}/${tenantId}/v2.0`;
}

export function v1Issuer(tenantId: string = TENANT_ID): string {
  return `https://${V1_ISSUER_HOST}/${tenantId}/`;
}

/**
 * A controllable in-memory JWKS endpoint. Counts fetches (for single-flight and
 * rotation assertions) and lets a test swap the served key set mid-flight.
 */
export class FakeJwksServer {
  public callCount = 0;
  public failNext = 0;
  private jwks: JSONWebKeySet;

  public constructor(initial: JSONWebKeySet) {
    this.jwks = initial;
  }

  public setKeys(jwks: JSONWebKeySet): void {
    this.jwks = jwks;
  }

  public get fetch(): FetchLike {
    return (_input) => {
      this.callCount += 1;
      if (this.failNext > 0) {
        this.failNext -= 1;
        return Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) });
      }
      const body = this.jwks;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(body as unknown),
      });
    };
  }
}
