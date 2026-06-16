import { JwksClient, type JwksClientOptions } from "../../jwks/jwks-client.js";

/** Options for {@link MicrosoftJwksClient}. */
export type MicrosoftJwksClientOptions = JwksClientOptions;

/**
 * Fetches and caches the Microsoft JWKS, exposing a jose-compatible key resolver
 * for signature verification.
 *
 * This is the provider-neutral {@link JwksClient} under a Microsoft-specific name
 * for clarity at call sites and a stable public export. All behavior — caching,
 * single-flight dedup, TTL, background refresh, rotation — lives in the base class
 * and is shared with every other provider.
 */
export class MicrosoftJwksClient extends JwksClient {}
