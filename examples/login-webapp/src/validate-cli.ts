/* eslint-disable no-console */
import "dotenv/config";
import { AuthError, MicrosoftProvider } from "@easy-sso/node";

// Validates a real Microsoft token with @easy-sso/node against live Entra JWKS.
// Usage: tsx src/validate-cli.ts <token>
//   VALIDATE_TENANT  override tenant mode (e.g. your tenant GUID for v1 tokens)
//   AUDIENCE         comma-separated accepted audiences (defaults to clientId forms)

const token = process.argv[2];
const clientId = process.env.CLIENT_ID;

if (token === undefined || token === "") {
  console.error("usage: tsx src/validate-cli.ts <token>");
  process.exit(2);
}
if (clientId === undefined || clientId === "") {
  console.error("CLIENT_ID is not set (see .env)");
  process.exit(2);
}

const provider = new MicrosoftProvider({
  clientId,
  tenantId: process.env.VALIDATE_TENANT ?? process.env.TENANT ?? "organizations",
  ...(process.env.AUDIENCE !== undefined ? { audience: process.env.AUDIENCE.split(",") } : {}),
});

provider
  .authenticate(token)
  .then((user) => {
    console.log("✅ VALID — verified by @easy-sso/node against live Microsoft JWKS\n");
    console.log(JSON.stringify(user, null, 2));
  })
  .catch((err: unknown) => {
    const code = AuthError.isAuthError(err) ? err.code : (err as Error).name;
    console.error(`❌ REJECTED — ${code}: ${(err as Error).message}`);
    process.exit(1);
  });
