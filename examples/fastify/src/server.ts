import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import {
  AuthError,
  AuthenticationError,
  AuthorizationError,
  MicrosoftProvider,
  extractBearerToken,
  type AuthProvider,
  type AuthUser,
} from "@easy-sso/node";

// Fastify isn't Express — yet the provider-agnostic core drops in unchanged.
// We talk to the `AuthProvider` interface directly from a Fastify hook.

declare module "fastify" {
  interface FastifyRequest {
    user?: AuthUser;
  }
}

const clientId = process.env.CLIENT_ID;
if (clientId === undefined || clientId === "") {
  throw new Error("Set CLIENT_ID (your Entra app registration's Application ID).");
}

const provider: AuthProvider = new MicrosoftProvider({
  clientId,
  tenantId: process.env.TENANT_ID ?? "common",
});

const app = Fastify({ logger: true });

// Authenticate when a token is present; leave anonymous otherwise.
app.addHook("onRequest", async (req: FastifyRequest) => {
  const token = extractBearerToken(req.headers.authorization);
  if (token === undefined) return;
  // Throwing here is caught by the error handler below.
  req.user = await provider.authenticate(token);
});

// Reusable guards built on the same normalized `AuthUser`.
function requireAuth(req: FastifyRequest): asserts req is FastifyRequest & { user: AuthUser } {
  if (req.user === undefined) {
    throw new AuthenticationError("Authentication is required");
  }
}

function requireRole(req: FastifyRequest, role: string): void {
  requireAuth(req);
  if (!req.user.roles.includes(role)) {
    throw new AuthorizationError(`Requires role '${role}'`);
  }
}

app.get("/health", () => ({ status: "ok" }));

app.get("/profile", (req: FastifyRequest) => {
  requireAuth(req);
  return { user: req.user };
});

app.get("/admin", (req: FastifyRequest) => {
  requireRole(req, "Admin");
  return { message: `Welcome, admin ${req.user?.name ?? req.user?.id}` };
});

// Map framework errors to HTTP responses.
app.setErrorHandler((error, _req: FastifyRequest, reply: FastifyReply) => {
  if (AuthError.isAuthError(error)) {
    void reply.status(error.statusCode).send(error.toJSON());
    return;
  }
  void reply.status(500).send({ error: "internal_error" });
});

const port = Number(process.env.PORT ?? 3000);
app.listen({ port }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});
