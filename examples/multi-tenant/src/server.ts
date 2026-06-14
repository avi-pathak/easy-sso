import express, { type NextFunction, type Request, type Response } from "express";
import { AuthError, microsoftAuth, requireAuth } from "@easy-sso/node";

const clientId = process.env.CLIENT_ID;
if (clientId === undefined || clientId === "") {
  throw new Error("Set CLIENT_ID (your multi-tenant Entra app registration's Application ID).");
}

// Comma-separated tenant GUIDs this SaaS app is allowed to serve.
const allowedTenants = (process.env.ALLOWED_TENANTS ?? "")
  .split(",")
  .map((t) => t.trim())
  .filter((t) => t.length > 0);

const app = express();

app.use(
  microsoftAuth({
    clientId,
    // Accept work/school accounts from any tenant...
    tenantId: "organizations",
    // ...but only the specific customer tenants we've onboarded.
    ...(allowedTenants.length > 0 ? { allowedTenants } : {}),
    // Custom claim mapping: pull the display name from a non-default claim and
    // treat group ids as roles.
    claims: {
      email: ["email", "preferred_username", "upn"],
      roles: ["roles", "groups"],
    },
  }),
);

app.get("/health", (_req, res) => {
  res.json({ status: "ok", allowedTenants });
});

// Every authenticated user — note `tenantId` is always populated for org tokens.
app.get("/whoami", requireAuth(), (req: Request, res: Response) => {
  res.json({
    id: req.user?.id,
    tenant: req.user?.tenantId,
    roles: req.user?.roles,
  });
});

// A simple per-tenant data partition keyed off the validated tenant id.
const tenantData: Record<string, string> = {};
app.get("/tenant/notes", requireAuth(), (req: Request, res: Response) => {
  const tenant = req.user?.tenantId ?? "unknown";
  res.json({ tenant, notes: tenantData[tenant] ?? "(none yet)" });
});

app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
  if (AuthError.isAuthError(err)) {
    res.status(err.statusCode).json(err.toJSON());
    return;
  }
  next(err);
});

const port = Number(process.env.PORT ?? 3000);
/* eslint-disable no-console */
app.listen(port, () => {
  console.log(`▶ multi-tenant example on http://localhost:${port}`);
  console.log(
    `  allowed tenants: ${allowedTenants.length > 0 ? allowedTenants.join(", ") : "ANY org tenant"}`,
  );
});
/* eslint-enable no-console */
