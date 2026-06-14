import express, { type NextFunction, type Request, type Response } from "express";
import { AuthError, microsoftAuth, requireAuth, requireRole } from "@easy-sso/node";

const PORT = Number(process.env.PORT ?? 3000);
const clientId = process.env.CLIENT_ID;
if (clientId === undefined || clientId === "") {
  throw new Error("Set CLIENT_ID (your Entra app registration's Application ID).");
}

const app = express();

// 1. Mount the provider middleware once. It validates a bearer token when present
//    and attaches `req.user`; requests without a token continue as anonymous.
app.use(
  microsoftAuth({
    clientId,
    tenantId: process.env.TENANT_ID ?? "common",
  }),
);

// Public route — no auth required.
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// 2. `requireAuth()` gates a route on a valid token (401 otherwise).
app.get("/profile", requireAuth(), (req: Request, res: Response) => {
  // `req.user` is fully typed thanks to the shipped Express augmentation.
  res.json({ user: req.user });
});

// 3. `requireRole()` adds role-based authorization (403 otherwise).
app.get("/admin", requireAuth(), requireRole("Admin"), (req: Request, res: Response) => {
  res.json({ message: `Welcome, admin ${req.user?.name ?? req.user?.id}` });
});

// 4. Centralized error handler. The framework's errors carry a statusCode and a
//    structured JSON body, so forwarding them is trivial.
app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
  if (AuthError.isAuthError(err)) {
    res.status(err.statusCode).json(err.toJSON());
    return;
  }
  next(err);
});

/* eslint-disable no-console */
app.listen(PORT, () => {
  console.log(`▶ express example listening on http://localhost:${PORT}`);
  console.log(`  try: curl -H "Authorization: Bearer <token>" http://localhost:${PORT}/profile`);
});
/* eslint-enable no-console */
