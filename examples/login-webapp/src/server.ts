import "dotenv/config";
import crypto from "node:crypto";
import express, { type NextFunction, type Request, type Response } from "express";
import { AuthError, GoogleProvider, MicrosoftProvider, type AuthUser } from "@easy-sso/node";

// --- Configuration -----------------------------------------------------------
//
// Microsoft and Google are each optional: a provider is enabled when its client
// id + secret are present. Configure one or both. The home page shows a button
// for every enabled provider, and each provider's ID token is validated by
// @easy-sso/node before a session is created.

const PORT = Number(process.env.PORT ?? 7070);

/** Everything needed to drive one provider's authorization-code flow + validation. */
interface OAuthFlow {
  name: string;
  label: string;
  loginPath: string;
  callbackPath: string;
  authorizeUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
  extraAuthParams?: Record<string, string>;
  /** @easy-sso/node validates the returned ID token here. */
  validate(idToken: string): Promise<AuthUser>;
}

const flows: OAuthFlow[] = [];

// Microsoft Entra ID
if (process.env.CLIENT_ID && process.env.CLIENT_SECRET) {
  const tenant = process.env.TENANT ?? "organizations";
  const authority = `https://login.microsoftonline.com/${tenant}`;
  const provider = new MicrosoftProvider({ clientId: process.env.CLIENT_ID, tenantId: tenant });
  const redirectUri = process.env.REDIRECT_URI ?? `http://localhost:${PORT}/auth/callback`;
  flows.push({
    name: "microsoft",
    label: "Microsoft",
    loginPath: "/auth/login",
    callbackPath: new URL(redirectUri).pathname,
    authorizeUrl: `${authority}/oauth2/v2.0/authorize`,
    tokenUrl: `${authority}/oauth2/v2.0/token`,
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    redirectUri,
    scope: "openid profile email",
    extraAuthParams: { response_mode: "query" },
    validate: (idToken) => provider.authenticate(idToken),
  });
}

// Google
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  const provider = new GoogleProvider({ clientId: process.env.GOOGLE_CLIENT_ID });
  const redirectUri = process.env.GOOGLE_REDIRECT_URI ?? `http://localhost:${PORT}/auth/callback`;
  flows.push({
    name: "google",
    label: "Google",
    loginPath: "/auth/google/login",
    callbackPath: new URL(redirectUri).pathname,
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri,
    scope: "openid email profile",
    extraAuthParams: { access_type: "online", prompt: "select_account" },
    validate: (idToken) => provider.authenticate(idToken),
  });
}

if (flows.length === 0) {
  throw new Error(
    "Configure at least one provider in .env: Microsoft (CLIENT_ID + CLIENT_SECRET) and/or Google (GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET). See .env.example.",
  );
}

// --- Trivial in-memory session store ----------------------------------------

interface Session {
  state?: string;
  nonce?: string;
  flow?: string;
  user?: AuthUser;
}
const sessions = new Map<string, Session>();

function getSession(req: Request, res: Response): Session {
  const cookies = parseCookies(req.headers.cookie);
  let sid = cookies.sid;
  if (sid === undefined || !sessions.has(sid)) {
    sid = crypto.randomUUID();
    sessions.set(sid, {});
    res.cookie("sid", sid, { httpOnly: true, sameSite: "lax", maxAge: 3_600_000, path: "/" });
  }
  return sessions.get(sid)!;
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (header === undefined) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

// --- Routes ------------------------------------------------------------------

const app = express();

app.get("/", (req, res) => {
  const session = getSession(req, res);
  res.type("html").send(session.user ? profilePage(session.user) : loginPage());
});

// Step 1: redirect the browser to the provider to sign in.
function startLogin(flow: OAuthFlow, req: Request, res: Response): void {
  const session = getSession(req, res);
  session.state = crypto.randomBytes(16).toString("hex");
  session.nonce = crypto.randomBytes(16).toString("hex");
  session.flow = flow.name;

  const params = new URLSearchParams({
    client_id: flow.clientId,
    response_type: "code",
    redirect_uri: flow.redirectUri,
    scope: flow.scope,
    state: session.state,
    nonce: session.nonce,
    ...flow.extraAuthParams,
  });
  res.redirect(`${flow.authorizeUrl}?${params.toString()}`);
}

// Step 2: the provider redirects back with a code; exchange it and validate.
// The provider is resolved from the session (recorded at login), not the URL —
// so providers can even share one redirect URI.
async function handleCallback(req: Request, res: Response): Promise<void> {
  const session = getSession(req, res);
  const query = req.query as Record<string, string | undefined>;

  if (query.error !== undefined) {
    throw new Error(`${query.error}: ${query.error_description ?? ""}`);
  }
  const flow = flows.find((f) => f.name === session.flow);
  if (flow === undefined || query.code === undefined || query.state !== session.state) {
    throw new Error("Invalid OAuth state or missing authorization code");
  }

  // Exchange the authorization code for tokens (confidential client).
  const tokenRes = await fetch(flow.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: flow.clientId,
      client_secret: flow.clientSecret,
      grant_type: "authorization_code",
      code: query.code,
      redirect_uri: flow.redirectUri,
    }).toString(),
  });
  const tokens = (await tokenRes.json()) as { id_token?: string; error_description?: string };
  if (!tokenRes.ok || tokens.id_token === undefined) {
    throw new Error(`Token exchange failed: ${tokens.error_description ?? tokenRes.status}`);
  }

  // *** @easy-sso/node validates the ID token here (Microsoft or Google). ***
  const user = await flow.validate(tokens.id_token);

  // Bind the validated token to this login attempt (replay defense).
  if (user.claims.nonce !== session.nonce) {
    throw new Error("Nonce mismatch — possible replay");
  }

  session.user = user;
  delete session.state;
  delete session.nonce;
  delete session.flow;
  res.redirect("/");
}

// Login routes are per-provider (internal links — not registered with the IdP).
for (const flow of flows) {
  app.get(flow.loginPath, (req, res) => {
    startLogin(flow, req, res);
  });
}
// Callback routes dispatch by the session-recorded provider, so two providers may
// share one redirect URI (e.g. both on /auth/callback).
for (const callbackPath of new Set(flows.map((f) => f.callbackPath))) {
  app.get(callbackPath, (req, res, next) => {
    handleCallback(req, res).catch(next);
  });
}

app.get("/auth/logout", (req, res) => {
  const sid = parseCookies(req.headers.cookie).sid;
  if (sid !== undefined) sessions.delete(sid);
  res.clearCookie("sid", { path: "/" });
  res.redirect("/");
});

// A JSON API guarded by the same validated session.
app.get("/api/me", (req, res) => {
  const session = getSession(req, res);
  if (session.user === undefined) {
    res.status(401).json({ error: "not_authenticated" });
    return;
  }
  res.json(session.user);
});

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const message = AuthError.isAuthError(err)
    ? `${err.code}: ${err.message}`
    : err instanceof Error
      ? err.message
      : "Unknown error";
  const status = AuthError.isAuthError(err) ? err.statusCode : 500;
  console.error("[auth error]", message);
  res.status(status).type("html").send(errorPage(message));
});

/* eslint-disable no-console */
app.listen(PORT, () => {
  console.log(`▶ login demo on http://localhost:${PORT}`);
  console.log(`  providers: ${flows.map((f) => f.label).join(", ")}`);
});
/* eslint-enable no-console */

// --- Views (no frontend build — just HTML) ----------------------------------

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c,
  );
}

function page(body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>easy-sso · Login</title>
<style>
  body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:64px auto;padding:0 20px;color:#1b1b1f}
  .card{border:1px solid #e3e3e8;border-radius:12px;padding:28px}
  .btn{display:inline-block;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600;margin:6px 8px 6px 0}
  .btn.microsoft{background:#2563eb}
  .btn.google{background:#1a73e8}
  pre{background:#f5f5f7;border-radius:8px;padding:16px;overflow:auto;font-size:13px}
  .muted{color:#6b6b70}
  a.link{color:#2563eb}
  .tag{display:inline-block;background:#eef;border-radius:6px;padding:2px 8px;font-size:13px}
</style></head><body>${body}</body></html>`;
}

function loginPage(): string {
  const buttons = flows
    .map((f) => `<a class="btn ${f.name}" href="${f.loginPath}">Login with ${f.label}</a>`)
    .join("");
  return page(`<div class="card">
    <h1>Sign in</h1>
    <p class="muted">This page is protected. Choose a provider — the returned ID token is validated by <code>@easy-sso/node</code>.</p>
    <p>${buttons}</p>
  </div>`);
}

function profilePage(user: AuthUser): string {
  const claims = escapeHtml(JSON.stringify(user.claims, null, 2));
  return page(`<div class="card">
    <h1>Hello, ${escapeHtml(user.name ?? user.email ?? user.id)} 👋</h1>
    <p class="muted">Signed in via <span class="tag">${escapeHtml(user.provider)}</span> — validated by <code>@easy-sso/node</code>.</p>
    <ul>
      <li><strong>id:</strong> ${escapeHtml(user.id)}</li>
      <li><strong>email:</strong> ${escapeHtml(user.email ?? "—")}</li>
      <li><strong>tenant / hd:</strong> ${escapeHtml(user.tenantId ?? "—")}</li>
      <li><strong>roles:</strong> ${escapeHtml(user.roles.join(", ") || "—")}</li>
    </ul>
    <p><a class="link" href="/api/me">/api/me (JSON)</a> · <a class="link" href="/auth/logout">Logout</a></p>
    <details><summary>Validated claims</summary><pre>${claims}</pre></details>
  </div>`);
}

function errorPage(message: string): string {
  return page(`<div class="card">
    <h1>Sign-in failed</h1>
    <pre>${escapeHtml(message)}</pre>
    <p><a class="link" href="/">← Back</a></p>
  </div>`);
}
