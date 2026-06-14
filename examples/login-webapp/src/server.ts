import "dotenv/config";
import crypto from "node:crypto";
import express, { type NextFunction, type Request, type Response } from "express";
import { AuthError, MicrosoftProvider, type AuthUser } from "@easy-sso/node";

// --- Configuration (fail fast) ----------------------------------------------

const CLIENT_ID = requireEnv("CLIENT_ID");
const CLIENT_SECRET = requireEnv("CLIENT_SECRET");
const TENANT = process.env.TENANT ?? "organizations";
const PORT = Number(process.env.PORT ?? 7070);
const REDIRECT_URI = process.env.REDIRECT_URI ?? `http://localhost:${PORT}/auth/callback`;
const AUTHORITY = `https://login.microsoftonline.com/${TENANT}`;
const SCOPE = "openid profile email";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`Missing required env var ${name} — see .env.example`);
  }
  return value;
}

// The whole point of the demo: @easy-sso/node validates the ID token Microsoft
// returns from the code exchange (signature, issuer, audience, expiry, tenant).
const provider = new MicrosoftProvider({ clientId: CLIENT_ID, tenantId: TENANT });

// --- Trivial in-memory session store ----------------------------------------

interface Session {
  state?: string;
  nonce?: string;
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

// Step 1: redirect the browser to Microsoft to sign in.
app.get("/auth/login", (req, res) => {
  const session = getSession(req, res);
  session.state = crypto.randomBytes(16).toString("hex");
  session.nonce = crypto.randomBytes(16).toString("hex");

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    response_mode: "query",
    scope: SCOPE,
    state: session.state,
    nonce: session.nonce,
  });
  res.redirect(`${AUTHORITY}/oauth2/v2.0/authorize?${params.toString()}`);
});

// Step 2: Microsoft redirects back with a code; exchange it and validate.
app.get("/auth/callback", (req, res, next) => {
  handleCallback(req, res).catch(next);
});

async function handleCallback(req: Request, res: Response): Promise<void> {
  const session = getSession(req, res);
  const query = req.query as Record<string, string | undefined>;

  if (query.error !== undefined) {
    throw new Error(`${query.error}: ${query.error_description ?? ""}`);
  }
  if (query.code === undefined || query.state !== session.state) {
    throw new Error("Invalid OAuth state or missing authorization code");
  }

  // Exchange the authorization code for tokens (confidential client).
  const tokenRes = await fetch(`${AUTHORITY}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code: query.code,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
    }).toString(),
  });
  const tokens = (await tokenRes.json()) as { id_token?: string; error_description?: string };
  if (!tokenRes.ok || tokens.id_token === undefined) {
    throw new Error(`Token exchange failed: ${tokens.error_description ?? tokenRes.status}`);
  }

  // *** @easy-sso/node validates the ID token here. ***
  const user = await provider.authenticate(tokens.id_token);

  // Bind the validated token to this login attempt (replay defense).
  if (user.claims.nonce !== session.nonce) {
    throw new Error("Nonce mismatch — possible replay");
  }

  session.user = user;
  delete session.state;
  delete session.nonce;
  res.redirect("/");
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
  console.log(`  tenant=${TENANT}  redirect_uri=${REDIRECT_URI}`);
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
<title>easy-sso · Login with Microsoft</title>
<style>
  body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:64px auto;padding:0 20px;color:#1b1b1f}
  .card{border:1px solid #e3e3e8;border-radius:12px;padding:28px}
  .btn{display:inline-block;background:#2f2f31;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600}
  .btn.ms{background:#2563eb}
  pre{background:#f5f5f7;border-radius:8px;padding:16px;overflow:auto;font-size:13px}
  .muted{color:#6b6b70}
  a.link{color:#2563eb}
</style></head><body>${body}</body></html>`;
}

function loginPage(): string {
  return page(`<div class="card">
    <h1>Sign in</h1>
    <p class="muted">This page is protected. Authenticate with your Microsoft work or school account.</p>
    <p><a class="btn ms" href="/auth/login">Login with Microsoft</a></p>
  </div>`);
}

function profilePage(user: AuthUser): string {
  const claims = escapeHtml(JSON.stringify(user.claims, null, 2));
  return page(`<div class="card">
    <h1>Hello, ${escapeHtml(user.name ?? user.email ?? user.id)} 👋</h1>
    <p class="muted">Your ID token was validated by <code>@easy-sso/node</code>.</p>
    <ul>
      <li><strong>id:</strong> ${escapeHtml(user.id)}</li>
      <li><strong>email:</strong> ${escapeHtml(user.email ?? "—")}</li>
      <li><strong>tenant:</strong> ${escapeHtml(user.tenantId ?? "—")}</li>
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
