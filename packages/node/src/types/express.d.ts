import type { AuthUser } from "../core/auth-user.js";

/**
 * Ambient augmentation of Express's `Request` so route handlers see a typed
 * `req.user` after the auth middleware runs. Shipped with the package and pulled
 * into the rolled-up declaration via a type-only import in `index.ts`, so simply
 * importing `@easy-sso/node` activates the typing — no extra setup required.
 *
 * `user` is optional because it is only present once an auth middleware has
 * validated a token; gate access with `requireAuth()` to narrow it at runtime.
 */
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export {};
