// middlewares/auth.ts
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

export type AuthUser = {
  userId: string;
  role: "USER" | "ADMIN";
};

declare global {
  namespace Express {
    interface Request {
      auth?: AuthUser;
    }
  }
}

/**
 * issueJwt - create a JWT for a user payload
 */
export function issueJwt(payload: AuthUser) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

/**
 * requireAuth - express middleware to require a valid JWT
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized" });

  const token = auth.slice(7);
  try {
    const data = jwt.verify(token, JWT_SECRET) as AuthUser;
    req.auth = data;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/**
 * requireAdmin - require an authenticated admin
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  // reuse requireAuth then check role
  requireAuth(req, res, () => {
    if (req.auth?.role !== "ADMIN")
      return res.status(403).json({ error: "Admin only" });
    next();
  });
}
