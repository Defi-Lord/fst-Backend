// middleware/auth.ts
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
 * requireAuth - express middleware to require a valid JWT in Authorization header
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || req.header("Authorization");
  if (!authHeader || !authHeader.toString().startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.toString().slice(7);
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
  // call requireAuth then verify role
  requireAuth(req, res, () => {
    if (req.auth?.role !== "ADMIN") {
      return res.status(403).json({ error: "Admin only" });
    }
    next();
  });
}
