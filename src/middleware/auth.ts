import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me"; // keep same default as auth route

// 🔥 MULTIPLE ADMIN WALLETS (same list as auth route)
const ADMIN_WALLETS = [
  "8569mYKpddFZsAkQYRrNgNiDKoYYd87UbmmpwvjJiyt2",
  "DVBiPM5bRjZQiX744miAy4QNkMmV9GPUW2SUjriABhRU",
];

/**
 * Issue JWT token (helper for server-side issuance if needed)
 */
export function issueJwt(payload: any) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

/**
 * Require Authentication Middleware
 * - Expects Authorization: Bearer <token>
 * - Verifies token, looks up wallet, attaches req.auth = { wallet, role }
 */
export async function requireAuth(req: any, res: any, next: any) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];
    let decoded: any;
    try {
      decoded = jwt.verify(token, JWT_SECRET) as any;
    } catch (err: any) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    // Lookup wallet by address from token
    const wallet = await prisma.wallet.findUnique({
      where: { address: decoded.wallet },
    });

    if (!wallet) {
      return res.status(401).json({ error: "Invalid user: wallet not found" });
    }

    // Determine role: prefer role from token, fall back to ADMIN_WALLETS check
    const roleFromToken = decoded.role;
    const isAdmin = roleFromToken === "ADMIN" || ADMIN_WALLETS.includes(wallet.address);
    const role = isAdmin ? "ADMIN" : "USER";

    req.auth = {
      wallet: wallet.address,
      role,
    };

    next();
  } catch (err: any) {
    console.error("❌ Auth verification error:", err?.message || err);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

/**
 * Require Admin Middleware
 */
export function requireAdmin(req: any, res: any, next: any) {
  if (!req.auth) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (req.auth.role !== "ADMIN") {
    return res.status(403).json({ error: "Forbidden: Admins only" });
  }

  next();
}
