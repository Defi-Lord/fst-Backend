import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me"; // same as in auth route

// 🔥 MUST MATCH EXACTLY with auth/verify
const ADMIN_WALLETS = [
  "8569mYKpddFZsAkQYRrNgNiDKoYYd87UbmmpwvjJiyt2",
  "DVBiPM5bRjZQiX744miAy4QNkMmV9GPUW2SUjriABhRU",
];

/**
 * Issue JWT token (helper function)
 */
export function issueJwt(payload: any) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

/**
 * Require Authentication Middleware
 * - Validates token
 * - Ensures wallet exists
 * - Attaches req.auth = { wallet, walletId, role }
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

    // wallet address MUST be inside token because it's signed
    if (!decoded.wallet) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    const wallet = await prisma.wallet.findUnique({
      where: { address: decoded.wallet },
    });

    if (!wallet) {
      return res.status(401).json({ error: "Invalid user: wallet not found" });
    }

    // Determine role
    const roleFromToken = decoded.role;
    const isAdmin =
      roleFromToken === "ADMIN" || ADMIN_WALLETS.includes(wallet.address);

    const role = isAdmin ? "ADMIN" : "USER";

    // Attach to request for use in routes
    req.auth = {
      wallet: wallet.address,
      walletId: wallet.id, // added for admin routes (useful!)
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
