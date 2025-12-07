// src/middleware/auth.ts
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me"; // same as auth route

// 🔥 MUST MATCH EXACTLY with auth/verify
const ADMIN_WALLETS = (
  (process.env.ADMIN_WALLETS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
);

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

    // Lookup user document by wallet
    const User = mongoose.model('User');
    const walletDoc = await User.findOne({ wallet: decoded.wallet }).lean();

    if (!walletDoc) {
      return res.status(401).json({ error: "Invalid user: wallet not found" });
    }

    // Determine role: prefer role from token, fall back to ADMIN_WALLETS list or DB role
    const roleFromToken = decoded.role;
    const dbRole = walletDoc.role || 'USER';
    const isAdmin = roleFromToken === "ADMIN" || dbRole === "ADMIN" || ADMIN_WALLETS.includes(walletDoc.wallet?.toLowerCase?.() || '');

    const role = isAdmin ? "ADMIN" : "USER";

    req.auth = {
      wallet: walletDoc.wallet,
      walletId: walletDoc._id,
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
