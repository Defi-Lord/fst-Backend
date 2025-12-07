// src/middleware/auth.ts
import jwt from "jsonwebtoken";
import mongoose, { Document, Model } from "mongoose";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

// 🔥 MUST MATCH EXACTLY with auth/verify
const ADMIN_WALLETS = (
  (process.env.ADMIN_WALLETS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
);

/* ----------------------------------------------
   USER DOCUMENT TYPE
   (Prevents TS errors like: "role does not exist")
----------------------------------------------- */
interface IUser extends Document {
  _id: string;
  wallet: string;
  role?: string;
}

/**
 * Issue JWT token
 */
export function issueJwt(payload: any) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

/**
 * Authentication Middleware
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
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    if (!decoded.wallet) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    // ---- FIXED: explicit Mongoose model + type ----
    const User = mongoose.model<IUser>("User");

    // must return ONE document, not array
    const userDoc = await User.findOne({ wallet: decoded.wallet }).lean<IUser>();

    if (!userDoc) {
      return res.status(401).json({ error: "Invalid user: wallet not found" });
    }

    // ---- FIXED: safe role detection ----
    const roleFromToken = decoded.role;
    const dbRole = userDoc.role || "USER";

    const isAdmin =
      roleFromToken === "ADMIN" ||
      dbRole === "ADMIN" ||
      ADMIN_WALLETS.includes(userDoc.wallet?.toLowerCase() || "");

    const role = isAdmin ? "ADMIN" : "USER";

    // ---- FIXED: enforce correct typing ----
    req.auth = {
      wallet: userDoc.wallet,
      walletId: userDoc._id,
      role,
    };

    return next();
  } catch (err: any) {
    console.error("❌ Auth verification error:", err.message || err);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

/**
 * Admin-only Middleware
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
