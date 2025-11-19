// src/middleware/auth.ts
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

// Admin wallet address (Solana)
const ADMIN_WALLET = "8569mYKpddFZsAkQYRrNgNiDKoYYd87UbmmpwvjJiyt2";

// Issue JWT
export function issueJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

// Require Authentication
export async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    // 🔥 FIX: lookup by wallet address, not database ID
    const wallet = await prisma.wallet.findUnique({
      where: { address: decoded.userId },
      include: { user: true },
    });

    if (!wallet) {
      return res.status(401).json({ error: "Invalid user: wallet not found" });
    }

    const role = wallet.address === ADMIN_WALLET
      ? "ADMIN"
      : (wallet.user?.role || "USER");

    req.auth = {
      ...decoded,
      wallet: wallet.address,
      role,
      userId: wallet.address,
    };

    next();

  } catch (err) {
    console.error("❌ Auth verification error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Require admin
export function requireAdmin(req, res, next) {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });
  if (req.auth.role !== "ADMIN") return res.status(403).json({ error: "Forbidden: Admins only" });
  next();
}
