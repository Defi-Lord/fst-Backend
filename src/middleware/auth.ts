// src/middleware/auth.ts
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

// Wallet address that is admin
const ADMIN_WALLET = "8569mYKpddFZsAkQYRrNgNiDKoYYd87UbmmpwvjJiyt2";

// Helper to issue JWT
export function issueJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

// Middleware: require authentication
export async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    // Load wallet ONLY (no user include because your schema does not support it)
    const wallet = await prisma.wallet.findUnique({
      where: { id: decoded.userId }
    });

    if (!wallet) {
      return res.status(401).json({ error: "Invalid user" });
    }

    // Determine admin role based on wallet address
    const role = wallet.address === ADMIN_WALLET ? "ADMIN" : "USER";

    req.auth = {
      ...decoded,
      wallet: wallet.address,
      role,
      userId: decoded.userId
    };

    next();
  } catch (err) {
    console.error("❌ Auth verification error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Middleware: require ADMIN privileges
export function requireAdmin(req, res, next) {
  if (!req.auth) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (req.auth.role !== "ADMIN") {
    return res.status(403).json({ error: "Forbidden: Admins only" });
  }

  next();
}
