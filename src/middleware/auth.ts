// src/middleware/auth.ts
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

// Solana Admin Wallet Address
const ADMIN_WALLET = "8569mYKpddFZsAkQYRrNgNiDKoYYd87UbmmpwvjJiyt2";

/**
 * Issue JWT token
 */
export function issueJwt(payload: any) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

/**
 * Require Authentication Middleware
 */
export async function requireAuth(req: any, res: any, next: any) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];
    const decoded: any = jwt.verify(token, JWT_SECRET);

    // Lookup wallet by its address
    const wallet = await prisma.wallet.findUnique({
      where: { address: decoded.wallet },
    });

    if (!wallet) {
      return res.status(401).json({ error: "Invalid user: wallet not found" });
    }

    // Assign role: ADMIN if matches admin wallet, else USER
    const role = wallet.address === ADMIN_WALLET ? "ADMIN" : "USER";

    req.auth = {
      wallet: wallet.address,
      role,
    };

    next();

  } catch (err: any) {
    console.error("❌ Auth verification error:", err.message);
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
