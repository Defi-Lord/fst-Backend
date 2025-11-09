// src/middleware/auth.ts
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "supersecret"; // replace in production

// Helper to issue JWT
export function issueJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

// Middleware: require authentication
export function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    req.auth = decoded;
    next();
  } catch (err) {
    console.error("❌ Auth verification error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Middleware: require admin privileges
export function requireAdmin(req, res, next) {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });
  if (req.auth.role !== "ADMIN") return res.status(403).json({ error: "Forbidden: Admins only" });
  next();
}
