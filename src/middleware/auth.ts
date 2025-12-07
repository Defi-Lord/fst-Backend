// src/middleware/auth.ts
import jwt from "jsonwebtoken";
import mongoose, { Document } from "mongoose";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

// Parse admin wallet list from ENV
const ADMIN_WALLETS = (
  (process.env.ADMIN_WALLETS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
);

// ------------------------
// USER DOC TYPE
// ------------------------
interface IUser extends Document {
  _id: string;
  wallet: string;
  role?: string;
}

// Safe function to get User model
function getUserModel(): mongoose.Model<IUser> {
  try {
    return mongoose.model<IUser>("User");
  } catch {
    const schema = new mongoose.Schema(
      {
        wallet: { type: String, unique: true },
        role: { type: String, default: "USER" },
        displayName: String,
      },
      { timestamps: true }
    );
    return mongoose.model<IUser>("User", schema);
  }
}

// ------------------------
// ISSUE JWT TOKEN
// ------------------------
export function issueJwt(payload: any) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

// ------------------------
// AUTH MIDDLEWARE
// ------------------------
export async function requireAuth(req: any, res: any, next: any) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];

    let decoded: any;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    if (!decoded.wallet) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    const User = getUserModel();

    // Important: must return a single user doc
    const user = await User.findOne({ wallet: decoded.wallet })
      .lean<IUser>()
      .exec();

    if (!user) {
      return res.status(401).json({ error: "User not found for this wallet" });
    }

    // Role resolution: DB → token → ENV list
    const dbRole = user.role || "USER";
    const tokenRole = decoded.role || "USER";
    const wallet = user.wallet.toLowerCase();

    const isAdmin =
      dbRole === "ADMIN" ||
      tokenRole === "ADMIN" ||
      ADMIN_WALLETS.includes(wallet);

    req.auth = {
      wallet: user.wallet,
      walletId: user._id,
      role: isAdmin ? "ADMIN" : "USER",
    };

    return next();
  } catch (err: any) {
    console.error("❌ requireAuth error:", err);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ------------------------
// ADMIN-ONLY MIDDLEWARE
// ------------------------
export function requireAdmin(req: any, res: any, next: any) {
  if (!req.auth) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (req.auth.role !== "ADMIN") {
    return res.status(403).json({ error: "Forbidden: Admins only" });
  }

  next();
}
