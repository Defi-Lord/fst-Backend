// src/routes/auth.ts
import express, { Request, Response } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import bs58 from "bs58";
import mongoose from "mongoose";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const NONCE_TTL_SEC = 300; // 5 minutes

// Ensure Nonce model exists (simple collection)
const nonceSchema = new mongoose.Schema({
  address: { type: String, unique: true },
  nonce: String,
  createdAt: Date,
});
try {
  mongoose.model('Nonce');
} catch {
  mongoose.model('Nonce', nonceSchema);
}
const Nonce = mongoose.model('Nonce');

// Use User model if available; fallback to generic model access
let User: any;
try {
  User = mongoose.model('User');
} catch {
  // minimal fallback schema if the app didn't register the model elsewhere
  const userSchema = new mongoose.Schema({
    wallet: { type: String, unique: true },
    token: String,
    role: { type: String, default: 'USER' },
    displayName: String,
  }, { timestamps: true });
  User = mongoose.model('User', userSchema);
}

// Helper: check admin wallets list from env (comma-separated)
function isAdminWallet(address: string) {
  const raw = (process.env.ADMIN_WALLETS || "").trim();
  if (!raw) return false;
  return raw.split(",").map((s) => s.trim().toLowerCase()).includes(address.toLowerCase());
}

// POST /auth/nonce
router.post("/nonce", async (req: Request, res: Response) => {
  try {
    const { walletAddress } = req.body;
    if (!walletAddress)
      return res.status(400).json({ success: false, error: "walletAddress required" });

    const nonce = crypto.randomBytes(16).toString("hex");
    const message = `FST login\n\nWallet: ${walletAddress}\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}\n\nBy signing this message you prove ownership of the wallet.`;

    await Nonce.findOneAndUpdate(
      { address: walletAddress },
      { nonce, createdAt: new Date() },
      { upsert: true }
    );

    return res.json({ success: true, nonce, message });
  } catch (err) {
    console.error("❌ /auth/nonce error:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// POST /auth/verify
router.post("/verify", async (req: Request, res: Response) => {
  try {
    const { walletAddress, signature } = req.body;
    if (!walletAddress || !signature)
      return res.status(400).json({ success: false, error: "missing_params" });

    const stored = await Nonce.findOne({ address: walletAddress });
    if (!stored || !stored.nonce)
      return res.status(400).json({ success: false, error: "nonce_missing" });

    const message = `FST login\n\nWallet: ${walletAddress}\nNonce: ${stored.nonce}\nIssued At: ${stored.createdAt.toISOString()}\n\nBy signing this message you prove ownership of the wallet.`;

    const encoder = new TextEncoder();
    const msgBytes = encoder.encode(message);

    let sigBytes: Uint8Array;
    try {
      sigBytes = Uint8Array.from(Buffer.from(signature, "base64"));
    } catch {
      sigBytes = bs58.decode(signature);
    }

    const pubkeyBytes = bs58.decode(walletAddress);
    const valid = nacl.sign.detached.verify(msgBytes, sigBytes, pubkeyBytes);
    if (!valid) return res.status(401).json({ success: false, error: "invalid_signature" });

    // Find or create user entry (User document contains wallet)
    let user = await User.findOne({ wallet: walletAddress });
    if (!user) {
      user = await User.create({ wallet: walletAddress, role: isAdminWallet(walletAddress) ? 'ADMIN' : 'USER' });
    }

    // Issue JWT with wallet and role — middleware expects { wallet, role }
    const payload = { wallet: walletAddress, role: user.role || 'USER' };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });

    // delete nonce
    await Nonce.deleteMany({ address: walletAddress });

    return res.json({ success: true, token, wallet: walletAddress, role: user.role || 'USER' });
  } catch (err) {
    console.error("❌ /auth/verify error:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// POST /auth/introspect
router.post("/introspect", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization || "";
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ ok: false, error: "Missing or invalid Authorization header" });
    }
    const token = authHeader.split(" ")[1];
    let decoded: any;
    try {
      decoded = jwt.verify(token, JWT_SECRET) as any;
    } catch (e) {
      return res.status(401).json({ ok: false, error: "Invalid or expired token" });
    }

    const walletAddress = decoded.wallet;
    if (!walletAddress) return res.status(401).json({ ok: false, error: "Invalid token payload" });

    const user = await User.findOne({ wallet: walletAddress });
    if (!user) return res.status(401).json({ ok: false, error: "Wallet not found" });

    return res.json({ ok: true, role: decoded.role || user.role || "USER", wallet: walletAddress });
  } catch (err) {
    console.error("❌ /auth/introspect error:", err);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
