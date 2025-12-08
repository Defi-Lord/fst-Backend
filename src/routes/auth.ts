// src/routes/auth.ts
import express, { Request, Response } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import bs58 from "bs58";
import mongoose from "mongoose";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const NONCE_TTL_SEC = 300;

/* =========================
   NONCE MODEL
========================= */
const nonceSchema = new mongoose.Schema({
  address: { type: String, unique: true },
  nonce: String,
  createdAt: Date,
});

let Nonce: any;
try {
  Nonce = mongoose.model("Nonce");
} catch {
  Nonce = mongoose.model("Nonce", nonceSchema);
}

/* =========================
   USER MODEL
========================= */
let User: any;
try {
  User = mongoose.model("User");
} catch {
  const userSchema = new mongoose.Schema(
    {
      wallet: { type: String, unique: true },
      role: { type: String, default: "USER" },
      displayName: String,
    },
    { timestamps: true }
  );
  User = mongoose.model("User", userSchema);
}

/* =========================
   ADMIN WALLET CHECK
========================= */
function isAdminWallet(addr: string) {
  const raw = process.env.ADMIN_WALLETS || "";
  if (!raw.trim()) return false;

  return raw
    .split(",")
    .map((w) => w.trim().toLowerCase())
    .includes(addr.toLowerCase());
}

/* =========================
   POST /auth/nonce
========================= */
router.post("/nonce", async (req: Request, res: Response) => {
  try {
    const { walletAddress } = req.body;
    if (!walletAddress)
      return res.status(400).json({ success: false, error: "walletAddress required" });

    const nonce = crypto.randomBytes(16).toString("hex");

    const message = `FST login

Wallet: ${walletAddress}
Nonce: ${nonce}
Issued At: ${new Date().toISOString()}

By signing this message you prove ownership of the wallet.`;

    await Nonce.findOneAndUpdate(
      { address: walletAddress },
      { nonce, createdAt: new Date() },
      { upsert: true }
    );

    res.json({ success: true, nonce, message });
  } catch (err) {
    console.error("❌ /auth/nonce:", err);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

/* =========================
   POST /auth/verify
========================= */
router.post("/verify", async (req: Request, res: Response) => {
  try {
    const { walletAddress, signature } = req.body;
    if (!walletAddress || !signature)
      return res.status(400).json({ success: false, error: "missing_params" });

    const stored = await Nonce.findOne({ address: walletAddress });
    if (!stored)
      return res.status(400).json({ success: false, error: "nonce_missing" });

    const message = `FST login

Wallet: ${walletAddress}
Nonce: ${stored.nonce}
Issued At: ${stored.createdAt.toISOString()}

By signing this message you prove ownership of the wallet.`;

    const msgBytes = new TextEncoder().encode(message);

    let sigBytes: Uint8Array;
    try {
      sigBytes = Uint8Array.from(Buffer.from(signature, "base64"));
    } catch {
      sigBytes = bs58.decode(signature);
    }

    const pubkeyBytes = bs58.decode(walletAddress);
    const valid = nacl.sign.detached.verify(msgBytes, sigBytes, pubkeyBytes);
    if (!valid)
      return res.status(401).json({ success: false, error: "invalid_signature" });

    /* ✅ FIND OR CREATE USER */
    let user = await User.findOne({ wallet: walletAddress });

    const shouldBeAdmin = isAdminWallet(walletAddress);

    if (!user) {
      user = await User.create({
        wallet: walletAddress,
        role: shouldBeAdmin ? "ADMIN" : "USER",
      });
    } else if (shouldBeAdmin && user.role !== "ADMIN") {
      // ✅ Auto-upgrade existing user
      user.role = "ADMIN";
      await user.save();
    }

    const payload = { wallet: walletAddress, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });

    await Nonce.deleteMany({ address: walletAddress });

    res.json({
      success: true,
      token,
      wallet: walletAddress,
      role: user.role,
    });
  } catch (err) {
    console.error("❌ /auth/verify:", err);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

/* =========================
   POST /auth/introspect
========================= */
router.post("/introspect", async (req: Request, res: Response) => {
  try {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer "))
      return res.status(401).json({ ok: false, error: "Missing token" });

    const token = auth.split(" ")[1];

    let decoded: any;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ ok: false, error: "Invalid token" });
    }

    const user = await User.findOne({ wallet: decoded.wallet });
    if (!user)
      return res.status(401).json({ ok: false, error: "User not found" });

    res.json({
      ok: true,
      wallet: user.wallet,
      role: user.role,
    });
  } catch (err) {
    console.error("❌ /auth/introspect:", err);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
