// src/routes/authRoutes.ts
import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { randomBytes } from "crypto";
import nacl from "tweetnacl";
import bs58 from "bs58";
import mongoose from "mongoose";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const NONCE_TTL_SEC = 300; // 5 minutes

/* =========================
   CHALLENGE MODEL
   Optional DB persistence (safer than in-memory)
========================= */
const challengeSchema = new mongoose.Schema({
  wallet: { type: String, unique: true },
  challenge: String,
  createdAt: { type: Date, default: Date.now },
});

let Challenge: any;
try {
  Challenge = mongoose.model("Challenge");
} catch {
  Challenge = mongoose.model("Challenge", challengeSchema);
}

/* =========================
   Admin wallet helper
   ADMIN_WALLETS=wallet1,wallet2
========================= */
function isAdminWallet(address: string) {
  const raw = process.env.ADMIN_WALLETS || "";
  if (!raw.trim()) return false;
  return raw.split(",").map(w => w.trim().toLowerCase()).includes(address.toLowerCase());
}

/* =========================
   Solana wallet validation
========================= */
function isSolanaAddress(addr: string) {
  try {
    const decoded = bs58.decode(addr);
    return decoded.length === 32;
  } catch {
    return false;
  }
}

/* =========================
   POST /auth/challenge
========================= */
router.post("/challenge", async (req: Request, res: Response) => {
  const { walletAddress } = req.body;

  if (!walletAddress) return res.status(400).json({ error: "walletAddress required" });
  if (!isSolanaAddress(walletAddress)) return res.status(400).json({ error: "invalid_wallet_address" });

  const challenge = `FST login

Wallet: ${walletAddress}
Nonce: ${randomBytes(16).toString("hex")}
Issued At: ${new Date().toISOString()}

By signing this message you prove ownership of the wallet.`;

  try {
    await Challenge.findOneAndUpdate(
      { wallet: walletAddress },
      { challenge, createdAt: new Date() },
      { upsert: true }
    );
    return res.json({ ok: true, challenge });
  } catch (err) {
    console.error("❌ /auth/challenge error:", err);
    return res.status(500).json({ error: "server_error" });
  }
});

/* =========================
   POST /auth/verify
========================= */
router.post("/verify", async (req: Request, res: Response) => {
  const { walletAddress, signature } = req.body;

  if (!walletAddress || !signature)
    return res.status(400).json({ error: "walletAddress and signature required" });
  if (!isSolanaAddress(walletAddress)) return res.status(400).json({ error: "invalid_wallet_address" });

  try {
    const challengeEntry = await Challenge.findOne({ wallet: walletAddress });
    if (!challengeEntry) return res.status(400).json({ error: "No challenge found" });

    // Optional TTL check
    if ((Date.now() - challengeEntry.createdAt.getTime()) / 1000 > NONCE_TTL_SEC) {
      await Challenge.deleteOne({ wallet: walletAddress });
      return res.status(400).json({ error: "Challenge expired" });
    }

    const msgBytes = new TextEncoder().encode(challengeEntry.challenge);

    let sigBytes: Uint8Array;
    try {
      sigBytes = Uint8Array.from(Buffer.from(signature, "base64"));
    } catch {
      sigBytes = bs58.decode(signature);
    }

    const pubKeyBytes = bs58.decode(walletAddress);
    const verified = nacl.sign.detached.verify(msgBytes, sigBytes, pubKeyBytes);

    if (!verified) return res.status(401).json({ error: "Invalid signature" });

    await Challenge.deleteOne({ wallet: walletAddress });

    const role = isAdminWallet(walletAddress) ? "ADMIN" : "USER";
    const token = jwt.sign({ wallet: walletAddress, role }, JWT_SECRET, { expiresIn: "30d" });

    return res.json({ success: true, token, wallet: walletAddress, role });
  } catch (err) {
    console.error("❌ /auth/verify error:", err);
    return res.status(500).json({ error: "Verification failed" });
  }
});

/* =========================
   POST /auth/introspect
========================= */
router.post("/introspect", (req: Request, res: Response) => {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ ok: false, error: "Missing or invalid Authorization header" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);
    return res.json({ ok: true, wallet: decoded.wallet, role: decoded.role || "USER" });
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid or expired token" });
  }
});

export default router;
