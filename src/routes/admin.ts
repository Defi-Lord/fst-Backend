import express from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { prisma } from "../lib/prisma";

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const NONCE_TTL_SEC = 300; // 5 minutes

// ============================================================
// 1. REQUEST NONCE
// ============================================================
router.post("/nonce", async (req, res) => {
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

    await prisma.nonce.upsert({
      where: { address: walletAddress },
      update: { nonce, createdAt: new Date() },
      create: { address: walletAddress, nonce, createdAt: new Date() },
    });

    return res.json({ success: true, nonce, message });
  } catch (err) {
    console.error("❌ /auth/nonce error:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// ============================================================
// 2. VERIFY SIGNATURE
// ============================================================
router.post("/verify", async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;

    if (!walletAddress || !signature)
      return res.status(400).json({ success: false, error: "missing_params" });

    const stored = await prisma.nonce.findUnique({
      where: { address: walletAddress },
    });

    if (!stored || !stored.nonce)
      return res.status(400).json({ success: false, error: "nonce_missing" });

    // Check TTL
    if (stored.createdAt) {
      const ageSec = (Date.now() - new Date(stored.createdAt).getTime()) / 1000;
      if (ageSec > NONCE_TTL_SEC) {
        // delete stale nonces to force fresh flow next time
        await prisma.nonce.deleteMany({ where: { address: walletAddress } });
        return res.status(400).json({ success: false, error: "nonce_expired" });
      }
    }

    const message = `FST login

Wallet: ${walletAddress}
Nonce: ${stored.nonce}
Issued At: ${stored.createdAt.toISOString()}

By signing this message you prove ownership of the wallet.`;

    const msgBytes = new TextEncoder().encode(message);

    let sigBytes: Uint8Array;
    try {
      // try base64 first
      sigBytes = Uint8Array.from(Buffer.from(signature, "base64"));
    } catch {
      // fallback to base58
      try {
        sigBytes = bs58.decode(signature);
      } catch (e) {
        return res.status(400).json({ success: false, error: "invalid_signature_encoding" });
      }
    }

    let pubkeyBytes: Uint8Array;
    try {
      pubkeyBytes = bs58.decode(walletAddress);
    } catch (e) {
      return res.status(400).json({ success: false, error: "invalid_wallet_address" });
    }

    const valid = nacl.sign.detached.verify(msgBytes, sigBytes, pubkeyBytes);
    if (!valid)
      return res.status(401).json({ success: false, error: "invalid_signature" });

    // ------------------------------------------------------------
    // Find or Create Wallet
    // ------------------------------------------------------------
    let wallet = await prisma.wallet.findUnique({
      where: { address: walletAddress },
    });

    if (!wallet) {
      wallet = await prisma.wallet.create({
        data: { address: walletAddress },
      });
    }

    // ------------------------------------------------------------
    // ADMIN WALLETS (adjust to your needs)
    // ------------------------------------------------------------
    const ADMIN_WALLETS = [
      "8569mYKpddFZsAkQYRrNgNiDKoYYd87UbmmpwvjJiyt2",
      "DVBiPM5bRjZQiX744miAy4QNkMmV9GPUW2SUjriABhRU",
    ];

    const role = ADMIN_WALLETS.includes(wallet.address) ? "ADMIN" : "USER";

    // ------------------------------------------------------------
    // ISSUE JWT WITH wallet AND role (matches middleware)
    // ------------------------------------------------------------
    const token = jwt.sign(
      {
        wallet: wallet.address, // used by requireAuth middleware
        role,                   // used by requireAdmin
      },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    // remove nonce so it can't be reused
    await prisma.nonce.deleteMany({ where: { address: walletAddress } });

    // return wallet id and address so frontend can store/use either
    return res.json({
      success: true,
      token,
      wallet: wallet.address,
      walletId: wallet.id,
      role,
    });
  } catch (err) {
    console.error("❌ /auth/verify error:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// ============================================================
// 3. INTROSPECT (client expects /auth/introspect)
//    - validates the Authorization header token and returns
//      { ok, role, wallet } so frontend can know current user.
// ============================================================
router.post("/introspect", async (req, res) => {
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

    // ensure wallet exists in DB
    const walletRec = await prisma.wallet.findUnique({ where: { address: decoded.wallet } });
    if (!walletRec) {
      return res.status(401).json({ ok: false, error: "Wallet not found" });
    }

    // respond with role/wallet (match the shape your frontend expects)
    return res.json({ ok: true, role: decoded.role || "USER", wallet: decoded.wallet, walletId: walletRec.id });
  } catch (err) {
    console.error("❌ /auth/introspect error:", err);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
