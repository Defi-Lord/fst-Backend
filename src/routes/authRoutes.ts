// src/routes/authRoutes.ts
import express from "express";
import jwt from "jsonwebtoken";
import { randomBytes } from "crypto";
import nacl from "tweetnacl";
import bs58 from "bs58";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

// ------------------------
// In-memory challenge store
// NOTE: OK for now, but DB-backed is better later
// ------------------------
const challenges = new Map<string, string>();

// ------------------------
// Admin wallet helper (supports multiple wallets)
// ADMIN_WALLETS=wallet1,wallet2,wallet3
// ------------------------
function isAdminWallet(address: string) {
  const raw = process.env.ADMIN_WALLETS || "";
  if (!raw.trim()) return false;

  return raw
    .split(",")
    .map(w => w.trim().toLowerCase())
    .includes(address.toLowerCase());
}

// ------------------------
// POST /auth/challenge
// ------------------------
router.post("/challenge", (req, res) => {
  const { walletAddress } = req.body;

  if (!walletAddress) {
    return res.status(400).json({ error: "walletAddress required" });
  }

  const challenge = `FST login

Wallet: ${walletAddress}
Nonce: ${randomBytes(16).toString("hex")}
Issued At: ${new Date().toISOString()}

By signing this message you prove ownership of the wallet.`;

  challenges.set(walletAddress, challenge);

  return res.json({
    ok: true,
    challenge,
  });
});

// ------------------------
// POST /auth/verify
// ------------------------
router.post("/verify", (req, res) => {
  const { walletAddress, signature } = req.body;

  if (!walletAddress || !signature) {
    return res.status(400).json({ error: "walletAddress and signature required" });
  }

  const challenge = challenges.get(walletAddress);
  if (!challenge) {
    return res.status(400).json({ error: "No challenge found" });
  }

  try {
    const msgBytes = new TextEncoder().encode(challenge);

    // Accept base64 OR bs58 signatures
    let sigBytes: Uint8Array;
    try {
      sigBytes = Uint8Array.from(Buffer.from(signature, "base64"));
    } catch {
      sigBytes = bs58.decode(signature);
    }

    const pubKeyBytes = bs58.decode(walletAddress);

    const verified = nacl.sign.detached.verify(
      msgBytes,
      sigBytes,
      pubKeyBytes
    );

    if (!verified) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    challenges.delete(walletAddress);

    const role = isAdminWallet(walletAddress) ? "ADMIN" : "USER";

    const token = jwt.sign(
      {
        wallet: walletAddress,
        role,
      },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    return res.json({
      success: true,
      token,
      wallet: walletAddress,
      role,
    });
  } catch (err) {
    console.error("❌ /auth/verify error:", err);
    return res.status(500).json({ error: "Verification failed" });
  }
});

// ------------------------
// POST /auth/introspect
// ------------------------
router.post("/introspect", (req, res) => {
  const authHeader = req.headers.authorization || "";

  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      ok: false,
      error: "Missing or invalid Authorization header",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);

    return res.json({
      ok: true,
      wallet: decoded.wallet,
      role: decoded.role || "USER",
    });
  } catch {
    return res.status(401).json({
      ok: false,
      error: "Invalid or expired token",
    });
  }
});

export default router;
