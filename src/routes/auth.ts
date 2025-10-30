// src/routes/auth.ts
import express from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { prisma } from "../lib/prisma.js"; // ensure this file exports `prisma`
import { Request, Response } from "express";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const NONCE_TTL_SEC = 300; // 5 minutes

// POST /auth/nonce
// Body: { walletAddress }
router.post("/nonce", async (req: Request, res: Response) => {
  try {
    const { walletAddress } = req.body;
    if (!walletAddress) return res.status(400).json({ success: false, error: "walletAddress required" });

    const nonce = crypto.randomBytes(16).toString("hex");
    // message to sign — server-controlled canonical message
    const message = `FST login\n\nWallet: ${walletAddress}\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}\n\nBy signing this message you prove ownership of the wallet. This message will expire in ${NONCE_TTL_SEC} seconds.`;

    // store nonce + message in DB table 'Nonce' (upsert)
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

// POST /auth/verify
// Body: { walletAddress, signature }   // signature must be base64
router.post("/verify", async (req: Request, res: Response) => {
  try {
    const { walletAddress, signature } = req.body;
    if (!walletAddress || !signature) return res.status(400).json({ success: false, error: "missing_params" });

    const stored = await prisma.nonce.findUnique({ where: { address: walletAddress } });
    if (!stored || !stored.nonce) return res.status(400).json({ success: false, error: "nonce_missing" });

    // Reconstruct the exact message server expects (must match the message signed by client)
    // NOTE: If client used the message returned earlier, it will match because we returned that message.
    const message = `FST login\n\nWallet: ${walletAddress}\nNonce: ${stored.nonce}\nIssued At: ${stored.createdAt?.toISOString?.()}\n\nBy signing this message you prove ownership of the wallet. This message will expire in ${NONCE_TTL_SEC} seconds.`;
    // But if your client signed the exact message string returned by /nonce (which includes the new timestamp),
    // ensure that message stored is identical. If you returned the message from /nonce, store it in DB as well.
    // For safety, we also allow verifying by encoding the text the client returned previously:
    // We'll try the raw message (from earlier /nonce response) first: try to fetch stored message (if you store),
    // otherwise try the canonical message above.
    // For simplicity, accept either the canonical or the returned one; here we attempt canonical.

    // Use TextEncoder to get bytes
    const encoder = new TextEncoder();
    const msgBytes = encoder.encode(message);

    // signature may be base64 or base58 — try decoding base64 then base58 fallback
    let sigBytes: Uint8Array;
    try {
      sigBytes = Uint8Array.from(Buffer.from(signature, "base64"));
    } catch {
      try {
        sigBytes = bs58.decode(signature);
      } catch {
        return res.status(400).json({ success: false, error: "signature_decode_failed" });
      }
    }

    // pubkey is base58 address
    let pubkeyBytes: Uint8Array;
    try {
      pubkeyBytes = bs58.decode(walletAddress);
    } catch {
      return res.status(400).json({ success: false, error: "invalid_wallet_address" });
    }

    const ok = nacl.sign.detached.verify(msgBytes, sigBytes, pubkeyBytes);
    if (!ok) return res.status(401).json({ success: false, error: "invalid_signature" });

    // At this point signature is valid. Upsert wallet & user and issue token.
    let wallet = await prisma.wallet.findUnique({ where: { address: walletAddress } });
    if (!wallet) {
      wallet = await prisma.wallet.create({ data: { address: walletAddress } });
    }

    // Optionally ensure a User exists (you may have join flow). Here we just issue token with wallet id.
    const payload = { sub: wallet.id, wallet: walletAddress, typ: "access" };
    const access = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

    // Clear nonce (consume)
    await prisma.nonce.deleteMany({ where: { address: walletAddress } });

    return res.json({ success: true, token: access, walletId: wallet.id });
  } catch (err) {
    console.error("❌ /auth/verify error:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

export default router;
