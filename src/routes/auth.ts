import express, { Request, Response } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { prisma } from "../lib/prisma.js";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const NONCE_TTL_SEC = 300; // 5 minutes

// POST /auth/nonce
router.post("/nonce", async (req: Request, res: Response) => {
  try {
    const { walletAddress } = req.body;
    if (!walletAddress)
      return res.status(400).json({ success: false, error: "walletAddress required" });

    const nonce = crypto.randomBytes(16).toString("hex");
    const message = `FST login\n\nWallet: ${walletAddress}\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}\n\nBy signing this message you prove ownership of the wallet.`;

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
router.post("/verify", async (req: Request, res: Response) => {
  try {
    const { walletAddress, signature } = req.body;
    if (!walletAddress || !signature)
      return res.status(400).json({ success: false, error: "missing_params" });

    const stored = await prisma.nonce.findUnique({ where: { address: walletAddress } });
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

    let wallet = await prisma.wallet.findUnique({ where: { address: walletAddress } });
    if (!wallet) wallet = await prisma.wallet.create({ data: { address: walletAddress } });

    const payload = { sub: wallet.id, wallet: walletAddress, typ: "access" };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

    await prisma.nonce.deleteMany({ where: { address: walletAddress } });

    return res.json({ success: true, token, walletId: wallet.id });
  } catch (err) {
    console.error("❌ /auth/verify error:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

export default router;
