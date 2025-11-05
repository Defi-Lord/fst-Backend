// src/routes/authRoutes.ts
import express from "express";
import jwt from "jsonwebtoken";
import { randomBytes } from "crypto";
import nacl from "tweetnacl";
import bs58 from "bs58";

const router = express.Router();

// Temporary in-memory store for wallet challenges
const challenges = new Map<string, string>();

// POST /auth/challenge → request a message to sign
router.post("/challenge", (req, res) => {
  const { address } = req.body;
  if (!address) return res.status(400).json({ error: "Missing address" });

  const challenge = `Sign this message to authenticate: ${randomBytes(16).toString("hex")}`;
  challenges.set(address, challenge);

  return res.json({ ok: true, challenge });
});

// POST /auth/verify → verify signature + issue JWT
router.post("/verify", (req, res) => {
  const { address, signature } = req.body;
  const challenge = challenges.get(address);
  if (!challenge) return res.status(400).json({ error: "No challenge found" });

  try {
    const msg = new TextEncoder().encode(challenge);
    const sig = Buffer.from(signature, "base64");
    const pubkey = bs58.decode(address);

    const verified = nacl.sign.detached.verify(msg, sig, pubkey);
    if (!verified) return res.status(401).json({ error: "Invalid signature" });

    challenges.delete(address);

    const token = jwt.sign(
      {
        id: address,
        role: address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER",
      },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "7d" }
    );

    return res.json({ ok: true, token });
  } catch (err) {
    console.error("verify error", err);
    return res.status(500).json({ error: "Verification failed" });
  }
});

export default router;
