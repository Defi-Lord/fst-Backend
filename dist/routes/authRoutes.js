"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// src/routes/authRoutes.ts
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = require("crypto");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const bs58_1 = __importDefault(require("bs58"));
const router = express_1.default.Router();
// Temporary in-memory store for wallet challenges
const challenges = new Map();
// POST /auth/challenge → request a message to sign
router.post("/challenge", (req, res) => {
    const { address } = req.body;
    if (!address)
        return res.status(400).json({ error: "Missing address" });
    const challenge = `Sign this message to authenticate: ${(0, crypto_1.randomBytes)(16).toString("hex")}`;
    challenges.set(address, challenge);
    return res.json({ ok: true, challenge });
});
// POST /auth/verify → verify signature + issue JWT
router.post("/verify", (req, res) => {
    const { address, signature } = req.body;
    const challenge = challenges.get(address);
    if (!challenge)
        return res.status(400).json({ error: "No challenge found" });
    try {
        const msg = new TextEncoder().encode(challenge);
        const sig = Buffer.from(signature, "base64");
        const pubkey = bs58_1.default.decode(address);
        const verified = tweetnacl_1.default.sign.detached.verify(msg, sig, pubkey);
        if (!verified)
            return res.status(401).json({ error: "Invalid signature" });
        challenges.delete(address);
        const token = jsonwebtoken_1.default.sign({
            id: address,
            role: address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER",
        }, process.env.JWT_SECRET || "secret", { expiresIn: "7d" });
        return res.json({ ok: true, token });
    }
    catch (err) {
        console.error("verify error", err);
        return res.status(500).json({ error: "Verification failed" });
    }
});
exports.default = router;
