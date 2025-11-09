"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const prisma_js_1 = require("../lib/prisma.js");
const router = (0, express_1.Router)();
// Helper to generate realistic Solana-style Base58 addresses
function generateSolanaAddress() {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let address = "";
    for (let i = 0; i < 44; i++) {
        address += alphabet[Math.floor(Math.random() * alphabet.length)];
    }
    return address;
}
// Helper to generate nonce
function generateNonce() {
    return Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
}
// Telegram Auth Route
router.post("/auth/telegram", async (req, res) => {
    try {
        const { telegramId, username } = req.body;
        if (!telegramId || !username) {
            return res.status(400).json({
                success: false,
                message: "Missing telegramId or username",
            });
        }
        let user = await prisma_js_1.prisma.user.findUnique({
            where: { telegramId },
            include: { wallet: true },
        });
        if (!user) {
            const walletAddress = generateSolanaAddress();
            const wallet = await prisma_js_1.prisma.wallet.create({
                data: { address: walletAddress },
            });
            user = await prisma_js_1.prisma.user.create({
                data: {
                    telegramId,
                    displayName: username,
                    role: "USER",
                    wallet: { connect: { id: wallet.id } },
                },
                include: { wallet: true },
            });
            console.log(`✅ New Telegram user created: ${username}`);
            console.log(`💰 Wallet created for user: ${walletAddress}`);
        }
        else {
            console.log(`🔁 Existing Telegram user found: ${username}`);
        }
        return res.status(200).json({ success: true, user });
    }
    catch (error) {
        console.error("❌ Error during Telegram auth:", error);
        return res.status(500).json({ success: false, error: "Server error" });
    }
});
// 🆕 Generate Nonce for Wallet Verification
router.post("/auth/nonce", async (req, res) => {
    try {
        const { address } = req.body;
        if (!address) {
            return res
                .status(400)
                .json({ success: false, message: "Wallet address is required" });
        }
        const newNonceValue = generateNonce();
        const nonce = await prisma_js_1.prisma.nonce.upsert({
            where: { address },
            update: { nonce: newNonceValue, createdAt: new Date() },
            create: { address, nonce: newNonceValue },
        });
        console.log(`🔁 Nonce generated for wallet ${address}`);
        return res.status(200).json({ success: true, nonce: nonce.nonce });
    }
    catch (error) {
        console.error("❌ Error generating nonce:", error);
        return res.status(500).json({ success: false, error: "Server error" });
    }
});
// Get user by Telegram ID
router.get("/user/:telegramId", async (req, res) => {
    try {
        const { telegramId } = req.params;
        const user = await prisma_js_1.prisma.user.findUnique({
            where: { telegramId },
            include: { wallet: true },
        });
        if (!user) {
            return res
                .status(404)
                .json({ success: false, message: "User not found" });
        }
        return res.status(200).json({ success: true, user });
    }
    catch (error) {
        console.error("❌ Error fetching user:", error);
        return res.status(500).json({ success: false, error: "Server error" });
    }
});
exports.default = router;
