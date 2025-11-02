import express from "express";
import { PrismaClient } from "@prisma/client";
const router = express.Router();
const prisma = new PrismaClient();
router.post("/telegram", async (req, res) => {
    try {
        const { telegramId, username } = req.body;
        console.log("📩 Received:", { telegramId, username }); // log the incoming data
        if (!telegramId || !username) {
            return res.status(400).json({ success: false, message: "Missing data" });
        }
        // check if the user exists using the ID
        let user = await prisma.user.findUnique({
            where: { id: telegramId },
        });
        if (!user) {
            console.log("🆕 Creating new user...");
            user = await prisma.user.create({
                data: { id, displayName, telegramId: id },
            });
            console.log("✅ User created:", user);
        }
        else {
            console.log("👤 Existing user found:", user);
        }
        return res.json({ success: true, user });
    }
    catch (err) {
        console.error("❌ Error in /auth/telegram route:", err);
        return res.status(500).json({ success: false, error: "Server error" });
    }
});
export default router;
