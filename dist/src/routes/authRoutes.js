import { Router } from "express";
import { PrismaClient } from "@prisma/client";
const router = Router();
const prisma = new PrismaClient();
router.post("/register", async (req, res) => {
    try {
        const { id, displayName } = req.body; // ✅ Get from request body
        if (!id || !displayName) {
            return res.status(400).json({ error: "Missing id or displayName" });
        }
        const user = await prisma.user.create({
            data: { id, displayName, telegramId: id },
        });
        res.status(201).json(user);
    }
    catch (error) {
        console.error("Error creating user:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
export default router;
