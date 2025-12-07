// src/routes/reward.ts
import express from "express";
import mongoose from "mongoose";
import { requireAuth, requireAdmin } from "../middleware/auth";

const router = express.Router();

// Ensure Reward model exists
let Reward: any;
try {
  Reward = mongoose.model("Reward");
} catch {
  const rewardSchema = new mongoose.Schema(
    {
      title: String,
      description: String,
      points: Number,
      image: String,
    },
    { timestamps: true }
  );
  Reward = mongoose.model("Reward", rewardSchema);
}

// GET /reward/all  (public or protected depending on your preference)
router.get("/all", async (req, res) => {
  try {
    const list = await Reward.find().sort({ createdAt: -1 });
    return res.json({ success: true, rewards: list });
  } catch (err) {
    console.error("❌ GET /reward/all:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// POST /reward/create (ADMIN)
router.post("/create", requireAdmin, async (req, res) => {
  try {
    const { title, description, points, image } = req.body;

    if (!title || !points)
      return res.status(400).json({ success: false, error: "missing_fields" });

    const reward = await Reward.create({ title, description, points, image });

    return res.json({ success: true, reward });
  } catch (err) {
    console.error("❌ POST /reward/create:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// POST /reward/update/:id (ADMIN)
router.post("/update/:id", requireAdmin, async (req, res) => {
  try {
    const reward = await Reward.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!reward)
      return res.status(404).json({ success: false, error: "reward_not_found" });

    return res.json({ success: true, reward });
  } catch (err) {
    console.error("❌ POST /reward/update:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// POST /reward/claim/:id (USER)
router.post("/claim/:id", requireAuth, async (req: any, res) => {
  try {
    const reward = await Reward.findById(req.params.id);
    if (!reward)
      return res.status(404).json({ success: false, error: "reward_not_found" });

    // Basic claim confirmation (adjust if needed)
    return res.json({ success: true, message: "Reward claimed", reward });
  } catch (err) {
    console.error("❌ POST /reward/claim:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

export default router;
