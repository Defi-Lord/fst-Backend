// src/routes/reward.ts
import express from "express";
import mongoose from "mongoose";
import { requireAuth, requireAdmin } from "../middleware/auth";

const router = express.Router();

/* ----------------------------------------------
   MODELS
---------------------------------------------- */
let Reward: any;
try {
  Reward = mongoose.model("Reward");
} catch {
  const rewardSchema = new mongoose.Schema(
    {
      title: String,
      description: String,
      image: String,
      category: { type: String, default: "GENERAL" },
      pointsRequired: { type: Number, required: true },
      inventory: { type: Number, default: 0 },
      claimLimit: { type: Number, default: 1 },
      claimedBy: { type: Map, of: Number, default: {} },
    },
    { timestamps: true }
  );
  Reward = mongoose.model("Reward", rewardSchema);
}

let Transaction: any;
try {
  Transaction = mongoose.model("Transaction");
} catch {
  const transactionSchema = new mongoose.Schema(
    {
      userWallet: String,
      type: String,
      amount: Number,
      meta: Object,
    },
    { timestamps: true }
  );
  Transaction = mongoose.model("Transaction", transactionSchema);
}

let User: any;
try {
  User = mongoose.model("User");
} catch {}

/* ----------------------------------------------
   ADMIN: Create Reward
---------------------------------------------- */
router.post("/create", requireAdmin, async (req, res) => {
  try {
    const { title, description, pointsRequired, inventory, claimLimit, image } =
      req.body;

    if (!title || !pointsRequired)
      return res.status(400).json({ success: false, error: "missing_fields" });

    const reward = await Reward.create({
      title,
      description,
      pointsRequired,
      inventory: inventory || 0,
      claimLimit: claimLimit || 1,
      image,
    });

    return res.json({ success: true, reward });
  } catch (err) {
    console.error("❌ Reward Create:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

/* ----------------------------------------------
   ADMIN: Update Reward
---------------------------------------------- */
router.post("/update/:id", requireAdmin, async (req, res) => {
  try {
    const reward = await Reward.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!reward)
      return res.status(404).json({ success: false, error: "not_found" });

    return res.json({ success: true, reward });
  } catch (err) {
    console.error("❌ Reward Update:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

/* ----------------------------------------------
   USER: Claim Reward
---------------------------------------------- */
router.post("/claim/:id", requireAuth, async (req: any, res) => {
  try {
    const wallet = req.auth.wallet;
    const reward = await Reward.findById(req.params.id);

    if (!reward)
      return res.status(404).json({ success: false, error: "reward_not_found" });

    // Get user
    const user = await User.findOne({ wallet });
    if (!user) return res.status(400).json({ success: false, error: "user_not_found" });

    // Check inventory
    if (reward.inventory <= 0)
      return res.status(400).json({ success: false, error: "reward_out_of_stock" });

    // Check if user has enough points
    if (user.points < reward.pointsRequired)
      return res.status(400).json({ success: false, error: "not_enough_points" });

    // Check claim limit
    const previousClaims = reward.claimedBy.get(wallet) || 0;
    if (previousClaims >= reward.claimLimit)
      return res.status(400).json({ success: false, error: "claim_limit_reached" });

    // Deduct points
    user.points -= reward.pointsRequired;
    await user.save();

    // Reduce inventory
    reward.inventory -= 1;
    reward.claimedBy.set(wallet, previousClaims + 1);
    await reward.save();

    // Auto-create transaction entry
    await Transaction.create({
      userWallet: wallet,
      type: "REWARD_CLAIM",
      amount: -reward.pointsRequired,
      meta: { rewardId: reward._id, rewardName: reward.title },
    });

    return res.json({
      success: true,
      message: "Reward claimed successfully",
      reward,
    });
  } catch (err) {
    console.error("❌ Reward Claim:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

/* ----------------------------------------------
   Public: List Rewards
---------------------------------------------- */
router.get("/all", async (req, res) => {
  try {
    const list = await Reward.find().sort({ createdAt: -1 });
    return res.json({ success: true, rewards: list });
  } catch (err) {
    console.error("❌ Reward All:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

export default router;
