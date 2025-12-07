// src/routes/transaction.ts
import express from "express";
import mongoose from "mongoose";
import { requireAuth, requireAdmin } from "../middleware/auth";

const router = express.Router();

/* ----------------------------------------------
   MODELS
---------------------------------------------- */
let Transaction: any;
try {
  Transaction = mongoose.model("Transaction");
} catch {
  const transactionSchema = new mongoose.Schema(
    {
      userWallet: String,
      type: String, // EARN, SPEND, ADMIN_ADJUST, REWARD_CLAIM
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
   ADMIN: Adjust User Points
---------------------------------------------- */
router.post("/admin/adjust", requireAdmin, async (req, res) => {
  try {
    const { wallet, amount, reason } = req.body;

    if (!wallet || !amount)
      return res.status(400).json({ success: false, error: "missing_fields" });

    const user = await User.findOne({ wallet });
    if (!user)
      return res.status(404).json({ success: false, error: "user_not_found" });

    user.points += amount;
    await user.save();

    // Log the transaction
    await Transaction.create({
      userWallet: wallet,
      type: "ADMIN_ADJUST",
      amount,
      meta: { reason },
    });

    return res.json({ success: true, points: user.points });
  } catch (err) {
    console.error("❌ Admin Adjust:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

/* ----------------------------------------------
   USER: Earn Points
---------------------------------------------- */
router.post("/earn", requireAuth, async (req: any, res) => {
  try {
    const wallet = req.auth.wallet;
    const { amount, meta } = req.body;

    if (!amount)
      return res.status(400).json({ success: false, error: "missing_amount" });

    const user = await User.findOne({ wallet });
    if (!user)
      return res.status(404).json({ success: false, error: "user_not_found" });

    user.points += amount;
    await user.save();

    await Transaction.create({
      userWallet: wallet,
      type: "EARN",
      amount,
      meta,
    });

    return res.json({ success: true, points: user.points });
  } catch (err) {
    console.error("❌ Earn Points:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

/* ----------------------------------------------
   USER: Spend Points
---------------------------------------------- */
router.post("/spend", requireAuth, async (req: any, res) => {
  try {
    const wallet = req.auth.wallet;
    const { amount, meta } = req.body;

    const user = await User.findOne({ wallet });
    if (!user) return res.status(404).json({ success: false, error: "user_not_found" });

    if (user.points < amount)
      return res.status(400).json({ success: false, error: "insufficient_points" });

    user.points -= amount;
    await user.save();

    await Transaction.create({
      userWallet: wallet,
      type: "SPEND",
      amount: -Math.abs(amount),
      meta,
    });

    return res.json({ success: true, points: user.points });
  } catch (err) {
    console.error("❌ Spend Points:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

/* ----------------------------------------------
   USER: Transaction History
---------------------------------------------- */
router.get("/user", requireAuth, async (req: any, res) => {
  try {
    const wallet = req.auth.wallet;
    const list = await Transaction.find({ userWallet: wallet }).sort({
      createdAt: -1,
    });
    return res.json({ success: true, transactions: list });
  } catch (err) {
    console.error("❌ User Transactions:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

/* ----------------------------------------------
   ADMIN: Full Transaction Logs
---------------------------------------------- */
router.get("/all", requireAdmin, async (req, res) => {
  try {
    const list = await Transaction.find().sort({ createdAt: -1 });
    return res.json({ success: true, transactions: list });
  } catch (err) {
    console.error("❌ All Transactions:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

export default router;
