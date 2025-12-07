// src/routes/transaction.ts
import express from "express";
import mongoose from "mongoose";
import { requireAuth, requireAdmin } from "../middleware/auth";

const router = express.Router();

// Ensure Transaction model exists
let Transaction: any;
try {
  Transaction = mongoose.model("Transaction");
} catch {
  const transactionSchema = new mongoose.Schema(
    {
      userWallet: String,
      type: String, // e.g. "EARN", "SPEND", "REWARD"
      amount: Number,
      meta: Object,
    },
    { timestamps: true }
  );
  Transaction = mongoose.model("Transaction", transactionSchema);
}

// POST /transaction/create
router.post("/create", requireAuth, async (req: any, res) => {
  try {
    const { type, amount, meta } = req.body;

    if (!type || !amount)
      return res.status(400).json({ success: false, error: "missing_fields" });

    const tx = await Transaction.create({
      userWallet: req.auth.wallet,
      type,
      amount,
      meta,
    });

    return res.json({ success: true, transaction: tx });
  } catch (err) {
    console.error("❌ POST /transaction/create:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// GET /transaction/user
router.get("/user", requireAuth, async (req: any, res) => {
  try {
    const list = await Transaction.find({ userWallet: req.auth.wallet }).sort({
      createdAt: -1,
    });

    return res.json({ success: true, transactions: list });
  } catch (err) {
    console.error("❌ GET /transaction/user:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

// GET /transaction/all (ADMIN)
router.get("/all", requireAdmin, async (req, res) => {
  try {
    const list = await Transaction.find().sort({ createdAt: -1 });

    return res.json({ success: true, transactions: list });
  } catch (err) {
    console.error("❌ GET /transaction/all:", err);
    return res.status(500).json({ success: false, error: "server_error" });
  }
});

export default router;
