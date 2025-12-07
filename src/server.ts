// src/server.ts
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";

import authRoutes from "./routes/auth";
import userRoutes from "./routes/user";
import rewardRoutes from "./routes/reward";
import transactionRoutes from "./routes/transaction";
import adminRoutes from "./routes/admin";

// Load environment variables
dotenv.config();

const app = express();

// ===== Middleware =====
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "10mb" }));

// ===== ENV DEBUG =====
console.log("🔍 Loaded ENV keys:", Object.keys(process.env));
console.log(
  "🔍 Mongo URI Status:",
  process.env.MONGO_URI
    ? "Using MONGO_URI"
    : process.env.MONGODB_URI
    ? "Using MONGODB_URI"
    : "❌ NO MONGO URI FOUND"
);

// ===== MongoDB Connection =====
const MONGO_URI =
  process.env.MONGO_URI ||
  process.env.MONGODB_URI ||
  "";

if (!MONGO_URI || MONGO_URI.trim().length === 0) {
  console.error("❌ ERROR: Missing MONGO_URI or MONGODB_URI in environment variables.");
  process.exit(1);
}

mongoose
  .connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
  } as any)
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message || err);
    process.exit(1);
  });

// ===== Routes =====
app.use("/auth", authRoutes);
app.use("/user", userRoutes);
app.use("/rewards", rewardRoutes);
app.use("/transactions", transactionRoutes);
app.use("/admin", adminRoutes);

// ===== Root Check =====
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "FST Backend API is running 🚀" });
});

// ===== Start Server =====
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 http://localhost:${PORT}`);
});
