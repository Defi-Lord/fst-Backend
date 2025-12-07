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

dotenv.config(); // Loads .env locally in development only

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// ===== ENV DEBUG (HELPFUL FOR DEPLOY TROUBLESHOOTING) =====
console.log("🔍 Loaded ENV keys:", Object.keys(process.env));
console.log(
  "🔍 Mongo URI status:",
  process.env.MONGO_URI ? "MONGO_URI ✔" : process.env.MONGODB_URI ? "MONGODB_URI ✔" : "❌ NOT SET"
);

// === MongoDB Connection ===
// Supports both common names: MONGO_URI and MONGODB_URI
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || "";

if (!MONGO_URI || MONGO_URI.trim().length === 0) {
  console.error("❌ Missing MONGO_URI or MONGODB_URI in environment variables");
  process.exit(1);
}

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Routes
app.use("/auth", authRoutes);
app.use("/user", userRoutes);
app.use("/rewards", rewardRoutes);
app.use("/transactions", transactionRoutes);
app.use("/admin", adminRoutes);

// Default route
app.get("/", (req, res) => {
  res.send("FST Backend API is running 🚀");
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
