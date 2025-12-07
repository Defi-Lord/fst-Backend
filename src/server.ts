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

dotenv.config(); // Loads local .env only in development

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// ==== ENV DEBUG (SAFE FOR PROD) ====
console.log("🔍 Loaded ENV keys:", Object.keys(process.env));
console.log("🔍 MONGO_URI value:", process.env.MONGO_URI ? "SET ✔" : "NOT SET ❌");

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI || MONGO_URI.trim().length === 0) {
  console.error("❌ Missing MONGO_URI in environment variables (value is empty)");
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
