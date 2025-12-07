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

dotenv.config();

const app = express();

/* ======================================================
   ✅ CORS CONFIG — FIXED FOR CREDENTIALS
====================================================== */
const allowedOrigins = [
  "https://fst-mini-app-three.vercel.app",
  "http://localhost:3000"
];

app.use(
  cors({
    origin: (origin, callback) => {
      // allow server-to-server / curl / same-origin
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ✅ REQUIRED for Render / preflight
app.options("*", cors());

/* ======================================================
   MIDDLEWARE
====================================================== */
app.use(express.json());

/* ======================================================
   🔍 ENV DEBUG (SAFE)
====================================================== */
console.log("🔍 ENV loaded:", {
  PORT: process.env.PORT ? "✔" : "❌",
  MONGO_URI: process.env.MONGO_URI ? "✔" : "❌",
  MONGODB_URI: process.env.MONGODB_URI ? "✔" : "❌",
});

/* ======================================================
   ✅ MongoDB Connection
====================================================== */
const MONGO_URI =
  process.env.MONGO_URI ||
  process.env.MONGODB_URI ||
  "";

if (!MONGO_URI) {
  console.error("❌ Missing MONGO_URI / MONGODB_URI");
  process.exit(1);
}

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

/* ======================================================
   ROUTES
====================================================== */
app.use("/auth", authRoutes);
app.use("/user", userRoutes);
app.use("/rewards", rewardRoutes);
app.use("/transactions", transactionRoutes);
app.use("/admin", adminRoutes);

/* ======================================================
   HEALTH CHECK
====================================================== */
app.get("/", (_req, res) => {
  res.send("✅ FST Backend API is running");
});

/* ======================================================
   START SERVER
====================================================== */
const PORT = Number(process.env.PORT) || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
