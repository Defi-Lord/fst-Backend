// src/server.ts
import express from "express";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { prisma } from "./lib/prisma.js";
import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/user.js"; // keep your user routes as-is

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3300;

app.use(cors({ origin: process.env.CORS_ORIGIN || true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev"));

// Mount
app.use("/auth", authRoutes);
app.use("/user", userRoutes);

// health
app.get("/", (req, res) => res.json({ ok: true, msg: "Backend is running and connected!" }));

async function connectDB() {
  try {
    await prisma.$connect();
    console.log("✅ Connected to PostgreSQL (via Prisma)");
  } catch (err) {
    console.error("❌ Database connection failed:", err);
    process.exit(1);
  }
}

connectDB().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
});
