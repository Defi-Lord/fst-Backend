import express, { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.js";
import adminRoutes from "./routes/admin.js";
import contestsRoutes from "./routes/contests.js";
import fplRoutes from "./routes/fpl.js";

dotenv.config();

const app = express();

// ================= MIDDLEWARE ================
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "*",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(helmet());

// Optional: Basic rate limiting
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 500,
  })
);

// =============== ROUTES =====================

// AUTH (Correct version from /routes/auth.ts)
app.use("/auth", authRoutes);

// ADMIN ROUTES
app.use("/admin", adminRoutes);

// FPL + USER + CONTEST ROUTES
app.use("/fpl", fplRoutes);
app.use("/contests", contestsRoutes);

// =============== HEALTH CHECK ==================
app.get("/health", (req: Request, res: Response) => {
  return res.json({ ok: true, status: "server is running" });
});

// =============== JWT DEBUG (OPTIONAL) ==================
app.post("/debug/decode", (req: Request, res: Response) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    return res.json({ ok: true, decoded });
  } catch (err: any) {
    return res.status(400).json({ ok: false, error: err.message });
  }
});

// =============== 404 HANDLER ==================
app.use("*", (req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// =============== SERVER START ==================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🔥 Server running on port ${PORT}`);
});
