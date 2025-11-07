// src/server.ts
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import { randomUUID } from "crypto";
import dotenv from "dotenv";
import nacl from "tweetnacl";
import bs58 from "bs58";
import helmet from "helmet";
import morgan from "morgan";
import NodeCache from "node-cache";
import https from "https";
import mongoose from "mongoose";
import { issueJwt, requireAuth, requireAdmin } from "./middleware/auth.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3300;
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://luciatrump30_db_user:Gentletiger@cluster0.8eynm3z.mongodb.net/fstdb?retryWrites=true&w=majority";

/* ---------------------------- MongoDB Connection ---------------------------- */
async function connectWithRetry(uri: string, attempts = 0) {
  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
    } as any);
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    if (attempts < 5) {
      const delay = 2000 * (attempts + 1);
      console.log(`🔁 Retrying MongoDB connection in ${delay}ms (attempt ${attempts + 1})`);
      setTimeout(() => connectWithRetry(uri, attempts + 1), delay);
    } else {
      console.error("📛 MongoDB connection failed permanently.");
    }
  }
}
connectWithRetry(MONGO_URI);

process.on("SIGINT", async () => {
  try {
    await mongoose.disconnect();
    console.log("MongoDB disconnected gracefully");
  } finally {
    process.exit(0);
  }
});

/* ------------------------------ SECURITY SETUP ------------------------------ */
app.set("trust proxy", 1);
app.use(cookieParser());
app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);
app.use(morgan("dev"));
app.use(bodyParser.json({ limit: "1mb" }));

/* --------------------------------- CORS ---------------------------------- */
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "https://fst-mini-app.vercel.app",
  "https://fst-mini-app-three.vercel.app",
  "https://fst-mini-app-git-feat-realms-free-and-21953f-defilords-projects.vercel.app",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      console.warn(`🚫 CORS blocked: ${origin}`);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

/* ----------------------------- Mongoose Models ----------------------------- */
type Role = "USER" | "ADMIN";

const userSchema = new mongoose.Schema({
  wallet: { type: String, unique: true },
  token: String,
  role: { type: String, default: "USER" },
  team: [{ playerId: Number }],
  displayName: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
});

const contestSchema = new mongoose.Schema(
  {
    name: String,
    type: { type: String, enum: ["FREE", "WEEKLY", "MONTHLY", "SEASONAL"] },
    entryFee: Number,
    registrationOpen: Boolean,
    participants: [
      {
        wallet: String,
        paid: Boolean,
        entryFee: Number,
        score: Number,
        joinedAt: Date,
      },
    ],
  },
  { timestamps: true }
);

const leaderboardSnapshotSchema = new mongoose.Schema(
  {
    realm: { type: String, enum: ["FREE", "WEEKLY", "MONTHLY", "SEASONAL"], required: true },
    gameweek: { type: Number, required: true },
    entries: [{ wallet: String, points: Number }],
  },
  { timestamps: true }
);

const historySchema = new mongoose.Schema(
  {
    realm: { type: String, enum: ["FREE", "WEEKLY", "MONTHLY", "SEASONAL"], required: true },
    gameweek: { type: Number, required: true },
    entries: [{ wallet: String, points: Number }],
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Contest = mongoose.model("Contest", contestSchema);
const LeaderboardSnapshot = mongoose.model("LeaderboardSnapshot", leaderboardSnapshotSchema);
const History = mongoose.model("History", historySchema);

/* -------------------------- Cache + HTTPS Agent --------------------------- */
const cache = new NodeCache({ stdTTL: 300 });
const httpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });

/* ------------------------------- WALLET AUTH ------------------------------- */
// ... (no changes in auth, admin, or contest routes)

/* ------------------------------ FPL PROXY ENDPOINTS ------------------------------ */
async function safeFetchJson(url: string, cacheKey: string, res: any) {
  try {
    const cached = cache.get(cacheKey);
    if (cached) return res.json(cached);

    const headers = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
      Accept: "application/json, text/plain, */*",
      "Accept-Language": "en-US,en;q=0.9",
    };

    const response = await fetch(url, { headers, agent: httpsAgent as any });
    if (!response.ok) {
      console.warn(`⚠️ Primary fetch failed (${response.status}). Trying proxy...`);
      const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(url)}`;
      const proxyRes = await fetch(proxyUrl, { headers });
      if (!proxyRes.ok) throw new Error(`Proxy fetch failed (${proxyRes.status})`);
      const proxyData = await proxyRes.json();
      cache.set(cacheKey, proxyData);
      return res.json(proxyData);
    }

    const data = await response.json();
    if (!data) throw new Error("Empty JSON response from FPL");
    cache.set(cacheKey, data);
    return res.json(data);
  } catch (err: any) {
    console.error("❌ FPL fetch error:", err?.message || err);
    res.status(500).json({ error: "Failed to fetch FPL data" });
  }
}

// ✅ Updated routes to support both with and without trailing slash
app.get(["/fpl/api/bootstrap-static", "/fpl/api/bootstrap-static/"], (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/bootstrap-static/", "bootstrap", res)
);

app.get(["/fpl/api/fixtures", "/fpl/api/fixtures/"], (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/fixtures/", "fixtures", res)
);

/* ------------------------------- HEALTH ------------------------------- */
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
app.get("/", (req, res) => res.send("✅ FST backend running with MongoDB + Wallet Auth + CORS!"));

// ✅ 404 fallback (handles unknown routes cleanly)
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.originalUrl}` });
});

/* ------------------------------- START ------------------------------- */
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
