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
import cron from "node-cron";
import { issueJwt, requireAuth, requireAdmin } from "./middleware/auth.js";
import { Connection, clusterApiUrl } from "@solana/web3.js";

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
      console.log(
        `🔁 Retrying MongoDB connection in ${delay}ms (attempt ${attempts + 1})`
      );
      setTimeout(() => connectWithRetry(uri, attempts + 1), delay);
    } else {
      console.error("📛 MongoDB connection failed permanently.");
    }
  }
}
connectWithRetry(MONGO_URI);

/* ------------------------------ SECURITY SETUP ------------------------------ */
app.set("trust proxy", 1);
app.use(cookieParser());
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan("dev"));
app.use(bodyParser.json({ limit: "2mb" }));

/* --------------------------------- CORS ---------------------------------- */
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "https://fst-mini-app.vercel.app",
  "https://fst-mini-app-three.vercel.app",
  "https://fst-mini-app-git-feat-realms-free-and-contest-defi-lord.vercel.app",
  "https://fst-mini-app-git-feat-realms-free-and-contest-defilords-projects.vercel.app",
];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      console.warn(`🚫 CORS blocked request from: ${origin}`);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

/* ----------------------------- Mongoose Models ----------------------------- */
type Role = "USER" | "ADMIN";

const userSchema = new mongoose.Schema(
  {
    wallet: { type: String, unique: true },
    token: String,
    role: { type: String, default: "USER" },
    team: [{ playerId: Number }],
    displayName: { type: String, default: null },
  },
  { timestamps: true }
);

const contestSchema = new mongoose.Schema(
  {
    name: String,
    type: { type: String, enum: ["FREE", "WEEKLY", "MONTHLY", "SEASONAL"] },
    entryFee: { type: Number, default: 0 },
    registrationOpen: Boolean,
    participants: [
      {
        wallet: String,
        paid: Boolean,
        entryFee: Number,
        txSignature: String,
        score: Number,
        joinedAt: Date,
      },
    ],
  },
  { timestamps: true }
);

const transactionSchema = new mongoose.Schema(
  {
    wallet: String,
    txSignature: { type: String, unique: true },
    amount: Number,
    confirmed: Boolean,
  },
  { timestamps: true }
);

const fplCacheSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true },
    data: Object,
    lastUpdated: Date,
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Contest = mongoose.model("Contest", contestSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);
const FPLCache = mongoose.model("FPLCache", fplCacheSchema);

/* -------------------------- Cache + HTTPS Agent --------------------------- */
const cache = new NodeCache({ stdTTL: 300 }); // 5 min TTL
const httpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });

/* ------------------------------- WALLET AUTH ------------------------------- */
const walletNonces = new Map<string, string>();

app.post("/auth/challenge", (req, res) => {
  try {
    const { address } = req.body;
    if (!address) return res.status(400).json({ error: "Missing wallet address" });
    const challenge = `Sign this message to verify your wallet: ${randomUUID()}`;
    walletNonces.set(address, challenge);
    res.json({ ok: true, challenge });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/verify", async (req, res) => {
  try {
    const { address, signature, message } = req.body;
    if (!address || !signature || !message)
      return res.status(400).json({ error: "Missing required fields" });

    const expected = walletNonces.get(address);
    if (!expected || expected !== message)
      return res.status(400).json({ error: "No challenge found" });

    const publicKeyBytes = bs58.decode(address);
    const signatureBytes = Uint8Array.from(Buffer.from(signature, "base64"));
    const messageBytes = new TextEncoder().encode(message);
    const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
    if (!isValid) return res.status(401).json({ error: "Invalid signature" });

    walletNonces.delete(address);
    const role: Role = address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER";
    const token = issueJwt({ userId: address, role });

    await User.findOneAndUpdate({ wallet: address }, { token, role }, { upsert: true });
    res.json({ ok: true, token, role });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/introspect", requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ wallet: req.auth!.userId });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ ok: true, role: user.role, wallet: user.wallet });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------------------------- FPL API PROXY (DB + CACHE) ---------------------------- */
app.get("/fpl/api/*", async (req, res) => {
  try {
    const endpoint = req.params[0];
    const key = `fpl:${endpoint}`;

    // Check cache first
    const cached = cache.get(key);
    if (cached) return res.json(cached);

    // Try DB fallback if FPL fails
    const url = `https://fantasy.premierleague.com/api/${endpoint}`;
    const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;

    const response = await fetch(proxyUrl, { agent: httpsAgent });
    if (!response.ok) {
      console.warn(`⚠️ FPL upstream returned ${response.status}`);
      const dbData = await FPLCache.findOne({ key });
      if (dbData) return res.json(dbData.data);
      return res.status(502).json({ error: "FPL upstream blocked request" });
    }

    const data = await response.json();
    cache.set(key, data);
    await FPLCache.findOneAndUpdate(
      { key },
      { data, lastUpdated: new Date() },
      { upsert: true }
    );

    res.json(data);
  } catch (err) {
    console.error("❌ FPL proxy error:", err);
    const dbData = await FPLCache.findOne({ key: req.params[0] });
    if (dbData) return res.json(dbData.data);
    res.status(500).json({ error: "FPL proxy failed" });
  }
});

/* -------------------------- Hourly FPL Data Refresh -------------------------- */
async function refreshFPLData() {
  const endpoints = ["bootstrap-static/", "fixtures/"];
  for (const ep of endpoints) {
    const url = `https://fantasy.premierleague.com/api/${ep}`;
    const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
    try {
      const response = await fetch(proxyUrl, { agent: httpsAgent });
      if (!response.ok) throw new Error(`FPL ${ep} failed: ${response.status}`);
      const data = await response.json();
      await FPLCache.findOneAndUpdate(
        { key: `fpl:${ep}` },
        { data, lastUpdated: new Date() },
        { upsert: true }
      );
      console.log(`✅ FPL cache refreshed: ${ep}`);
    } catch (err) {
      console.warn(`⚠️ FPL refresh failed for ${ep}:`, err);
    }
  }
}
cron.schedule("0 * * * *", refreshFPLData); // every hour
setTimeout(refreshFPLData, 5000); // initial refresh on boot

/* -------------------------- VERIFY PAYMENT -------------------------- */
const solana = new Connection(clusterApiUrl("mainnet-beta"), "confirmed");

async function verifySolanaTx(signature: string, expectedWallet: string, minAmountLamports: number) {
  try {
    const tx = await solana.getTransaction(signature, { commitment: "confirmed" });
    if (!tx) return false;
    const accountKeys = tx.transaction.message.accountKeys.map((k) => k.toBase58());
    if (!accountKeys.includes(expectedWallet)) return false;
    const post = tx.meta?.postBalances ?? [];
    const pre = tx.meta?.preBalances ?? [];
    const diff = pre[0] - post[0];
    return diff >= minAmountLamports;
  } catch {
    return false;
  }
}

/* ----------------------------- ADMIN ROUTES ----------------------------- */
app.get("/admin/contests", requireAdmin, async (_req, res) => {
  const contests = await Contest.find().sort({ createdAt: -1 });
  res.json({ ok: true, contests });
});

/* -------------------------- JOIN CONTEST -------------------------- */
app.post("/contests/:id/join", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { txSignature } = req.body;
  const wallet = req.auth!.userId;

  const contest = await Contest.findById(id);
  if (!contest || !contest.registrationOpen)
    return res.status(400).json({ error: "Contest not open" });

  if (contest.entryFee === 0) {
    const exists = contest.participants.find((p: any) => p.wallet === wallet);
    if (!exists) {
      contest.participants.push({
        wallet,
        paid: true,
        entryFee: 0,
        txSignature: null,
        score: 0,
        joinedAt: new Date(),
      });
      await contest.save();
    }
    return res.json({ ok: true, message: "Joined free contest" });
  }

  if (!txSignature)
    return res.status(400).json({ error: "Missing transaction signature" });

  const lamports = (contest.entryFee || 0) * 1e9;
  const verified = await verifySolanaTx(txSignature, wallet, lamports);
  if (!verified) return res.status(400).json({ error: "Transaction not verified" });

  await Transaction.create({ wallet, txSignature, amount: contest.entryFee, confirmed: true });

  const exists = contest.participants.find((p: any) => p.wallet === wallet);
  if (!exists) {
    contest.participants.push({
      wallet,
      paid: true,
      entryFee: contest.entryFee,
      txSignature,
      score: 0,
      joinedAt: new Date(),
    });
    await contest.save();
  }

  res.json({ ok: true, message: "Successfully joined contest" });
});

/* ------------------------------- HEALTH ------------------------------- */
app.get("/health", (_req, res) => res.json({ status: "ok" }));
app.get("/", (_req, res) =>
  res.send("✅ FST backend running with MongoDB + hourly FPL cache + Solana payments!")
);
app.use((_req, res) => res.status(404).json({ error: "Route not found" }));

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
