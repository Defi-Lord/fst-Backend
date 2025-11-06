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
// ✅ Clean and safe CORS setup (fixes your frontend issue)
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
      if (!origin) return callback(null, true); // allow server-to-server, Postman
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

const userSchema = new mongoose.Schema(
  {
    wallet: { type: String, unique: true },
    token: String,
    role: { type: String, default: "USER" },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

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
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Contest = mongoose.model("Contest", contestSchema);

/* -------------------------- Cache + HTTPS Agent --------------------------- */
const cache = new NodeCache({ stdTTL: 300 });
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
    console.error("❌ Challenge error:", err);
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
    const signatureBytes =
      typeof signature === "string"
        ? Uint8Array.from(Buffer.from(signature, "base64"))
        : new Uint8Array(signature.data || signature);
    const messageBytes = new TextEncoder().encode(message);
    const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
    if (!isValid) return res.status(401).json({ error: "Invalid signature" });

    walletNonces.delete(address);
    const role: Role = address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER";
    const token = issueJwt({ userId: address, role });

    await User.findOneAndUpdate(
      { wallet: address },
      { token, role, createdAt: new Date() },
      { new: true, upsert: true }
    );

    res.json({ ok: true, token, role });
  } catch (err) {
    console.error("❌ Verify wallet error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/introspect", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(200).json({ active: false, payload: { role: "USER" } });
    const user = await User.findOne({ token });
    if (!user) return res.status(200).json({ active: false, payload: { role: "USER" } });
    res.json({ active: true, payload: { role: user.role } });
  } catch (err) {
    console.error("❌ Introspect error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ wallet: req.auth!.userId });
    if (!user) return res.status(401).json({ error: "Invalid token" });
    res.json({ user: { id: user.wallet, role: user.role } });
  } catch (err) {
    console.error("❌ /me error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* -------------------------------- ADMIN -------------------------------- */
app.get("/admin/contests", requireAdmin, async (req, res) => {
  const contests = await Contest.find({});
  res.json({ contests });
});

/* ------------------------------- USER JOIN ------------------------------- */
app.post("/contests/:id/join", requireAuth, async (req, res) => {
  const id = req.params.id;
  const { payNow } = req.body;
  const wallet = req.auth!.userId;

  const contest = await Contest.findById(id);
  if (!contest) return res.status(404).json({ error: "Contest not found" });

  const alreadyJoined = (contest.participants || []).find((p) => p.wallet === wallet);
  if (alreadyJoined) return res.json({ joined: true });

  const paid = contest.entryFee === 0 || Boolean(payNow);
  contest.participants.push({
    wallet,
    paid,
    entryFee: contest.entryFee,
    score: 0,
    joinedAt: new Date(),
  });
  await contest.save();

  res.json({ joined: true });
});

/* ------------------------------ FPL PROXY ------------------------------ */
async function safeFetchJson(url: string, cacheKey: string, res: any) {
  try {
    const cached = cache.get(cacheKey);
    if (cached) return res.json(cached);

    const response = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0" },
      agent: httpsAgent as any,
    });

    const text = await response.text();
    let parsed: any = null;

    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      console.warn(`⚠️ Invalid JSON from ${url}, using fallback proxy`);
      const proxy = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
      const fallbackRes = await fetch(proxy);
      parsed = await fallbackRes.json();
    }

    cache.set(cacheKey, parsed);
    res.json(parsed);
  } catch (err: any) {
    console.error("❌ FPL fetch error:", err?.message || err);
    res.status(500).json({ error: "Failed to fetch FPL data" });
  }
}

app.get("/fpl/api/bootstrap-static/", (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/bootstrap-static/", "bootstrap", res)
);
app.get("/fpl/api/fixtures/", (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/fixtures/", "fixtures", res)
);

/* ------------------------------- HEALTH ------------------------------- */
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
app.get("/", (req, res) => res.send("✅ FST backend running with MongoDB + Wallet Auth + CORS!"));

/* ------------------------------- START ------------------------------- */
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
