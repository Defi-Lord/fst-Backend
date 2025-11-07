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

/* ------------------------------ SECURITY SETUP ------------------------------ */
app.set("trust proxy", 1);
app.use(cookieParser());
app.use(helmet({ crossOriginResourcePolicy: false }));
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
    entryFee: Number,
    registrationOpen: Boolean,
    participants: [
      { wallet: String, paid: Boolean, entryFee: Number, score: Number, joinedAt: Date },
    ],
  },
  { timestamps: true }
);

const snapshotSchema = new mongoose.Schema(
  {
    realm: String,
    gameweek: Number,
    entries: [{ wallet: String, points: Number }],
  },
  { timestamps: true }
);

const historySchema = new mongoose.Schema(
  {
    realm: String,
    gameweek: Number,
    entries: [{ wallet: String, points: Number }],
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Contest = mongoose.model("Contest", contestSchema);
const LeaderboardSnapshot = mongoose.model("LeaderboardSnapshot", snapshotSchema);
const History = mongoose.model("History", historySchema);

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
    const signatureBytes = Uint8Array.from(Buffer.from(signature, "base64"));
    const messageBytes = new TextEncoder().encode(message);
    const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
    if (!isValid) return res.status(401).json({ error: "Invalid signature" });

    walletNonces.delete(address);
    const role: Role = address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER";
    const token = issueJwt({ userId: address, role });

    await User.findOneAndUpdate(
      { wallet: address },
      { token, role },
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
    const user = token ? await User.findOne({ token }) : null;
    if (!user) return res.json({ active: false, payload: { role: "USER" } });
    res.json({ active: true, payload: { role: user.role } });
  } catch (err) {
    console.error("❌ Introspect error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/me", requireAuth, async (req, res) => {
  const user = await User.findOne({ wallet: req.auth!.userId });
  if (!user) return res.status(401).json({ error: "Invalid token" });
  res.json({ user: { id: user.wallet, role: user.role, displayName: user.displayName } });
});

/* ------------------------------- ADMIN ROUTES ------------------------------- */
app.get("/admin/users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}, "wallet role displayName createdAt updatedAt").lean();
    res.json({ users });
  } catch (err) {
    console.error("❌ /admin/users error:", err);
    res.status(500).json({ error: "Failed to load users" });
  }
});

app.get("/admin/contests", requireAdmin, async (req, res) => {
  try {
    const contests = await Contest.find({}).lean();
    res.json({ contests });
  } catch (err) {
    console.error("❌ /admin/contests error:", err);
    res.status(500).json({ error: "Failed to load contests" });
  }
});

/* ---------------------------- FPL FETCH HELPER ---------------------------- */
async function fetchJson(url: string) {
  const headers = {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    Accept: "application/json,text/plain,*/*",
    "Accept-Language": "en-US,en;q=0.9",
    Referer: "https://fantasy.premierleague.com/",
    Origin: "https://fantasy.premierleague.com",
  };

  const cached = cache.get(url);
  if (cached) return cached;

  const proxies = [
    url,
    `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
    `https://corsproxy.io/?${encodeURIComponent(url)}`,
    `https://thingproxy.freeboard.io/fetch/${url}`,
  ];

  for (const proxy of proxies) {
    try {
      const resp = await fetch(proxy, { headers, agent: httpsAgent as any, timeout: 15000 });
      if (!resp.ok) throw new Error(`Bad status ${resp.status}`);
      const data = await resp.json();
      cache.set(url, data);
      return data;
    } catch (err: any) {
      console.warn(`⚠️ Proxy failed (${proxy}): ${err.message}`);
      continue;
    }
  }
  throw new Error(`All proxies failed for ${url}`);
}

/* ------------------------- FPL SYNC + SNAPSHOT -------------------------- */
const lastSyncedEvent: Record<string, number | null> = {
  FREE: null,
  WEEKLY: null,
  MONTHLY: null,
  SEASONAL: null,
};

// (same computeAndStoreSnapshots function as before…)

/* ------------------------------- FPL API PROXY ------------------------------- */
app.get(["/fpl/api/bootstrap-static", "/fpl/api/bootstrap-static/"], async (req, res) => {
  const data = await fetchJson("https://fantasy.premierleague.com/api/bootstrap-static/");
  res.json(data);
});

app.get(["/fpl/api/fixtures", "/fpl/api/fixtures/"], async (req, res) => {
  const data = await fetchJson("https://fantasy.premierleague.com/api/fixtures/");
  res.json(data);
});

/* ------------------------------- HEALTH ------------------------------- */
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
app.get("/", (req, res) =>
  res.send("✅ FST backend running with MongoDB + Wallet Auth + CORS + Admin routes!")
);

/* 404 fallback */
app.use((req, res) => res.status(404).json({ error: `Route not found: ${req.originalUrl}` }));

/* ------------------------------- START ------------------------------- */
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
