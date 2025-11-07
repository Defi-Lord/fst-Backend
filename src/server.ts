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
  const { address } = req.body;
  if (!address) return res.status(400).json({ error: "Missing wallet address" });
  const challenge = `Sign this message to verify your wallet: ${randomUUID()}`;
  walletNonces.set(address, challenge);
  res.json({ ok: true, challenge });
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
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Server error" });
  }
});

/* ------------------------------ FETCH HELPERS ------------------------------ */
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
  let resp = await fetch(url, { headers, agent: httpsAgent as any });
  if (resp.status === 403 || resp.status === 404) {
    console.warn(`⚠️ FPL blocked ${url}, using proxy...`);
    const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
    resp = await fetch(proxyUrl, { headers });
  }
  if (!resp.ok) throw new Error(`Fetch failed ${resp.status}`);
  const data = await resp.json();
  cache.set(url, data);
  return data;
}

/* ------------------------- FPL SYNC + SNAPSHOT -------------------------- */
const lastSyncedEvent: Record<string, number | null> = {
  FREE: null,
  WEEKLY: null,
  MONTHLY: null,
  SEASONAL: null,
};

async function computeAndStoreSnapshots() {
  try {
    const bootstrap = await fetchJson("https://fantasy.premierleague.com/api/bootstrap-static/");
    const current_event =
      Number(
        bootstrap?.event ||
          bootstrap?.current_event ||
          bootstrap?.events?.find((e: any) => e.is_current)?.id
      ) || 0;
    const elements = bootstrap?.elements || [];
    const seasonPoints = new Map(elements.map((el: any) => [el.id, el.total_points || 0]));

    let liveMap = new Map<number, number>();
    if (current_event) {
      const live = await fetchJson(
        `https://fantasy.premierleague.com/api/event/${current_event}/live/`
      );
      for (const el of live?.elements || []) {
        liveMap.set(el.id, el.stats?.total_points ?? 0);
      }
    }

    const allUsers = await User.find({}).lean();
    const realms: Array<"FREE" | "WEEKLY" | "MONTHLY" | "SEASONAL"> = [
      "FREE",
      "WEEKLY",
      "MONTHLY",
      "SEASONAL",
    ];

    for (const realm of realms) {
      const entries = allUsers.map((u) => {
        const team = Array.isArray(u.team) ? u.team : [];
        const ids = team.map((t: any) => t.playerId).filter(Boolean);
        let total = 0;
        for (const id of ids) {
          total += realm === "FREE" ? seasonPoints.get(id) || 0 : liveMap.get(id) || 0;
        }
        return { wallet: u.wallet, points: Math.round(total) };
      });

      entries.sort((a, b) => b.points - a.points);
      const gameweek = current_event || 0;

      await LeaderboardSnapshot.findOneAndUpdate(
        { realm, gameweek },
        { realm, gameweek, entries },
        { upsert: true }
      );

      const last = lastSyncedEvent[realm];
      if (last != null && last !== gameweek) {
        const prevSnap = await LeaderboardSnapshot.findOne({ realm, gameweek: last }).lean();
        if (prevSnap && !(await History.findOne({ realm, gameweek: last }))) {
          await new History(prevSnap).save();
          const toKeep = await History.find({ realm }).sort({ gameweek: -1 }).limit(10);
          const keepIds = toKeep.map((d: any) => d._id);
          await History.deleteMany({ realm, _id: { $nin: keepIds } });
        }
      }
      lastSyncedEvent[realm] = gameweek;
    }
    console.log(`✅ FPL sync completed for GW${current_event}`);
  } catch (err: any) {
    console.error("❌ computeAndStoreSnapshots error:", err?.message || err);
  }
}

setInterval(computeAndStoreSnapshots, 1000 * 60 * 60);
computeAndStoreSnapshots();

/* ------------------------------- HEALTH ------------------------------- */
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
app.get("/", (req, res) => res.send("✅ FST backend running with MongoDB + Wallet Auth + CORS!"));

/* ------------------------------- START ------------------------------- */
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
