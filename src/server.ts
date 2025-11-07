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

const userSchema = new mongoose.Schema(
  {
    wallet: { type: String, unique: true },
    token: String,
    role: { type: String, default: "USER" },
    // store user's selected team (array of player IDs from FPL)
    team: [{ playerId: Number }],
    // optional display name
    displayName: { type: String, default: null },
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

/* Leaderboard snapshot (latest or per-gameweek) */
const leaderboardSnapshotSchema = new mongoose.Schema(
  {
    realm: { type: String, enum: ["FREE", "WEEKLY", "MONTHLY", "SEASONAL"], required: true },
    gameweek: { type: Number, required: true },
    entries: [
      {
        wallet: String,
        points: Number,
      },
    ],
  },
  { timestamps: true }
);

/* History - snapshots kept for last 10 gameweeks per realm */
const historySchema = new mongoose.Schema(
  {
    realm: { type: String, enum: ["FREE", "WEEKLY", "MONTHLY", "SEASONAL"], required: true },
    gameweek: { type: Number, required: true },
    entries: [
      {
        wallet: String,
        points: Number,
      },
    ],
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
    res.json({ user: { id: user.wallet, role: user.role, displayName: user.displayName } });
  } catch (err) {
    console.error("❌ /me error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* -------------------------------- ADMIN -------------------------------- */
app.get("/admin/contests", requireAdmin, async (req, res) => {
  const contests = await Contest.find({}).sort({ createdAt: -1 });
  res.json({ contests });
});

// Create contest
app.post("/admin/contests", requireAdmin, async (req, res) => {
  try {
    const { name, type, entryFee } = req.body;
    if (!name || !type) return res.status(400).json({ error: "Missing required fields" });

    const contest = new Contest({
      name,
      type,
      entryFee: entryFee || 0,
      registrationOpen: true,
      participants: [],
    });
    await contest.save();
    res.json({ ok: true, contest });
  } catch (err: any) {
    console.error("❌ /admin/contests POST error:", err?.message || err);
    res.status(500).json({ error: "Failed to create contest" });
  }
});

// Toggle registration
app.patch("/admin/contests/:id/toggle", requireAdmin, async (req, res) => {
  try {
    const contest = await Contest.findById(req.params.id);
    if (!contest) return res.status(404).json({ error: "Contest not found" });

    contest.registrationOpen = !contest.registrationOpen;
    await contest.save();
    res.json({ ok: true, registrationOpen: contest.registrationOpen });
  } catch (err: any) {
    console.error("❌ /admin/contests/:id/toggle error:", err?.message || err);
    res.status(500).json({ error: "Failed to toggle contest" });
  }
});

// Delete contest
app.delete("/admin/contests/:id", requireAdmin, async (req, res) => {
  try {
    await Contest.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (err: any) {
    console.error("❌ /admin/contests/:id DELETE error:", err?.message || err);
    res.status(500).json({ error: "Failed to delete contest" });
  }
});

/* ------------------------------- ADMIN USERS ------------------------------- */
app.get("/admin/users", requireAdmin, async (req, res) => {
  try {
    // return wallet (the connected wallet), role, timestamps and displayName
    const users = await User.find({}, { wallet: 1, role: 1, displayName: 1, createdAt: 1, updatedAt: 1 }).sort({
      createdAt: -1,
    });
    res.json({ ok: true, users });
  } catch (err: any) {
    console.error("❌ /admin/users error:", err?.message || err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.get("/admin/users/:wallet", requireAdmin, async (req, res) => {
  try {
    const wallet = req.params.wallet;
    const user = await User.findOne({ wallet });
    if (!user) return res.status(404).json({ error: "User not found" });

    const contests = await Contest.find({ "participants.wallet": wallet }).select(
      "name type entryFee participants"
    );
    res.json({ ok: true, user, contests });
  } catch (err: any) {
    console.error("❌ /admin/users/:wallet error:", err?.message || err);
    res.status(500).json({ error: "Failed to fetch user details" });
  }
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

/* -------------------------- Leaderboard & History APIs --------------------- */

/**
 * GET /leaderboard/:realm
 * Returns the latest snapshot (entries array) for the realm (FREE/WEEKLY/MONTHLY/SEASONAL).
 * Example: /leaderboard/FREE
 */
app.get("/leaderboard/:realm", async (req, res) => {
  try {
    const realm = (req.params.realm || "").toUpperCase();
    if (!["FREE", "WEEKLY", "MONTHLY", "SEASONAL"].includes(realm)) {
      return res.status(400).json({ error: "Unknown realm" });
    }

    // Prefer latest snapshot for that realm
    const snapshot = await LeaderboardSnapshot.findOne({ realm }).sort({ createdAt: -1 });
    if (!snapshot) return res.json({ ok: true, snapshot: { realm, gameweek: null, entries: [] } });

    // populate displayName if available
    const wallets = snapshot.entries.map((e: any) => e.wallet);
    const users = await User.find({ wallet: { $in: wallets } }, { wallet: 1, displayName: 1 }).lean();
    const nameMap = new Map(users.map((u: any) => [u.wallet, u.displayName]));

    const entries = snapshot.entries
      .map((e: any) => ({ wallet: e.wallet, points: e.points, name: nameMap.get(e.wallet) || null }))
      .sort((a: any, b: any) => b.points - a.points);

    res.json({ ok: true, snapshot: { realm: snapshot.realm, gameweek: snapshot.gameweek, entries } });
  } catch (err: any) {
    console.error("❌ /leaderboard/:realm error:", err?.message || err);
    res.status(500).json({ error: "Failed to fetch leaderboard" });
  }
});

/**
 * GET /history/contest/:contestId/my
 * Returns up to 10 last gameweeks (round & points) for the authenticated user in the contest's realm.
 */
app.get("/history/contest/:contestId/my", requireAuth, async (req, res) => {
  try {
    const wallet = req.auth!.userId;
    const contestId = req.params.contestId;
    const contest = await Contest.findById(contestId);
    if (!contest) return res.status(404).json({ error: "Contest not found" });

    const realm = contest.type;
    const snapshots = await History.find({ realm }).sort({ gameweek: -1 }).limit(10).lean();

    const scores = snapshots
      .map((snap: any) => {
        const entry = (snap.entries || []).find((p: any) => p.wallet === wallet);
        return { round: snap.gameweek, points: entry ? entry.points : 0 };
      })
      .filter((x) => x.round != null)
      .sort((a, b) => a.round - b.round); // ascending by round

    res.json({ ok: true, contest: { id: contest._id, realm: contest.type, title: contest.name }, scores });
  } catch (err: any) {
    console.error("❌ /history/contest/:contestId/my error:", err?.message || err);
    res.status(500).json({ error: "Failed to fetch user history" });
  }
});

/* ------------------------------ FPL SYNC --------------------------------- */
/**
 * Periodically sync with FPL:
 * - fetch bootstrap-static -> provides elements[] with season total_points and current_event
 * - fetch event/{current_event}/live/ -> provides live points for players for that event
 * For each realm:
 *  - FREE -> use element.total_points (season total) to compute user totals
 *  - WEEKLY/MONTHLY/SEASONAL -> use live event stats.total_points for the current GW to compute user's points for that GW
 *
 * Save snapshot to LeaderboardSnapshot (upsert latest), and when current_event changes, move previous snapshot into History and trim to last 10.
 */

// local memory: last synced event per realm
const lastSyncedEvent: Record<string, number | null> = { FREE: null, WEEKLY: null, MONTHLY: null, SEASONAL: null };

async function fetchJson(url: string) {
  const cached = cache.get(url);
  if (cached) return cached;
  const resp = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0" }, agent: httpsAgent as any });
  if (!resp.ok) throw new Error(`Fetch failed ${resp.status} ${url}`);
  const data = await resp.json();
  cache.set(url, data);
  return data;
}

async function computeAndStoreSnapshots() {
  try {
    // bootstrap (season totals + current_event)
    const bootstrapUrl = "https://fantasy.premierleague.com/api/bootstrap-static/";
    const bootstrap = (await fetchJson(bootstrapUrl)) as any;
    const current_event = Number(bootstrap?.event || bootstrap?.current_event || bootstrap?.events?.find((e:any)=>e.is_current)?.id) || null;
    const elementsBootstrap = bootstrap?.elements || [];

    // map playerId -> season total_points
    const seasonPoints = new Map<number, number>();
    for (const el of elementsBootstrap) {
      const id = Number(el?.id);
      const pts = Number(el?.total_points ?? el?.points_total ?? 0);
      if (!Number.isFinite(pts)) continue;
      seasonPoints.set(id, pts);
    }

    // try live event for current gameweek (if available)
    let liveMap = new Map<number, number>();
    if (current_event) {
      try {
        const liveUrl = `https://fantasy.premierleague.com/api/event/${current_event}/live/`;
        const live = (await fetchJson(liveUrl)) as any;
        // live.elements is typical shape: array of { id, stats: { total_points: X } }
        const liveElements = live?.elements || live?.elements_stats || live?.elements || [];
        for (const el of liveElements) {
          const id = Number(el?.id || el?.element || el?.player_id);
          const pts =
            Number(el?.stats?.total_points ?? el?.stats?.total_points ?? el?.total_points ?? el?.points ?? 0) ||
            0;
          if (!Number.isFinite(pts)) continue;
          liveMap.set(id, pts);
        }
      } catch (err) {
        console.warn("⚠️ Could not fetch live event data:", err?.message || err);
      }
    }

    // gather all users once (we need teams)
    const allUsers = await User.find({}).lean();

    // For each realm build entries
    const realms: Array<"FREE" | "WEEKLY" | "MONTHLY" | "SEASONAL"> = ["FREE", "WEEKLY", "MONTHLY", "SEASONAL"];
    for (const realm of realms) {
      const entries: Array<{ wallet: string; points: number }> = [];

      for (const u of allUsers) {
        const team = Array.isArray(u.team) ? u.team : [];
        // team is array of { playerId: number } or numbers
        let playerIds: number[] = team.map((t: any) => (typeof t === "number" ? t : Number(t?.playerId || t?.id || 0))).filter(Boolean);

        // fallback: if user didn't save team, skip or zero
        if (!playerIds.length) {
          entries.push({ wallet: u.wallet, points: 0 });
          continue;
        }

        let total = 0;
        if (realm === "FREE") {
          // season totals from bootstrap
          for (const pid of playerIds) {
            total += Number(seasonPoints.get(pid) ?? 0);
          }
        } else {
          // weekly/monthly/seasonal -> use live points for current_event
          for (const pid of playerIds) {
            total += Number(liveMap.get(pid) ?? 0);
          }
        }
        entries.push({ wallet: u.wallet, points: Math.round((total + Number.EPSILON) * 100) / 100 });
      }

      // sort desc
      entries.sort((a, b) => b.points - a.points);

      // upsert latest leaderboard snapshot for realm & gameweek (use current_event or 0)
      const gameweek = current_event || 0;
      await LeaderboardSnapshot.findOneAndUpdate(
        { realm, gameweek },
        { realm, gameweek, entries },
        { upsert: true, new: true }
      );

      // if we detect event changed since last sync -> move previous snapshot to History and trim history to 10
      const last = lastSyncedEvent[realm];
      if (last != null && last !== gameweek) {
        // previous snapshot (last) -> move to history if not already exists
        const prevSnap = await LeaderboardSnapshot.findOne({ realm, gameweek: last }).lean();
        if (prevSnap) {
          // ensure not duplicated in History
          const exists = await History.findOne({ realm, gameweek: last });
          if (!exists) {
            await new History({ realm, gameweek: last, entries: prevSnap.entries }).save();
            // trim to last 10 per realm
            const toKeep = await History.find({ realm }).sort({ gameweek: -1 }).limit(10).select("_id").lean();
            const keepIds = toKeep.map((d:any) => d._id);
            await History.deleteMany({ realm, _id: { $nin: keepIds } });
            console.log(`🗂 Moved snapshot GW${last} -> history (realm=${realm})`);
          }
        }
      }
      // update lastSyncedEvent
      lastSyncedEvent[realm] = gameweek;
    }

    console.log(`🔄 FPL sync complete ${new Date().toISOString()} (current_event=${current_event})`);
  } catch (err: any) {
    console.error("❌ computeAndStoreSnapshots error:", err?.message || err);
  }
}

/* run on startup and every hour */
(async () => {
  await computeAndStoreSnapshots(); // first run
  // every hour
  setInterval(computeAndStoreSnapshots, 1000 * 60 * 60);
})();

/* ------------------------------- FPL PROXY ENDPOINTS ------------------------------ */
async function safeFetchJson(url: string, cacheKey: string, res: any) {
  try {
    const cached = cache.get(cacheKey);
    if (cached) return res.json(cached);

    const headers = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
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

app.get("/fpl/api/bootstrap-static/", (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/bootstrap-static/", "bootstrap", res)
);
app.get("/fpl/api/fixtures/", (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/fixtures/", "fixtures", res)
);

/* ------------------------------- HEALTH ------------------------------- */
app.get("/admin/overview", requireAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalContests = await Contest.countDocuments();
    const activeParticipants = await Contest.aggregate([
      { $unwind: "$participants" },
      { $group: { _id: "$participants.wallet" } },
      { $count: "uniqueParticipants" },
    ]);
    // try to read current event from bootstrap cache if present
    const bootstrap = (cache.get("https://fantasy.premierleague.com/api/bootstrap-static/") as any) || null;
    const current_event = bootstrap ? bootstrap.current_event || bootstrap.event : null;
    res.json({
      ok: true,
      overview: {
        totalUsers,
        totalContests,
        activeParticipants: activeParticipants?.[0]?.uniqueParticipants ?? 0,
        currentEvent: current_event ?? null,
      },
    });
  } catch (err: any) {
    console.error("❌ /admin/overview error:", err?.message || err);
    res.status(500).json({ error: "Failed to fetch overview" });
  }
});

app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
app.get("/", (req, res) => res.send("✅ FST backend running with MongoDB + Wallet Auth + CORS!"));

/* ------------------------------- START ------------------------------- */
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
