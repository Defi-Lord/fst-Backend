// server.ts
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

import { issueJwt, requireAuth, requireAdmin, AuthUser } from "./middlewares/auth";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3300;

// ---------- SECURITY + UTILITIES ----------
app.use(bodyParser.json());
app.use(cookieParser());
app.use(helmet());
app.use(morgan("dev"));

// ---------- CORS ----------
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "https://fst-mini-app.vercel.app",
  "https://fst-mini-app-three.vercel.app",
  "https://fst-mini-app-git-feat-realms-free-and-21953f-defilords-projects.vercel.app",
];

app.use(
  cors({
    origin: (origin, cb) =>
      !origin || allowedOrigins.includes(origin) ? cb(null, true) : cb(new Error("Not allowed by CORS")),
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Preflight / OPTIONS fallback (keeps explicit headers)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// ---------- CACHE ----------
const cache = new NodeCache({ stdTTL: 300 }); // 5 minutes
const httpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });

// ---------- MOCK DATABASE STRUCTURES ----------
type Role = "USER" | "ADMIN";

interface UserRecord {
  id: string; // wallet address
  wallet: string;
  token?: string; // JWT string
  role: Role;
  createdAt: number;
}

interface Participant {
  wallet: string;
  joinedAt: number;
  paid: boolean;
  entryFee: number;
  score: number; // current contest score
  // history of last gameweeks — newest first
  history: { gw: number; score: number }[];
  position?: number; // computed field (1-based)
}

interface Contest {
  id: number;
  name: string;
  type: "FREE" | "WEEKLY" | "MONTHLY" | "SEASONAL";
  entryFee: number;
  participants: Map<string, Participant>; // wallet -> participant
  registrationOpen: boolean;
  registrationStart?: string; // ISO datetime
  registrationEnd?: string; // ISO datetime
  createdAt: number;
}

const users = new Map<string, UserRecord>(); // wallet -> user
const contests = new Map<number, Contest>(); // id -> contest

// ---------- seed some contests ----------
function seedContests() {
  const now = Date.now();
  const c1: Contest = {
    id: 1,
    name: "Weekly Realm",
    type: "WEEKLY",
    entryFee: 1, // currency unit (simulate)
    participants: new Map(),
    registrationOpen: true,
    createdAt: now,
  };
  const c2: Contest = {
    id: 2,
    name: "Free Realm",
    type: "FREE",
    entryFee: 0,
    participants: new Map(),
    registrationOpen: true,
    createdAt: now,
  };
  const c3: Contest = {
    id: 3,
    name: "Monthly Realm",
    type: "MONTHLY",
    entryFee: 5,
    participants: new Map(),
    registrationOpen: true,
    createdAt: now,
  };
  contests.set(c1.id, c1);
  contests.set(c2.id, c2);
  contests.set(c3.id, c3);
}
seedContests();

// ---------- AUTH ROUTES ----------

app.get("/auth/nonce", (req, res) => {
  const { address } = req.query;
  if (!address) return res.status(400).json({ error: "Missing address" });
  const nonce = randomUUID();
  // you might want to persist nonce tied to address for real verification
  res.json({ nonce });
});

/**
 * Verify wallet signature (Solana) and return JWT
 * - On success: create or update user record, return JWT and role
 */
app.post("/auth/verify", async (req, res) => {
  try {
    const { address, signature, message } = req.body;
    if (!address || !signature || !message) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // If user already exists and has valid token, quickly return it.
    const existing = users.get(address);
    if (existing && existing.token) {
      // Optionally verify token still valid by decoding; to keep it simple return it.
      return res.json({ token: existing.token, role: existing.role });
    }

    // verify signature using tweetnacl + bs58 (Solana-style public key)
    const publicKeyBytes = bs58.decode(address);
    const signatureBytes = new Uint8Array(signature.data || signature);
    const messageBytes = new TextEncoder().encode(message);

    const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);

    if (!isValid) {
      console.warn("❌ Invalid signature for wallet:", address);
      return res.status(401).json({ error: "Invalid signature" });
    }

    const role: Role = address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER";
    const jwtToken = issueJwt({ userId: address, role });

    const record: UserRecord = {
      id: address,
      wallet: address,
      token: jwtToken,
      role,
      createdAt: Date.now(),
    };
    users.set(address, record);

    console.log("✅ Wallet verified (issue JWT):", address, "| Role:", role);
    res.json({ token: jwtToken, role });
  } catch (err) {
    console.error("❌ Verify wallet error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * /auth/introspect - accept body { token } and return active/payload
 * Useful for frontend libraries expecting introspect endpoint.
 */
app.post("/auth/introspect", (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ active: false, payload: { role: "USER" } });

    // simple lookup by token
    const user = Array.from(users.values()).find((u) => u.token === token);
    if (!user) return res.status(200).json({ active: false, payload: { role: "USER" } });

    return res.json({ active: true, payload: { role: user.role } });
  } catch (err) {
    console.error("❌ Introspect error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- /me ----------
app.get("/me", requireAuth, (req, res) => {
  try {
    const userId = req.auth!.userId;
    const user = users.get(userId);
    if (!user) return res.status(401).json({ error: "Invalid token" });
    res.json({ user: { id: user.wallet, role: user.role } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ADMIN-ENDPOINTS ----------

/**
 * /admin/users
 * Admin-only: list all users and some stats
 */
app.get("/admin/users", requireAdmin, (req, res) => {
  const arr = Array.from(users.values()).map((u) => ({
    wallet: u.wallet,
    role: u.role,
    createdAt: u.createdAt,
  }));
  res.json({ users: arr });
});

/**
 * /admin/contests - admin view of contests with participants summary
 */
app.get("/admin/contests", requireAdmin, (req, res) => {
  const list = Array.from(contests.values()).map((c) => {
    const participants = Array.from(c.participants.values());
    return {
      id: c.id,
      name: c.name,
      type: c.type,
      entryFee: c.entryFee,
      registrationOpen: c.registrationOpen,
      registrationStart: c.registrationStart,
      registrationEnd: c.registrationEnd,
      participantsCount: participants.length,
      paidCount: participants.filter((p) => p.paid).length,
      createdAt: c.createdAt,
    };
  });
  res.json({ contests: list });
});

/**
 * Admin sets availability window (start/end ISO datetime) and toggles registration
 */
app.post("/admin/contests/:id/availability", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const contest = contests.get(id);
  if (!contest) return res.status(404).json({ error: "Contest not found" });

  const { registrationStart, registrationEnd, registrationOpen } = req.body;
  if (registrationStart) contest.registrationStart = registrationStart;
  if (registrationEnd) contest.registrationEnd = registrationEnd;
  if (typeof registrationOpen === "boolean") contest.registrationOpen = registrationOpen;

  contests.set(id, contest);
  res.json({ success: true, contest });
});

/**
 * Admin can update entry fee
 */
app.post("/admin/contests/:id/entryfee", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { entryFee } = req.body;
  const contest = contests.get(id);
  if (!contest) return res.status(404).json({ error: "Contest not found" });
  contest.entryFee = Number(entryFee) || 0;
  contests.set(id, contest);
  res.json({ success: true, contest });
});

/**
 * Admin dashboard: everything an admin needs to monitor
 */
app.get("/admin/dashboard", requireAdmin, (req, res) => {
  const contestSummaries = Array.from(contests.values()).map((c) => {
    const participants = Array.from(c.participants.values());
    return {
      id: c.id,
      name: c.name,
      type: c.type,
      entryFee: c.entryFee,
      registrationOpen: c.registrationOpen,
      participantsCount: participants.length,
      paidCount: participants.filter((p) => p.paid).length,
    };
  });
  res.json({
    totalUsers: users.size,
    contests: contestSummaries,
  });
});

// ---------- USER/APP ROUTES ----------

/**
 * Join a contest
 * - requires authentication (wallet)
 * - body { payNow: boolean } (simulated)
 */
app.post("/contests/:id/join", requireAuth, (req, res) => {
  try {
    const id = Number(req.params.id);
    const contest = contests.get(id);
    if (!contest) return res.status(404).json({ error: "Contest not found" });

    // check registration window if present
    if (contest.registrationStart && contest.registrationEnd) {
      const now = new Date();
      const start = new Date(contest.registrationStart);
      const end = new Date(contest.registrationEnd);
      if (now < start || now > end || !contest.registrationOpen) {
        return res.status(403).json({ error: "Registration closed for this contest" });
      }
    } else if (!contest.registrationOpen) {
      return res.status(403).json({ error: "Registration closed" });
    }

    const wallet = req.auth!.userId;
    if (contest.participants.has(wallet)) {
      return res.status(400).json({ error: "Already joined" });
    }

    const { payNow } = req.body;
    // simulate payment: if entryFee > 0 and payNow !== true -> fail
    const required = contest.entryFee || 0;
    const paid = required === 0 ? true : Boolean(payNow);

    if (required > 0 && !paid) {
      return res.status(400).json({ error: "Payment required to join this contest" });
    }

    const participant: Participant = {
      wallet,
      joinedAt: Date.now(),
      paid,
      entryFee: required,
      score: 0,
      history: [], // will record { gw, score } entries
    };

    contest.participants.set(wallet, participant);
    contests.set(id, contest);

    res.json({ joined: true, participant });
  } catch (err) {
    console.error("Join error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Get contest participants (public but admin gets richer view)
 */
app.get("/contests/:id/participants", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const contest = contests.get(id);
  if (!contest) return res.status(404).json({ error: "Contest not found" });

  const arr = Array.from(contest.participants.values()).map((p) => ({
    wallet: p.wallet,
    joinedAt: p.joinedAt,
    paid: p.paid,
    entryFee: p.entryFee,
    score: p.score,
  }));

  res.json({ participants: arr });
});

/**
 * Admin: update a participant's score (useful to update after GW resolved)
 * Body: { wallet: string, score: number, gw?: number }
 */
app.post("/admin/contests/:id/participant/score", requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const contest = contests.get(id);
    if (!contest) return res.status(404).json({ error: "Contest not found" });

    const { wallet, score, gw } = req.body;
    if (!wallet || typeof score !== "number") return res.status(400).json({ error: "Invalid body" });

    const participant = contest.participants.get(wallet);
    if (!participant) return res.status(404).json({ error: "Participant not found" });

    // push to history if gw provided
    if (gw && Number.isFinite(gw)) {
      participant.history.unshift({ gw: Number(gw), score });
      // keep only last 10 entries
      if (participant.history.length > 10) participant.history.splice(10);
    }

    participant.score = score;
    contest.participants.set(wallet, participant);
    contests.set(id, contest);

    res.json({ success: true, participant });
  } catch (err) {
    console.error("Update score error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Leaderboard for a contest - returns participants sorted by score desc
 */
app.get("/contests/:id/leaderboard", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const contest = contests.get(id);
  if (!contest) return res.status(404).json({ error: "Contest not found" });

  const participants = Array.from(contest.participants.values());
  participants.sort((a, b) => b.score - a.score);

  // assign positions
  participants.forEach((p, idx) => (p.position = idx + 1));

  const list = participants.map((p) => ({
    wallet: p.wallet,
    score: p.score,
    position: p.position,
  }));

  res.json({ leaderboard: list });
});

/**
 * Contest history (user's past 10 gameweeks) - admin or user themselves can access
 */
app.get("/contests/:id/history/:wallet?", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const contest = contests.get(id);
  if (!contest) return res.status(404).json({ error: "Contest not found" });

  // wallet param optional — if not provided and requestor is user, show theirs; if admin, show all
  const requestedWallet = req.params.wallet;
  if (requestedWallet) {
    const p = contest.participants.get(requestedWallet);
    if (!p) return res.status(404).json({ error: "Participant not found" });
    return res.json({ wallet: p.wallet, history: p.history.slice(0, 10) });
  }

  // if admin -> return all participants history; if user -> return theirs
  if (req.auth!.role === "ADMIN") {
    const all = Array.from(contest.participants.values()).map((p) => ({
      wallet: p.wallet,
      history: p.history.slice(0, 10),
    }));
    return res.json({ histories: all });
  }

  // regular user: return their history
  const wallet = req.auth!.userId;
  const p = contest.participants.get(wallet);
  if (!p) return res.status(404).json({ error: "Participant not found" });
  res.json({ wallet: p.wallet, history: p.history.slice(0, 10) });
});

// ---------- FPL DATA (safe fetch + caching) ----------
async function safeFetchJson(url: string, cacheKey: string, res: any) {
  try {
    const cached = cache.get(cacheKey);
    if (cached) return res.json(cached);

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; FST-App/1.0; +https://fst-mini-app.vercel.app)",
        Accept: "application/json",
      },
      agent: httpsAgent as any,
    });

    if (!response.ok) {
      console.error("❌ FPL fetch failed:", response.status, response.statusText);
      return res.status(502).json({ error: "Failed to fetch FPL data" });
    }

    const data = await response.json();
    cache.set(cacheKey, data);
    return res.json(data);
  } catch (err: any) {
    console.error("❌ FPL fetch error:", err.message || err);
    return res.status(500).json({ error: "Failed to fetch FPL data" });
  }
}

app.get("/fpl/api/bootstrap-static/", (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/bootstrap-static/", "bootstrap", res)
);

app.get("/fpl/api/fixtures/", (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/fixtures/", "fixtures", res)
);

// ---------- HEALTH & ROOT ----------
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
app.get("/", (req, res) => res.send("✅ FST backend running successfully!"));

// ---------- PREFETCH & WARMUP ----------
async function prefetchAll() {
  try {
    const [boot, fix] = await Promise.all([
      fetch("https://fantasy.premierleague.com/api/bootstrap-static/").then((r) => r.json()).catch(() => null),
      fetch("https://fantasy.premierleague.com/api/fixtures/").then((r) => r.json()).catch(() => null),
    ]);
    if (boot) cache.set("bootstrap", boot);
    if (fix) cache.set("fixtures", fix);
    console.log("✅ Prefetched FPL data");
  } catch (e) {
    console.warn("⚠️ Prefetch failed:", e);
  }
}

app.get("/warmup", async (req, res) => {
  prefetchAll();
  return res.json({ warmed: true });
});

// ---------- START SERVER ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  prefetchAll();
});
