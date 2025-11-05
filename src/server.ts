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

import { issueJwt, requireAuth, requireAdmin } from "./middleware/auth.js";
import authRoutes from "./routes/authRoutes.js"; // ✅ wallet auth routes

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
      !origin || allowedOrigins.includes(origin)
        ? cb(null, true)
        : cb(new Error("Not allowed by CORS")),
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Preflight fix
app.options("*", (req, res) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.sendStatus(200);
});

// ---------- CACHE ----------
const cache = new NodeCache({ stdTTL: 300 });
const httpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });

// ---------- MOCK DATABASE ----------
type Role = "USER" | "ADMIN";

interface UserRecord {
  id: string;
  wallet: string;
  token?: string;
  role: Role;
  createdAt: number;
}

interface Participant {
  wallet: string;
  joinedAt: number;
  paid: boolean;
  entryFee: number;
  score: number;
  history: { gw: number; score: number }[];
  position?: number;
}

interface Contest {
  id: number;
  name: string;
  type: "FREE" | "WEEKLY" | "MONTHLY" | "SEASONAL";
  entryFee: number;
  participants: Map<string, Participant>;
  registrationOpen: boolean;
  registrationStart?: string;
  registrationEnd?: string;
  createdAt: number;
}

const users = new Map<string, UserRecord>();
const contests = new Map<number, Contest>();

function seedContests() {
  const now = Date.now();
  contests.set(1, {
    id: 1,
    name: "Weekly Realm",
    type: "WEEKLY",
    entryFee: 1,
    participants: new Map(),
    registrationOpen: true,
    createdAt: now,
  });
  contests.set(2, {
    id: 2,
    name: "Free Realm",
    type: "FREE",
    entryFee: 0,
    participants: new Map(),
    registrationOpen: true,
    createdAt: now,
  });
  contests.set(3, {
    id: 3,
    name: "Monthly Realm",
    type: "MONTHLY",
    entryFee: 5,
    participants: new Map(),
    registrationOpen: true,
    createdAt: now,
  });
}
seedContests();

// ---------- WALLET AUTH ROUTES ----------
app.use("/auth", authRoutes); // ✅ handles /auth/challenge + /auth/verify (new secure route)

// ---------- LEGACY AUTH (still supported) ----------
app.get("/auth/nonce", (req, res) => {
  const { address } = req.query;
  if (!address) return res.status(400).json({ error: "Missing address" });
  const nonce = randomUUID();
  res.json({ nonce });
});

app.post("/auth/verify-old", async (req, res) => {
  try {
    const { address, signature, message } = req.body;
    if (!address || !signature || !message)
      return res.status(400).json({ error: "Missing required fields" });

    const publicKeyBytes = bs58.decode(address);
    const signatureBytes = new Uint8Array(signature.data || signature);
    const messageBytes = new TextEncoder().encode(message);

    const isValid = nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      publicKeyBytes
    );

    if (!isValid) return res.status(401).json({ error: "Invalid signature" });

    const role: Role =
      address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER";
    const token = issueJwt({ userId: address, role });

    const record: UserRecord = {
      id: address,
      wallet: address,
      token,
      role,
      createdAt: Date.now(),
    };
    users.set(address, record);

    res.json({ token, role });
  } catch (err) {
    console.error("❌ Verify wallet error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/introspect", (req, res) => {
  const { token } = req.body;
  const user = Array.from(users.values()).find((u) => u.token === token);
  if (!user)
    return res.status(200).json({ active: false, payload: { role: "USER" } });
  res.json({ active: true, payload: { role: user.role } });
});

app.get("/me", requireAuth, (req, res) => {
  const user = users.get(req.auth!.userId);
  if (!user) return res.status(401).json({ error: "Invalid token" });
  res.json({ user: { id: user.wallet, role: user.role } });
});

// ---------- ADMIN ----------
app.get("/admin/contests", requireAdmin, (req, res) => {
  const data = Array.from(contests.values()).map((c) => ({
    id: c.id,
    name: c.name,
    type: c.type,
    entryFee: c.entryFee,
    registrationOpen: c.registrationOpen,
    participantsCount: c.participants.size,
  }));
  res.json({ contests: data });
});

// ---------- USER CONTESTS ----------
app.post("/contests/:id/join", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const contest = contests.get(id);
  if (!contest) return res.status(404).json({ error: "Contest not found" });
  const wallet = req.auth!.userId;
  const { payNow } = req.body;

  const paid = contest.entryFee === 0 || Boolean(payNow);
  contest.participants.set(wallet, {
    wallet,
    joinedAt: Date.now(),
    paid,
    entryFee: contest.entryFee,
    score: 0,
    history: [],
  });
  contests.set(id, contest);
  res.json({ joined: true });
});

// ---------- FPL DATA ----------
async function safeFetchJson(url: string, cacheKey: string, res: any) {
  try {
    const cached = cache.get(cacheKey);
    if (cached) return res.json(cached);

    const response = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0" },
      agent: httpsAgent as any,
    });

    if (!response.ok) {
      console.warn(`⚠️ FPL fetch failed (${response.status}). Trying fallback proxy...`);
      const proxy = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
      const fallback = await fetch(proxy);
      if (!fallback.ok)
        return res.status(502).json({ error: "Failed to fetch FPL data" });
      const data = await fallback.json();
      cache.set(cacheKey, data);
      return res.json(data);
    }

    const data = await response.json();
    cache.set(cacheKey, data);
    res.json(data);
  } catch (err: any) {
    console.error("❌ FPL fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch FPL data" });
  }
}

app.get("/fpl/api/bootstrap-static/", (req, res) =>
  safeFetchJson(
    "https://fantasy.premierleague.com/api/bootstrap-static/",
    "bootstrap",
    res
  )
);
app.get("/fpl/api/fixtures/", (req, res) =>
  safeFetchJson(
    "https://fantasy.premierleague.com/api/fixtures/",
    "fixtures",
    res
  )
);

// ---------- HEALTH ----------
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
app.get("/", (req, res) =>
  res.send("✅ FST backend running successfully with wallet auth + CORS fixes!")
);

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
