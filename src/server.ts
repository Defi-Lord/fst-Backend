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

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3300;

// ---------- SECURITY + UTILITIES ----------
app.use(bodyParser.json());
app.use(cookieParser());
app.use(helmet());
app.use(morgan("tiny"));

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
  })
);

// ---------- CACHE ----------
const cache = new NodeCache({ stdTTL: 300 }); // 5 minutes
const httpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });

// ---------- MOCK USERS ----------
interface User {
  id: string;
  wallet: string;
  token: string;
  role: string;
}
const users = new Map<string, User>();

// ---------- AUTH ----------
app.get("/auth/nonce", (req, res) => {
  const { address } = req.query;
  if (!address) return res.status(400).json({ error: "Missing address" });
  const nonce = randomUUID();
  res.json({ nonce });
});

app.post("/auth/verify", async (req, res) => {
  const start = Date.now();
  try {
    const { address, signature, message } = req.body;
    if (!address || !signature || !message)
      return res.status(400).json({ error: "Missing fields" });

    // return cached session immediately
    const existing = users.get(address);
    if (existing) return res.json({ token: existing.token, role: existing.role });

    const pubKey = bs58.decode(address);
    const sig = new Uint8Array(signature.data || signature);
    const msg = new TextEncoder().encode(message);
    const isValid = nacl.sign.detached.verify(msg, sig, pubKey);
    if (!isValid) return res.status(401).json({ error: "Invalid signature" });

    const token = randomUUID();
    const role = address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER";
    users.set(address, { id: address, wallet: address, token, role });

    console.log(`✅ Wallet verified in ${Date.now() - start} ms`);
    res.json({ token, role });
  } catch (err) {
    console.error("❌ Verify error:", err);
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

app.get("/me", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized" });
  const token = auth.split(" ")[1];
  const user = Array.from(users.values()).find((u) => u.token === token);
  if (!user) return res.status(401).json({ error: "Invalid token" });
  res.json({ user });
});

// ---------- FAST FPL FETCH ----------
async function safeFetch(url: string, cacheKey: string, res: any) {
  try {
    const cached = cache.get(cacheKey);
    if (cached) return res.json(cached);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    let r = await fetch(url, {
      headers: { "User-Agent": "FST-App/1.0", Accept: "application/json" },
      agent: httpsAgent,
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!r.ok) {
      const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(
        url
      )}`;
      r = await fetch(proxyUrl);
    }

    const data = await r.json();
    cache.set(cacheKey, data);
    res.json(data);
  } catch (err) {
    console.error(`❌ ${cacheKey} fetch failed`, err);
    res.status(502).json({ error: "Fetch failed" });
  }
}

// ---------- ROUTES ----------
app.get("/fpl/api/bootstrap-static", (req, res) =>
  safeFetch("https://fantasy.premierleague.com/api/bootstrap-static/", "bootstrap", res)
);
app.get("/fpl/api/fixtures", (req, res) =>
  safeFetch("https://fantasy.premierleague.com/api/fixtures/", "fixtures", res)
);

app.get("/admin/contests", (req, res) => {
  res.json({
    contests: [
      { id: 1, name: "Weekly Realm", status: "active" },
      { id: 2, name: "Free Realm", status: "completed" },
    ],
  });
});

app.get("/health", (_, res) => res.status(200).json({ status: "ok" }));

// ping endpoint (for uptime robots)
app.get("/warmup", (_, res) => {
  Promise.allSettled([
    fetch("https://fantasy.premierleague.com/api/bootstrap-static/"),
    fetch("https://fantasy.premierleague.com/api/fixtures/"),
  ]).then(() => res.json({ warmed: true }));
});

app.get("/", (_, res) =>
  res.send("✅ FST backend running with fast caching & wallet auth")
);

// ---------- PREFETCH DATA ----------
async function prefetchAll() {
  console.log("🚀 Prefetching FPL data...");
  try {
    const [boot, fix] = await Promise.all([
      fetch("https://fantasy.premierleague.com/api/bootstrap-static/").then((r) => r.json()),
      fetch("https://fantasy.premierleague.com/api/fixtures/").then((r) => r.json()),
    ]);
    cache.set("bootstrap", boot);
    cache.set("fixtures", fix);
    console.log("✅ Prefetched and cached successfully");
  } catch (e) {
    console.warn("⚠️ Prefetch failed:", e);
  }
}

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  prefetchAll();
});
