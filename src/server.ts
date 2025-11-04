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
import { requireAuth, requireAdmin, issueJwt } from "./middleware/auth";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3300;

// ---------- SECURITY + UTILITIES ----------
app.use(bodyParser.json());
app.use(cookieParser());
app.use(helmet());
app.use(morgan("dev"));

// ---------- CORS SETUP ----------
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "https://fst-mini-app.vercel.app",
  "https://fst-mini-app-three.vercel.app",
  "https://fst-mini-app-git-feat-realms-free-and-21953f-defilords-projects.vercel.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn("❌ Blocked CORS origin:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ---------- CACHE ----------
const cache = new NodeCache({ stdTTL: 60 }); // cache 1 minute

// ---------- MOCK DATABASE ----------
interface User {
  id: string;
  wallet: string;
  token: string;
  role: string;
}
const users = new Map<string, User>();

// ---------- AUTH ROUTES ----------
app.get("/auth/nonce", (req, res) => {
  const { address } = req.query;
  if (!address) return res.status(400).json({ error: "Missing address" });
  const nonce = randomUUID();
  res.json({ nonce });
});

// ✅ Verify wallet using Solana signature verification
app.post("/auth/verify", async (req, res) => {
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

    if (!isValid) {
      console.warn("❌ Invalid signature for wallet:", address);
      return res.status(401).json({ error: "Invalid signature" });
    }

    const token = issueJwt({
      userId: address,
      role:
        address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER",
    });

    const user: User = {
      id: address,
      wallet: address,
      token,
      role:
        address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER",
    };
    users.set(address, user);

    console.log("✅ Wallet verified:", address, "| Role:", user.role);
    res.json({ token, role: user.role });
  } catch (err) {
    console.error("❌ Verify wallet error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- AUTH HELPERS ----------
app.get("/me", requireAuth, (req, res) => {
  try {
    const user = users.get(req.auth!.userId);
    if (!user) return res.status(401).json({ error: "Invalid token" });
    res.json({ user: { id: user.wallet, role: user.role } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/introspect", (req, res) => {
  try {
    const { token } = req.body;
    const user = Array.from(users.values()).find((u) => u.token === token);
    if (!user)
      return res.status(200).json({ active: false, payload: { role: "USER" } });

    res.json({ active: true, payload: { role: user.role } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- FPL DATA (Fast + Reliable with Fallback Proxy) ----------
const agent = new https.Agent({
  keepAlive: true,
  rejectUnauthorized: false,
});

async function safeFetchJson(url: string, cacheKey: string, res: any) {
  try {
    const cached = cache.get(cacheKey);
    if (cached) {
      console.log(`🟢 Serving ${cacheKey} from cache`);
      return res.json(cached);
    }

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; FST-App/1.0)",
        Accept: "application/json",
      },
      agent,
    });

    if (!response.ok) {
      console.warn(`⚠️ Primary FPL source failed (${response.status}). Retrying via fallback...`);
      const fallback = await fetch(`https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`);
      if (!fallback.ok) {
        console.error("❌ Fallback proxy also failed:", fallback.statusText);
        return res.status(502).json({ error: `Failed to fetch ${cacheKey}` });
      }
      const data = await fallback.json();
      cache.set(cacheKey, data);
      console.log(`✅ Fetched ${cacheKey} from fallback`);
      return res.json(data);
    }

    const data = await response.json();
    cache.set(cacheKey, data);
    console.log(`✅ Successfully fetched ${cacheKey}`);
    return res.json(data);
  } catch (err: any) {
    console.error(`❌ ${cacheKey} error:`, err.message || err);
    return res.status(500).json({ error: `Failed to fetch ${cacheKey}` });
  }
}

app.get("/fpl/api/bootstrap-static/", (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/bootstrap-static/", "bootstrap", res)
);

app.get("/fpl/api/fixtures/", (req, res) =>
  safeFetchJson("https://fantasy.premierleague.com/api/fixtures/", "fixtures", res)
);

// ---------- ADMIN ----------
app.get("/admin/contests", requireAdmin, (req, res) => {
  res.json({
    contests: [
      { id: 1, name: "Weekly Realm", status: "active" },
      { id: 2, name: "Free Realm", status: "completed" },
    ],
  });
});

// ---------- HEALTH ----------
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));

// ---------- ROOT ----------
app.get("/", (req, res) => {
  res.send("✅ FST backend running successfully with fast FPL fallback & JWT auth!");
});

// ---------- START SERVER ----------
async function startServer() {
  try {
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log("✅ Prefetched FPL data");
    });
  } catch (err) {
    console.error("❌ Server start error:", err);
  }
}

startServer();
