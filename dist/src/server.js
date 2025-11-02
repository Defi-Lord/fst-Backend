import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import { randomUUID } from "crypto";
import dotenv from "dotenv";
import nacl from "tweetnacl";
import bs58 from "bs58";
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3300;
// ---------- MIDDLEWARE ----------
app.use(bodyParser.json());
app.use(cookieParser());
// ✅ Comprehensive CORS setup
const allowedOrigins = [
    "http://localhost:5174",
    "https://fst-mini-app-three.vercel.app", // your deployed frontend
];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            console.warn("❌ Blocked CORS origin:", origin);
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));
app.options("*", cors());
const users = new Map();
// ---------- AUTH ROUTES ----------
// Nonce endpoint (real-world you'd cache or store this)
app.get("/auth/nonce", (req, res) => {
    const { address } = req.query;
    if (!address)
        return res.status(400).json({ error: "Missing address" });
    const nonce = randomUUID();
    res.json({ nonce });
});
// ✅ Verify wallet (with real cryptographic signature verification)
app.post("/auth/verify", async (req, res) => {
    try {
        const { address, signature, message } = req.body;
        if (!address || !signature || !message) {
            return res.status(400).json({ error: "Missing required fields" });
        }
        const publicKeyBytes = bs58.decode(address);
        const signatureBytes = Uint8Array.from(signature);
        const messageBytes = new TextEncoder().encode(message);
        const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
        if (!isValid) {
            console.warn("❌ Invalid signature for wallet:", address);
            return res.status(401).json({ error: "Invalid signature" });
        }
        // Generate a session token for this verified wallet
        const token = randomUUID();
        const user = {
            id: address,
            wallet: address,
            token,
            role: address.startsWith("Admin") ? "ADMIN" : "USER",
        };
        users.set(address, user);
        console.log("✅ Wallet verified and authenticated:", address);
        res.json({ token });
    }
    catch (err) {
        console.error("❌ Verify wallet error:", err);
        res.status(500).json({ error: "Server error" });
    }
});
// ---------- USER + AUTH UTILITIES ----------
app.get("/me", (req, res) => {
    try {
        const auth = req.headers.authorization;
        if (!auth?.startsWith("Bearer ")) {
            return res.status(401).json({ error: "Unauthorized" });
        }
        const token = auth.split(" ")[1];
        const user = Array.from(users.values()).find((u) => u.token === token);
        if (!user) {
            return res.status(401).json({ error: "Invalid token" });
        }
        res.json({ user: { id: user.wallet, role: user.role } });
    }
    catch {
        res.status(500).json({ error: "Server error" });
    }
});
app.post("/auth/introspect", (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(200).json({ active: false, payload: { role: "USER" } });
        }
        const user = Array.from(users.values()).find((u) => u.token === token);
        if (!user) {
            return res.status(200).json({ active: false, payload: { role: "USER" } });
        }
        res.json({ active: true, payload: { role: user.role } });
    }
    catch {
        res.status(500).json({ error: "Server error" });
    }
});
// ---------- FPL DATA ----------
app.get("/fpl/api/bootstrap-static/", async (req, res) => {
    try {
        const response = await fetch("https://fantasy.premierleague.com/api/bootstrap-static/");
        const data = await response.json();
        res.json(data);
    }
    catch (err) {
        console.error("❌ FPL bootstrap error:", err);
        res.status(500).json({ error: "Failed to fetch FPL data" });
    }
});
app.get("/fpl/api/fixtures/", async (req, res) => {
    try {
        const response = await fetch("https://fantasy.premierleague.com/api/fixtures/");
        const data = await response.json();
        res.json(data);
    }
    catch (err) {
        console.error("❌ FPL fixtures error:", err);
        res.status(500).json({ error: "Failed to fetch fixtures" });
    }
});
// ---------- ADMIN ----------
app.get("/admin/contests", (req, res) => {
    res.json({
        contests: [
            { id: 1, name: "Weekly Realm", status: "active" },
            { id: 2, name: "Free Realm", status: "completed" },
        ],
    });
});
// ---------- ROOT ----------
app.get("/", (req, res) => {
    res.send("✅ FST backend running successfully with real wallet verification!");
});
// ---------- START SERVER ----------
async function startServer() {
    try {
        app.listen(PORT, () => {
            console.log(`🚀 Server running at http://localhost:${PORT}`);
        });
    }
    catch (err) {
        console.error("❌ Server start error:", err);
    }
}
startServer();
