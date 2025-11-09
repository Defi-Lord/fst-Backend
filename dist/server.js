"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// src/server.ts
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const body_parser_1 = __importDefault(require("body-parser"));
const crypto_1 = require("crypto");
const dotenv_1 = __importDefault(require("dotenv"));
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const bs58_1 = __importDefault(require("bs58"));
const helmet_1 = __importDefault(require("helmet"));
const morgan_1 = __importDefault(require("morgan"));
const node_cache_1 = __importDefault(require("node-cache"));
const https_1 = __importDefault(require("https"));
const mongoose_1 = __importDefault(require("mongoose"));
const auth_js_1 = require("./middleware/auth.js");
const web3_js_1 = require("@solana/web3.js");
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = process.env.PORT || 3300;
const MONGO_URI = process.env.MONGO_URI ||
    "mongodb+srv://luciatrump30_db_user:Gentletiger@cluster0.8eynm3z.mongodb.net/fstdb?retryWrites=true&w=majority";
/* ---------------------------- MongoDB Connection ---------------------------- */
async function connectWithRetry(uri, attempts = 0) {
    try {
        await mongoose_1.default.connect(uri, {
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
        });
        console.log("✅ MongoDB connected");
    }
    catch (err) {
        console.error("❌ MongoDB connection error:", err);
        if (attempts < 5) {
            const delay = 2000 * (attempts + 1);
            console.log(`🔁 Retrying MongoDB connection in ${delay}ms (attempt ${attempts + 1})`);
            setTimeout(() => connectWithRetry(uri, attempts + 1), delay);
        }
        else {
            console.error("📛 MongoDB connection failed permanently.");
        }
    }
}
connectWithRetry(MONGO_URI);
/* ------------------------------ SECURITY SETUP ------------------------------ */
app.set("trust proxy", 1);
app.use((0, cookie_parser_1.default)());
app.use((0, helmet_1.default)({ crossOriginResourcePolicy: false }));
app.use((0, morgan_1.default)("dev"));
app.use(body_parser_1.default.json({ limit: "2mb" }));
/* --------------------------------- CORS ---------------------------------- */
const allowedOrigins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://fst-mini-app.vercel.app",
    "https://fst-mini-app-three.vercel.app",
    "https://fst-mini-app-git-feat-realms-free-and-contest-defi-lord.vercel.app",
    "https://fst-mini-app-git-feat-realms-free-and-contest-defilords-projects.vercel.app",
];
app.use((0, cors_1.default)({
    origin: (origin, callback) => {
        if (!origin)
            return callback(null, true);
        if (allowedOrigins.includes(origin))
            return callback(null, true);
        console.warn(`🚫 CORS blocked request from: ${origin}`);
        return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));
const userSchema = new mongoose_1.default.Schema({
    wallet: { type: String, unique: true },
    token: String,
    role: { type: String, default: "USER" },
    team: [{ playerId: Number }],
    displayName: { type: String, default: null },
}, { timestamps: true });
const contestSchema = new mongoose_1.default.Schema({
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
}, { timestamps: true });
const transactionSchema = new mongoose_1.default.Schema({
    wallet: String,
    txSignature: { type: String, unique: true },
    amount: Number,
    confirmed: Boolean,
}, { timestamps: true });
const User = mongoose_1.default.model("User", userSchema);
const Contest = mongoose_1.default.model("Contest", contestSchema);
const Transaction = mongoose_1.default.model("Transaction", transactionSchema);
/* -------------------------- Cache + HTTPS Agent --------------------------- */
const cache = new node_cache_1.default({ stdTTL: 300 });
const httpsAgent = new https_1.default.Agent({ keepAlive: true, rejectUnauthorized: false });
/* ------------------------------- WALLET AUTH ------------------------------- */
const walletNonces = new Map();
app.post("/auth/challenge", (req, res) => {
    try {
        const { address } = req.body;
        if (!address)
            return res.status(400).json({ error: "Missing wallet address" });
        const challenge = `Sign this message to verify your wallet: ${(0, crypto_1.randomUUID)()}`;
        walletNonces.set(address, challenge);
        res.json({ ok: true, challenge });
    }
    catch (err) {
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
        const publicKeyBytes = bs58_1.default.decode(address);
        const signatureBytes = Uint8Array.from(Buffer.from(signature, "base64"));
        const messageBytes = new TextEncoder().encode(message);
        const isValid = tweetnacl_1.default.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
        if (!isValid)
            return res.status(401).json({ error: "Invalid signature" });
        walletNonces.delete(address);
        const role = address === process.env.ADMIN_WALLET_ADDRESS ? "ADMIN" : "USER";
        const token = (0, auth_js_1.issueJwt)({ userId: address, role });
        await User.findOneAndUpdate({ wallet: address }, { token, role }, { upsert: true });
        res.json({ ok: true, token, role });
    }
    catch (err) {
        console.error("❌ Verify wallet error:", err);
        res.status(500).json({ error: "Server error" });
    }
});
/* -------------------------- VERIFY PAYMENT -------------------------- */
const solana = new web3_js_1.Connection((0, web3_js_1.clusterApiUrl)("mainnet-beta"), "confirmed");
async function verifySolanaTx(signature, expectedWallet, minAmountLamports) {
    try {
        const tx = await solana.getTransaction(signature, { commitment: "confirmed" });
        if (!tx) {
            console.warn(`⚠️ Transaction not found: ${signature}`);
            return false;
        }
        const accountKeys = tx.transaction.message.accountKeys.map((k) => k.toBase58());
        if (!accountKeys.includes(expectedWallet)) {
            console.warn(`⚠️ Wallet ${expectedWallet} not in tx ${signature}`);
            return false;
        }
        const post = tx.meta?.postBalances ?? [];
        const pre = tx.meta?.preBalances ?? [];
        const diff = pre[0] - post[0];
        return diff >= minAmountLamports;
    }
    catch (err) {
        console.error("verifySolanaTx error:", err);
        return false;
    }
}
/* -------------------------- JOIN CONTEST -------------------------- */
app.post("/contests/:id/join", auth_js_1.requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { txSignature } = req.body;
        const wallet = req.auth.userId;
        const contest = await Contest.findById(id);
        if (!contest || !contest.registrationOpen)
            return res.status(400).json({ error: "Contest not open" });
        // Free contests skip payment verification
        if (contest.entryFee === 0) {
            const exists = contest.participants.find((p) => p.wallet === wallet);
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
        if (!verified)
            return res.status(400).json({ error: "Transaction not verified" });
        await Transaction.create({ wallet, txSignature, amount: contest.entryFee, confirmed: true });
        const exists = contest.participants.find((p) => p.wallet === wallet);
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
    }
    catch (err) {
        console.error("❌ join contest error:", err);
        res.status(500).json({ error: "Server error" });
    }
});
/* ------------------------------- HEALTH ------------------------------- */
app.get("/health", (req, res) => res.json({ status: "ok" }));
app.get("/", (req, res) => res.send("✅ FST backend running with MongoDB + Wallet Auth + Solana payments!"));
app.use((req, res) => res.status(404).json({ error: `Route not found: ${req.originalUrl}` }));
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
