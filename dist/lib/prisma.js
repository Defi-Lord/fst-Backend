"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prisma = void 0;
exports.connectDB = connectDB;
// src/lib/prisma.ts
const client_1 = require("@prisma/client");
// Create Prisma client singleton
exports.prisma = global.prisma ||
    new client_1.PrismaClient({
        log: ["query", "info", "warn", "error"],
    });
// Connect function with retry logic
async function connectDB(retries = 5, delayMs = 3000) {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            await exports.prisma.$connect();
            console.log("✅ Connected to PostgreSQL!");
            return;
        }
        catch (err) {
            console.error(`❌ Failed to connect to PostgreSQL (attempt ${attempt}):`, err);
            if (attempt < retries) {
                console.log(`🔁 Retrying in ${delayMs / 1000}s...`);
                await new Promise((res) => setTimeout(res, delayMs));
            }
            else {
                console.error("🚨 Could not connect to PostgreSQL after multiple attempts.");
                process.exit(1);
            }
        }
    }
}
// Store globally in dev to avoid re-instantiation
if (process.env.NODE_ENV !== "production") {
    global.prisma = exports.prisma;
}
