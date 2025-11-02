// src/lib/prisma.ts
import { PrismaClient } from "@prisma/client";
export const prisma = new PrismaClient();
export async function connectDB() {
    try {
        await prisma.$connect();
        console.log("✅ Connected to PostgreSQL (Local)!");
    }
    catch (err) {
        console.error("❌ Failed to connect to PostgreSQL:", err);
        process.exit(1);
    }
}
