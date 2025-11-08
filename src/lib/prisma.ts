// src/lib/prisma.ts
import { PrismaClient } from "@prisma/client";

declare global {
  // Prevent multiple instances of PrismaClient in dev (hot reload)
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

// Create Prisma client singleton
export const prisma =
  global.prisma ||
  new PrismaClient({
    log: ["query", "info", "warn", "error"],
  });

// Connect function with retry logic
export async function connectDB(retries = 5, delayMs = 3000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await prisma.$connect();
      console.log("✅ Connected to PostgreSQL!");
      return;
    } catch (err) {
      console.error(`❌ Failed to connect to PostgreSQL (attempt ${attempt}):`, err);
      if (attempt < retries) {
        console.log(`🔁 Retrying in ${delayMs / 1000}s...`);
        await new Promise((res) => setTimeout(res, delayMs));
      } else {
        console.error("🚨 Could not connect to PostgreSQL after multiple attempts.");
        process.exit(1);
      }
    }
  }
}

// Store globally in dev to avoid re-instantiation
if (process.env.NODE_ENV !== "production") {
  global.prisma = prisma;
}
