import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  try {
    console.log("🔍 Testing database connection...");

    // Quick query — counts users in the table
    const usersCount = await prisma.user.count();

    console.log(`✅ Database connection OK! Found ${usersCount} users.`);
  } catch (error) {
    console.error("❌ Database connection failed:", error);
  } finally {
    await prisma.$disconnect();
  }
}

main();
