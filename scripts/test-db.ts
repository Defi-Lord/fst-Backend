// scripts/test-db.ts
import { prisma } from "../src/lib/prisma.js";

async function main() {
  console.log("🚀 Testing MongoDB + Prisma connection...");

  // Create a test wallet and user
  const wallet = await prisma.wallet.create({
    data: { address: "TestWallet12345" },
  });

  const user = await prisma.user.create({
    data: {
      displayName: "Test User",
      wallet: { connect: { id: wallet.id } },
      role: "USER",
    },
    include: { wallet: true },
  });

  console.log("✅ User created:", user);

  // Read data back
  const allUsers = await prisma.user.findMany({
    include: { wallet: true },
  });

  console.log("📦 Users in DB:", allUsers);

  // Clean up (optional)
  await prisma.user.deleteMany({});
  await prisma.wallet.deleteMany({});

  console.log("🧹 Cleaned up test data!");
}

main()
  .then(() => {
    console.log("✅ Test complete!");
    process.exit(0);
  })
  .catch((err) => {
    console.error("❌ Error testing DB:", err);
    process.exit(1);
  });
