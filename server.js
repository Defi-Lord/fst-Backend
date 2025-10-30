// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import morgan from "morgan";
import prisma from "./src/db.js"; // ✅ Prisma (Supabase PostgreSQL connector)

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Middleware setup
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.json());
app.use(morgan("dev"));

// ✅ Database connection
(async () => {
  try {
    await prisma.$connect();
    console.log("✅ Connected to Supabase PostgreSQL!");
  } catch (err) {
    console.error("❌ Database connection failed:", err);
  }
})();

// ✅ Basic test route
app.get("/", (req, res) => {
  res.json({ message: "✅ Backend is running smoothly!" });
});

// ✅ Example API routes structure (optional, for later use)
// import routes from "./src/routes/index.js";
// app.use("/api", routes);

// ✅ Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
