"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.issueJwt = issueJwt;
exports.requireAuth = requireAuth;
exports.requireAdmin = requireAdmin;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
/**
 * issueJwt - create a JWT for a user payload
 */
function issueJwt(payload) {
    return jsonwebtoken_1.default.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}
/**
 * requireAuth - express middleware to require a valid JWT in Authorization header
 */
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization || req.header("Authorization");
    if (!authHeader || !authHeader.toString().startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    const token = authHeader.toString().slice(7);
    try {
        const data = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        req.auth = data;
        next();
    }
    catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
}
/**
 * requireAdmin - require an authenticated admin
 */
function requireAdmin(req, res, next) {
    // call requireAuth then verify role
    requireAuth(req, res, () => {
        if (req.auth?.role !== "ADMIN") {
            return res.status(403).json({ error: "Admin only" });
        }
        next();
    });
}
