import jwt from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
export function issueJwt(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
export function requireAuth(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer '))
        return res.status(401).json({ error: 'Unauthorized' });
    const token = auth.slice(7);
    try {
        const data = jwt.verify(token, JWT_SECRET);
        req.auth = data;
        next();
    }
    catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}
export function requireAdmin(req, res, next) {
    requireAuth(req, res, () => {
        if (req.auth?.role !== 'ADMIN')
            return res.status(403).json({ error: 'Admin only' });
        next();
    });
}
