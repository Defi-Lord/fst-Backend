import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { requireAdmin, requireAuth } from '../middleware/auth';
import { parsePage } from '../utils/pagination';
const router = Router();
// Public: list open contests
router.get('/', async (_req, res) => {
    const contests = await prisma.contest.findMany({
        where: { status: 'OPEN' },
        orderBy: { createdAt: 'desc' },
        include: { payoutRules: true },
    });
    res.json(contests);
});
// Admin: create or update a contest
router.post('/', requireAdmin, async (req, res) => {
    const { id, slug, title, realm, playersLimit, transferpool, status } = req.body || {};
    if (!slug || !title || !realm || !playersLimit)
        return res.status(400).json({ error: 'slug, title, realm, playersLimit required' });
    const data = { slug, title, realm, playersLimit, transferpool: transferpool ?? 0 };
    if (status)
        data.status = status;
    const contest = id
        ? await prisma.contest.update({ where: { id }, data })
        : await prisma.contest.create({ data });
    res.json(contest);
});
// Join contest (mark entry as paid) — call this after payment success
router.post('/:id/join', requireAuth, async (req, res) => {
    const id = req.params.id;
    const userId = req.auth.userId;
    const user = await prisma.user.findUnique({ where: { id: userId }, include: { wallet: true } });
    if (!user?.wallet)
        return res.status(400).json({ error: 'wallet not found' });
    const entry = await prisma.contestEntry.upsert({
        where: { userId_contestId: { userId, contestId: id } },
        update: { paid: true, address: user.wallet.address },
        create: { userId, contestId: id, paid: true, address: user.wallet.address },
    });
    res.json({ ok: true, entry });
});
// Contest leaderboard (scoped)
router.get('/:id/leaderboard', async (req, res) => {
    const { skip, take, page, pageSize } = parsePage(req.query);
    const id = req.params.id;
    const [rows, total] = await Promise.all([
        prisma.leaderboardEntry.findMany({
            where: { contestId: id },
            skip, take,
            orderBy: [{ points: 'desc' }, { updatedAt: 'asc' }],
            include: { user: { include: { wallet: true } } },
        }),
        prisma.leaderboardEntry.count({ where: { contestId: id } }),
    ]);
    res.json({ page, pageSize, total, rows });
});
// Stats per contest
router.get('/:id/stats', requireAdmin, async (req, res) => {
    const id = req.params.id;
    const [paid, teams] = await Promise.all([
        prisma.contestEntry.count({ where: { contestId: id, paid: true } }),
        prisma.team.count({ where: { contestId: id } }),
    ]);
    res.json({ participants: paid, teams });
});
export default router;
