import { Router } from 'express';
import { requireAdmin } from '../middleware/auth';
import { prisma } from '../lib/prisma';
import { parsePage } from '../utils/pagination';
const router = Router();
// Admin dashboard summary
router.get('/dashboard/summary', requireAdmin, async (_req, res) => {
    const [users, wallets, entries, weekly, monthly, seasonal] = await Promise.all([
        prisma.user.count(),
        prisma.wallet.count(),
        prisma.contestEntry.count({ where: { paid: true } }),
        prisma.contestEntry.count({ where: { paid: true, contest: { realm: 'WEEKLY' } } }),
        prisma.contestEntry.count({ where: { paid: true, contest: { realm: 'MONTHLY' } } }),
        prisma.contestEntry.count({ where: { paid: true, contest: { realm: 'SEASONAL' } } }),
    ]);
    res.json({ users, wallets, paidEntries: entries, breakdown: { weekly, monthly, seasonal } });
});
// List users with their contests
router.get('/users', requireAdmin, async (req, res) => {
    const { skip, take, page, pageSize } = parsePage(req.query);
    const [items, total] = await Promise.all([
        prisma.user.findMany({
            skip, take,
            include: {
                wallet: true,
                entries: { include: { contest: true } },
            },
            orderBy: { createdAt: 'desc' },
        }),
        prisma.user.count(),
    ]);
    res.json({ page, pageSize, total, items });
});
// Contest participants per contest
router.get('/contests/:id/participants', requireAdmin, async (req, res) => {
    const id = req.params.id;
    const participants = await prisma.contestEntry.findMany({
        where: { contestId: id, paid: true },
        include: { user: { include: { wallet: true } } },
    });
    res.json({ count: participants.length, participants });
});
// Create/update prize pool and payout rules
router.post('/contests/:id/prize', requireAdmin, async (req, res) => {
    const id = req.params.id;
    const { prizePoolCents, payouts } = req.body || {};
    if (typeof prizePoolCents !== 'number' || !Array.isArray(payouts)) {
        return res.status(400).json({ error: 'prizePoolCents (number) and payouts (array) required' });
    }
    const sum = payouts.reduce((a, p) => a + Number(p.percent || 0), 0);
    if (Math.abs(sum - 100) > 0.0001)
        return res.status(400).json({ error: 'payout percents must sum to 100' });
    await prisma.$transaction([
        prisma.contest.update({ where: { id }, data: { prizePoolCents } }),
        prisma.payoutRule.deleteMany({ where: { contestId: id } }),
        prisma.payoutRule.createMany({ data: payouts.map((p) => ({ contestId: id, rank: Number(p.rank), percent: Number(p.percent) })) }),
    ]);
    const contest = await prisma.contest.findUnique({ where: { id }, include: { payoutRules: true } });
    res.json({ ok: true, contest });
});
// Admin audit log (stub listing)
router.get('/actions', requireAdmin, async (req, res) => {
    const { skip, take, page, pageSize } = parsePage(req.query);
    const [items, total] = await Promise.all([
        prisma.adminAction.findMany({ skip, take, orderBy: { createdAt: 'desc' } }),
        prisma.adminAction.count(),
    ]);
    res.json({ page, pageSize, total, items });
});
export default router;
