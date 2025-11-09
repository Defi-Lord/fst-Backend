"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const prisma_1 = require("../lib/prisma");
const pagination_1 = require("../utils/pagination");
const router = (0, express_1.Router)();
// Admin dashboard summary
router.get('/dashboard/summary', auth_1.requireAdmin, async (_req, res) => {
    const [users, wallets, entries, weekly, monthly, seasonal] = await Promise.all([
        prisma_1.prisma.user.count(),
        prisma_1.prisma.wallet.count(),
        prisma_1.prisma.contestEntry.count({ where: { paid: true } }),
        prisma_1.prisma.contestEntry.count({ where: { paid: true, contest: { realm: 'WEEKLY' } } }),
        prisma_1.prisma.contestEntry.count({ where: { paid: true, contest: { realm: 'MONTHLY' } } }),
        prisma_1.prisma.contestEntry.count({ where: { paid: true, contest: { realm: 'SEASONAL' } } }),
    ]);
    res.json({ users, wallets, paidEntries: entries, breakdown: { weekly, monthly, seasonal } });
});
// List users with their contests
router.get('/users', auth_1.requireAdmin, async (req, res) => {
    const { skip, take, page, pageSize } = (0, pagination_1.parsePage)(req.query);
    const [items, total] = await Promise.all([
        prisma_1.prisma.user.findMany({
            skip, take,
            include: {
                wallet: true,
                entries: { include: { contest: true } },
            },
            orderBy: { createdAt: 'desc' },
        }),
        prisma_1.prisma.user.count(),
    ]);
    res.json({ page, pageSize, total, items });
});
// Contest participants per contest
router.get('/contests/:id/participants', auth_1.requireAdmin, async (req, res) => {
    const id = req.params.id;
    const participants = await prisma_1.prisma.contestEntry.findMany({
        where: { contestId: id, paid: true },
        include: { user: { include: { wallet: true } } },
    });
    res.json({ count: participants.length, participants });
});
// Create/update prize pool and payout rules
router.post('/contests/:id/prize', auth_1.requireAdmin, async (req, res) => {
    const id = req.params.id;
    const { prizePoolCents, payouts } = req.body || {};
    if (typeof prizePoolCents !== 'number' || !Array.isArray(payouts)) {
        return res.status(400).json({ error: 'prizePoolCents (number) and payouts (array) required' });
    }
    const sum = payouts.reduce((a, p) => a + Number(p.percent || 0), 0);
    if (Math.abs(sum - 100) > 0.0001)
        return res.status(400).json({ error: 'payout percents must sum to 100' });
    await prisma_1.prisma.$transaction([
        prisma_1.prisma.contest.update({ where: { id }, data: { prizePoolCents } }),
        prisma_1.prisma.payoutRule.deleteMany({ where: { contestId: id } }),
        prisma_1.prisma.payoutRule.createMany({ data: payouts.map((p) => ({ contestId: id, rank: Number(p.rank), percent: Number(p.percent) })) }),
    ]);
    const contest = await prisma_1.prisma.contest.findUnique({ where: { id }, include: { payoutRules: true } });
    res.json({ ok: true, contest });
});
// Admin audit log (stub listing)
router.get('/actions', auth_1.requireAdmin, async (req, res) => {
    const { skip, take, page, pageSize } = (0, pagination_1.parsePage)(req.query);
    const [items, total] = await Promise.all([
        prisma_1.prisma.adminAction.findMany({ skip, take, orderBy: { createdAt: 'desc' } }),
        prisma_1.prisma.adminAction.count(),
    ]);
    res.json({ page, pageSize, total, items });
});
exports.default = router;
