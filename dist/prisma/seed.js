import { prisma } from '../src/lib/prisma';
async function main() {
    const defaults = [
        { slug: 'weekly', title: 'Weekly Contest', realm: 'WEEKLY', playersLimit: 11, transferpool: 0 },
        { slug: 'monthly', title: 'Monthly Contest', realm: 'MONTHLY', playersLimit: 13, transferpool: 1 },
        { slug: 'seasonal', title: 'Seasonal Contest', realm: 'SEASONAL', playersLimit: 15, transferpool: 1 },
    ];
    for (const d of defaults) {
        const contest = await prisma.contest.upsert({
            where: { slug: d.slug },
            update: { title: d.title, playersLimit: d.playersLimit, transferpool: d.transferpool },
            create: { slug: d.slug, title: d.title, realm: d.realm, playersLimit: d.playersLimit, transferpool: d.transferpool },
        });
        const payouts = [
            { rank: 1, percent: 30 },
            { rank: 2, percent: 20 },
            { rank: 3, percent: 15 },
            { rank: 4, percent: 12 },
            { rank: 5, percent: 9 },
            { rank: 6, percent: 6 },
            { rank: 7, percent: 5 },
            { rank: 8, percent: 3 },
        ];
        await prisma.payoutRule.deleteMany({ where: { contestId: contest.id } });
        await prisma.payoutRule.createMany({ data: payouts.map(p => ({ ...p, contestId: contest.id })) });
    }
}
main().then(() => {
    console.log('Seed complete');
    process.exit(0);
}).catch((e) => {
    console.error(e);
    process.exit(1);
});
