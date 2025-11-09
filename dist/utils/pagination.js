"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parsePage = parsePage;
function parsePage(query) {
    const page = Math.max(1, parseInt(query.page) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(query.pageSize) || 20));
    const skip = (page - 1) * pageSize;
    const take = pageSize;
    return { page, pageSize, skip, take };
}
