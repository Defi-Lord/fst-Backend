/*
  Warnings:

  - The primary key for the `Nonce` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `id` on the `Nonce` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "Nonce_address_key";

-- AlterTable
ALTER TABLE "Nonce" DROP CONSTRAINT "Nonce_pkey",
DROP COLUMN "id",
ADD CONSTRAINT "Nonce_pkey" PRIMARY KEY ("address");
