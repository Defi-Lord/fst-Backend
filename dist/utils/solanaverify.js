"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifySolanaSignature = verifySolanaSignature;
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const bs58_1 = __importDefault(require("bs58"));
/**
 * Verify a Solana signature over a UTF-8 message.
 * @param address base58 public key
 * @param message utf8 string
 * @param signature base58 signature
 */
function verifySolanaSignature(address, message, signature) {
    try {
        const pubkey = bs58_1.default.decode(address);
        const sig = bs58_1.default.decode(signature);
        const msg = new TextEncoder().encode(message);
        return tweetnacl_1.default.sign.detached.verify(msg, sig, pubkey);
    }
    catch {
        return false;
    }
}
