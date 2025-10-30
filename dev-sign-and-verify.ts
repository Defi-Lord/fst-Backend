// dev-sign-and-verify.ts
import { Keypair, PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";

// 1️⃣ Generate a Solana wallet keypair
const keypair = Keypair.generate();
const publicKey = keypair.publicKey.toBase58();

console.log("🪪 Public Key:", publicKey);

// 2️⃣ Create a mock message (like a nonce)
const message = "Hello from Solana verification demo!";
const messageBytes = new TextEncoder().encode(message);

// 3️⃣ Sign the message
const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
console.log("🖊️ Signature (base64):", Buffer.from(signature).toString("base64"));

// 4️⃣ Verify the signature
const isValid = nacl.sign.detached.verify(
  messageBytes,
  signature,
  keypair.publicKey.toBytes()
);

console.log("✅ Signature verified:", isValid);
