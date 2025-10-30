import nacl from 'tweetnacl'
import bs58 from 'bs58'

/**
 * Verify a Solana signature over a UTF-8 message.
 * @param address base58 public key
 * @param message utf8 string
 * @param signature base58 signature
 */
export function verifySolanaSignature(address: string, message: string, signature: string): boolean {
  try {
    const pubkey = bs58.decode(address)
    const sig = bs58.decode(signature)
    const msg = new TextEncoder().encode(message)
    return nacl.sign.detached.verify(msg, sig, pubkey)
  } catch {
    return false
  }
}
