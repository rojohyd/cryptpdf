/**
 * PDF Standard Security Handler Revision 5 key derivation.
 * Implements Algorithms 3.8, 3.9, 3.10 from the Adobe Supplement to ISO 32000.
 *
 * U/O structure (48 bytes each):
 *   [0:32]  = SHA-256 hash for password verification
 *   [32:40] = validation salt (8 random bytes)
 *   [40:48] = key salt (8 random bytes)
 */

import { sha256, getRandomBytes } from './crypto.js';
import {
  aes256CbcEncryptNoPadding,
  aes256CbcDecryptNoPadding,
  aes256EcbEncrypt,
} from './crypto.js';
import { preparePassword } from './saslprep.js';

const ZERO_IV = new Uint8Array(16);

function concat(...arr: Uint8Array[]): Uint8Array {
  const total = arr.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arr) { out.set(a, off); off += a.length; }
  return out;
}

export interface Rev5Keys {
  fileEncryptionKey: Uint8Array;
  O: Uint8Array;
  U: Uint8Array;
  OE: Uint8Array;
  UE: Uint8Array;
  Perms: Uint8Array;
}

export interface Rev5EncryptParams {
  userPassword: string;
  ownerPassword: string;
  permissions: number;
  encryptMetadata: boolean;
}

/**
 * Compute all Rev 5 Encrypt dictionary values and the file encryption key.
 * Algorithms 3.8 (U/UE), 3.9 (O/OE), 3.10 (Perms).
 */
export async function computeRev5Keys(params: Rev5EncryptParams): Promise<Rev5Keys> {
  const userPwd = preparePassword(params.userPassword);
  const ownerPwd = preparePassword(params.ownerPassword || params.userPassword);
  const fileEncryptionKey = getRandomBytes(32);

  // --- Algorithm 3.8: U and UE ---
  const userValSalt = getRandomBytes(8);
  const userKeySalt = getRandomBytes(8);
  const uHash = await sha256(concat(userPwd, userValSalt));
  const U = concat(uHash, userValSalt, userKeySalt);

  const ueKey = await sha256(concat(userPwd, userKeySalt));
  const UE = await aes256CbcEncryptNoPadding(ueKey, ZERO_IV, fileEncryptionKey);

  // --- Algorithm 3.9: O and OE (owner hash includes U) ---
  const ownerValSalt = getRandomBytes(8);
  const ownerKeySalt = getRandomBytes(8);
  const oHash = await sha256(concat(ownerPwd, ownerValSalt, U));
  const O = concat(oHash, ownerValSalt, ownerKeySalt);

  const oeKey = await sha256(concat(ownerPwd, ownerKeySalt, U));
  const OE = await aes256CbcEncryptNoPadding(oeKey, ZERO_IV, fileEncryptionKey);

  // --- Algorithm 3.10: Perms ---
  const permsBlock = new Uint8Array(16);
  const p = (params.permissions >>> 0) & 0xFFFFFFFF;
  permsBlock[0] = p & 0xFF;
  permsBlock[1] = (p >> 8) & 0xFF;
  permsBlock[2] = (p >> 16) & 0xFF;
  permsBlock[3] = (p >> 24) & 0xFF;
  permsBlock[4] = 0xFF;
  permsBlock[5] = 0xFF;
  permsBlock[6] = 0xFF;
  permsBlock[7] = 0xFF;
  permsBlock[8] = params.encryptMetadata ? 0x54 : 0x46; // 'T' or 'F'
  permsBlock[9] = 0x61;  // 'a'
  permsBlock[10] = 0x64; // 'd'
  permsBlock[11] = 0x62; // 'b'
  const rnd = getRandomBytes(4);
  permsBlock.set(rnd, 12);
  const Perms = await aes256EcbEncrypt(fileEncryptionKey, permsBlock);

  return { fileEncryptionKey, O, U, OE, UE, Perms };
}

/**
 * Recover the file encryption key from a user or owner password.
 * Tries user password first, then owner password.
 */
export async function deriveFileKeyFromPassword(
  password: string,
  U: Uint8Array,
  O: Uint8Array,
  OE: Uint8Array,
  UE: Uint8Array,
): Promise<Uint8Array | null> {
  const pwd = preparePassword(password);

  // Try user password: SHA-256(pwd || U[32:40]) should match U[0:32]
  const userValSalt = U.subarray(32, 40);
  const userKeySalt = U.subarray(40, 48);
  const uCheck = await sha256(concat(pwd, userValSalt));
  if (compareBytes(uCheck, U.subarray(0, 32)) === 0) {
    try {
      const ueKey = await sha256(concat(pwd, userKeySalt));
      const key = await aes256CbcDecryptNoPadding(ueKey, ZERO_IV, UE);
      if (key.length === 32) return key;
    } catch {
      // UE decryption failed
    }
  }

  // Try owner password: SHA-256(pwd || O[32:40] || U) should match O[0:32]
  const ownerValSalt = O.subarray(32, 40);
  const ownerKeySalt = O.subarray(40, 48);
  const oCheck = await sha256(concat(pwd, ownerValSalt, U));
  if (compareBytes(oCheck, O.subarray(0, 32)) === 0) {
    try {
      const oeKey = await sha256(concat(pwd, ownerKeySalt, U));
      const key = await aes256CbcDecryptNoPadding(oeKey, ZERO_IV, OE);
      if (key.length === 32) return key;
    } catch {
      // OE decryption failed
    }
  }

  return null;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return 1;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return 1;
  return 0;
}
