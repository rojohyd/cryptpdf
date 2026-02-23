/**
 * Thin wrapper over Node crypto / Web Crypto for AES-256-CBC and SHA-256.
 * No external crypto dependencies.
 */

const AES_BLOCK_SIZE = 16;
const KEY_LENGTH = 32;

let _nodeCrypto: typeof import('crypto') | null = null;

async function getNodeCrypto(): Promise<typeof import('crypto')> {
  if (_nodeCrypto) return _nodeCrypto;
  try {
    _nodeCrypto = await import('node:crypto') as typeof import('crypto');
    return _nodeCrypto;
  } catch {
    throw new Error('cryptpdf: Node crypto module not available');
  }
}

export function getRandomBytes(length: number): Uint8Array {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    const out = new Uint8Array(length);
    globalThis.crypto.getRandomValues(out);
    return out;
  }
  throw new Error('cryptpdf: no crypto available. Use Node 18+ or an environment with crypto.getRandomValues.');
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    const buf = await globalThis.crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(buf);
  }
  const crypto = await getNodeCrypto();
  const h = crypto.createHash('sha256').update(Buffer.from(data));
  return new Uint8Array(h.digest());
}


/** CBC encrypt/decrypt without padding (for exact block multiples). Uses ECB per block. */
function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

export async function aes256CbcEncryptNoPadding(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  if (plaintext.length % AES_BLOCK_SIZE !== 0 || iv.length !== AES_BLOCK_SIZE) {
    throw new Error('Plaintext length must be multiple of 16; IV must be 16 bytes');
  }
  const out = new Uint8Array(plaintext.length);
  let prev = iv;
  for (let i = 0; i < plaintext.length; i += AES_BLOCK_SIZE) {
    const block = xor16(prev, plaintext.subarray(i, i + AES_BLOCK_SIZE));
    const enc = await aes256EcbEncrypt(key, block);
    out.set(enc, i);
    prev = enc;
  }
  return out;
}

export async function aes256CbcDecryptNoPadding(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  if (ciphertext.length % AES_BLOCK_SIZE !== 0 || iv.length !== AES_BLOCK_SIZE) {
    throw new Error('Ciphertext length must be multiple of 16; IV must be 16 bytes');
  }
  const out = new Uint8Array(ciphertext.length);
  let prev = new Uint8Array(iv);
  for (let i = 0; i < ciphertext.length; i += AES_BLOCK_SIZE) {
    const enc = new Uint8Array(ciphertext.subarray(i, i + AES_BLOCK_SIZE));
    const dec = await aes256EcbDecrypt(key, enc);
    for (let j = 0; j < 16; j++) out[i + j] = prev[j]! ^ dec[j]!;
    prev = enc;
  }
  return out;
}

/** AES-256-CBC encrypt with PKCS#7 padding (handled natively by Web Crypto / Node). */
export async function aes256CbcEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== KEY_LENGTH || iv.length !== AES_BLOCK_SIZE) {
    throw new Error('AES-256-CBC: key must be 32 bytes, IV 16 bytes');
  }
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw', key, { name: 'AES-CBC', length: 256 }, false, ['encrypt']
    );
    const buf = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-CBC', iv }, cryptoKey, plaintext
    );
    return new Uint8Array(buf);
  }
  const crypto = await getNodeCrypto();
  const c = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv));
  return new Uint8Array(Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]));
}

/** AES-256-CBC decrypt with PKCS#7 unpadding (handled natively by Web Crypto / Node). */
export async function aes256CbcDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== KEY_LENGTH || iv.length !== AES_BLOCK_SIZE) {
    throw new Error('AES-256-CBC: key must be 32 bytes, IV 16 bytes');
  }
  if (ciphertext.length % AES_BLOCK_SIZE !== 0) {
    throw new Error('AES-256-CBC: ciphertext length must be multiple of 16');
  }
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw', key, { name: 'AES-CBC', length: 256 }, false, ['decrypt']
    );
    const buf = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv }, cryptoKey, ciphertext
    );
    return new Uint8Array(buf);
  }
  const crypto = await getNodeCrypto();
  const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv));
  return new Uint8Array(Buffer.concat([d.update(Buffer.from(ciphertext)), d.final()]));
}

/** AES-256-ECB one block (16 bytes). Used for Perms and for CBC-no-padding. */
export async function aes256EcbEncrypt(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  if (block.length !== AES_BLOCK_SIZE || key.length !== KEY_LENGTH) {
    throw new Error('AES-256-ECB: 16-byte block, 32-byte key');
  }
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt']
    );
    const buf = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: new Uint8Array(16) },
      cryptoKey,
      block
    );
    return new Uint8Array(buf).slice(0, AES_BLOCK_SIZE);
  }
  const crypto = await getNodeCrypto();
  const c = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(key),
    Buffer.alloc(16, 0)
  );
  const out = Buffer.concat([c.update(Buffer.from(block)), c.final()]);
  return new Uint8Array(out.slice(0, AES_BLOCK_SIZE));
}

export async function aes256EcbDecrypt(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  if (block.length !== AES_BLOCK_SIZE || key.length !== KEY_LENGTH) {
    throw new Error('AES-256-ECB: 16-byte block, 32-byte key');
  }
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    // Web Crypto CBC decrypt validates PKCS#7 on the result, which fails for
    // arbitrary plaintext. Work around by appending a second ciphertext block
    // that decrypts to a full PKCS#7 padding block [0x10]*16.
    //   C2 = AES-Encrypt(K, [0x10]*16 XOR C)
    //   CBC-Decrypt(K, IV=0, [C, C2]):
    //     P1 = AES-Decrypt(K, C) XOR 0 = AES-Decrypt(K, C)   <- what we want
    //     P2 = AES-Decrypt(K, C2) XOR C = [0x10]*16           <- valid padding, stripped
    const FULL_PAD = new Uint8Array(16).fill(16);
    const c2Input = xor16(FULL_PAD, block);
    const c2 = await aes256EcbEncrypt(key, c2Input);

    const twoBlocks = new Uint8Array(32);
    twoBlocks.set(block, 0);
    twoBlocks.set(c2, 16);

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw', key, { name: 'AES-CBC', length: 256 }, false, ['decrypt']
    );
    const buf = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: new Uint8Array(16) }, cryptoKey, twoBlocks
    );
    return new Uint8Array(buf);
  }
  const crypto = await getNodeCrypto();
  const d = crypto.createDecipheriv(
    'aes-256-cbc', Buffer.from(key), Buffer.alloc(16, 0)
  );
  d.setAutoPadding(false);
  const out = Buffer.concat([d.update(Buffer.from(block)), d.final()]);
  return new Uint8Array(out);
}
