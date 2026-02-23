/**
 * cryptpdf – minimal PDF encrypt/decrypt with AES-256 (PDF Rev 5).
 * Buffer in, buffer out. Peer dependency: pdf-lib.
 */

export { encryptPDF } from './encrypt.js';
export type { EncryptOptions } from './encrypt.js';
export { decryptPDF } from './decrypt.js';
