/**
 * PDF decryption: read Encrypt dict, derive key, decrypt streams and strings (Rev 5 only).
 */

import { PDFDocument, PDFName, PDFHexString, PDFString, PDFDict, PDFArray, PDFRawStream } from 'pdf-lib';
import { aes256CbcDecrypt } from './crypto.js';
import { deriveFileKeyFromPassword } from './kdf.js';

const IV_LEN = 16;

function getEncryptBytes(dict: PDFDict, key: string): Uint8Array | null {
  const v = dict.get(PDFName.of(key));
  if (!v) return null;
  if (v instanceof PDFHexString) return v.asBytes();
  if (v instanceof PDFString) return v.asBytes();
  return null;
}

async function decryptObject(
  data: Uint8Array,
  fileKey: Uint8Array
): Promise<Uint8Array> {
  if (data.length < IV_LEN + 16) throw new Error('Encrypted object too short');
  const iv = data.slice(0, IV_LEN);
  const ciphertext = data.slice(IV_LEN);
  return aes256CbcDecrypt(fileKey, iv, ciphertext);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

const PDFHexStringOf = (PDFHexString as unknown as { of: (s: string) => PDFHexString }).of;

async function decryptStringsInDict(
  dict: PDFDict,
  dec: (data: Uint8Array) => Promise<Uint8Array>
): Promise<void> {
  for (const [key, value] of dict.entries()) {
    const n = (key as PDFName).asString();
    if (n === '/Length' || n === '/Filter' || n === '/DecodeParms') continue;

    if (value instanceof PDFHexString || value instanceof PDFString) {
      const bytes = value.asBytes();
      if (bytes.length < IV_LEN + 16) continue;
      try {
        const decrypted = await dec(bytes);
        dict.set(key as PDFName, PDFHexStringOf(bytesToHex(decrypted)));
      } catch {
        // Not an encrypted string or decryption failed; leave as-is
      }
    } else if (value instanceof PDFDict) {
      await decryptStringsInDict(value, dec);
    } else if (value instanceof PDFArray) {
      await decryptStringsInArray(value, dec);
    }
  }
}

async function decryptStringsInArray(
  arr: PDFArray,
  dec: (data: Uint8Array) => Promise<Uint8Array>
): Promise<void> {
  for (const el of arr.asArray()) {
    if (el instanceof PDFDict) {
      await decryptStringsInDict(el, dec);
    } else if (el instanceof PDFArray) {
      await decryptStringsInArray(el, dec);
    }
  }
}

/**
 * Decrypt a PDF protected with AES-256 (Rev 5). Returns decrypted PDF buffer.
 * Throws if password is wrong or PDF is not Rev 5 encrypted.
 */
export async function decryptPDF(pdfBytes: Uint8Array, password: string): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.load(pdfBytes, { ignoreEncryption: true, updateMetadata: false });
  const context = pdfDoc.context;
  const trailer = context.trailerInfo;

  const encryptRef = trailer.Encrypt;
  if (!encryptRef) throw new Error('PDF is not encrypted');

  const encryptObj = context.lookup(encryptRef);
  if (!(encryptObj instanceof PDFDict)) throw new Error('Invalid Encrypt dictionary');

  const R = encryptObj.lookup(PDFName.of('R'));
  const V = encryptObj.lookup(PDFName.of('V'));
  const r = R && 'asNumber' in R ? (R as { asNumber: () => number }).asNumber() : 0;
  const v = V && 'asNumber' in V ? (V as { asNumber: () => number }).asNumber() : 0;
  if (r !== 5 || v !== 5) {
    throw new Error(`Unsupported encryption: R=${r}, V=${v}. Only AES-256 (R=5, V=5) is supported.`);
  }

  const O = getEncryptBytes(encryptObj, 'O');
  const U = getEncryptBytes(encryptObj, 'U');
  const OE = getEncryptBytes(encryptObj, 'OE');
  const UE = getEncryptBytes(encryptObj, 'UE');

  if (!O || !U || !OE || !UE || O.length !== 48 || U.length !== 48 || OE.length !== 32 || UE.length !== 32) {
    throw new Error(
      `Invalid Encrypt dictionary: O=${O?.length}, U=${U?.length}, OE=${OE?.length}, UE=${UE?.length}`
    );
  }

  const fileKey = await deriveFileKeyFromPassword(password, U, O, OE, UE);
  if (!fileKey) throw new Error('Wrong password');

  const dec = (data: Uint8Array) => decryptObject(data, fileKey);

  const indirectObjects = context.enumerateIndirectObjects();
  for (const [, obj] of indirectObjects) {
    if (obj instanceof PDFDict) {
      const filter = obj.get(PDFName.of('Filter'));
      if (filter && (filter as PDFName).asString() === '/Standard') continue;
    }
    if (obj instanceof PDFRawStream) {
      const streamData = (obj as PDFRawStream & { contents: Uint8Array }).contents;
      const decrypted = await dec(streamData);
      (obj as PDFRawStream & { contents: Uint8Array }).contents = decrypted;
    }
    if (obj instanceof PDFDict) {
      await decryptStringsInDict(obj, dec);
    } else if (obj instanceof PDFArray) {
      await decryptStringsInArray(obj, dec);
    }
  }

  delete (trailer as Record<string, unknown>).Encrypt;

  return pdfDoc.save({ useObjectStreams: false });
}
