/**
 * PDF encryption: build Encrypt dict (Rev 5), traverse objects, encrypt streams and strings with AES-256-CBC.
 */

import { PDFDocument, PDFName, PDFHexString, PDFString, PDFDict, PDFArray, PDFRawStream, PDFNumber, PDFBool } from 'pdf-lib';
import { getRandomBytes, aes256CbcEncrypt } from './crypto.js';
import { computeRev5Keys } from './kdf.js';

const IV_LEN = 16;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function encryptObject(
  data: Uint8Array,
  fileKey: Uint8Array
): Promise<Uint8Array> {
  const iv = getRandomBytes(IV_LEN);
  const ciphertext = await aes256CbcEncrypt(fileKey, iv, data);
  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv);
  out.set(ciphertext, iv.length);
  return out;
}

const PDFHexStringOf = (PDFHexString as unknown as { of: (s: string) => PDFHexString }).of;

async function encryptStringsInDict(
  dict: PDFDict,
  enc: (data: Uint8Array) => Promise<Uint8Array>
): Promise<void> {
  for (const [key, value] of dict.entries()) {
    const n = (key as PDFName).asString();
    if (n === '/Length' || n === '/Filter' || n === '/DecodeParms') continue;

    if (value instanceof PDFString) {
      const encrypted = await enc(value.asBytes());
      dict.set(key as PDFName, PDFHexStringOf(bytesToHex(encrypted)));
    } else if (value instanceof PDFHexString) {
      const encrypted = await enc(value.asBytes());
      dict.set(key as PDFName, PDFHexStringOf(bytesToHex(encrypted)));
    } else if (value instanceof PDFDict) {
      await encryptStringsInDict(value, enc);
    } else if (value instanceof PDFArray) {
      await encryptStringsInArray(value, enc);
    }
  }
}

async function encryptStringsInArray(
  arr: PDFArray,
  enc: (data: Uint8Array) => Promise<Uint8Array>
): Promise<void> {
  for (const el of arr.asArray()) {
    if (el instanceof PDFDict) {
      await encryptStringsInDict(el, enc);
    } else if (el instanceof PDFArray) {
      await encryptStringsInArray(el, enc);
    }
  }
}

export interface EncryptOptions {
  permissions?: number;
  encryptMetadata?: boolean;
}

/**
 * Encrypt a PDF with AES-256 (Rev 5). Input and output are PDF buffers.
 */
export async function encryptPDF(
  pdfBytes: Uint8Array,
  userPassword: string,
  ownerPassword?: string,
  options: EncryptOptions = {}
): Promise<Uint8Array> {
  const permissions = options.permissions ?? -4;
  const encryptMetadata = options.encryptMetadata !== false;

  const pdfDoc = await PDFDocument.load(pdfBytes, { ignoreEncryption: true, updateMetadata: false });
  const context = pdfDoc.context;
  const trailer = context.trailerInfo;

  if (!trailer.ID) {
    const fileId = getRandomBytes(16);
    (trailer as unknown as { ID: unknown }).ID = [
      PDFHexStringOf(bytesToHex(fileId)),
      PDFHexStringOf(bytesToHex(fileId)),
    ];
  }

  const keys = await computeRev5Keys({
    userPassword,
    ownerPassword: ownerPassword ?? userPassword,
    permissions,
    encryptMetadata,
  });

  const enc = (data: Uint8Array) => encryptObject(data, keys.fileEncryptionKey);

  const indirectObjects = context.enumerateIndirectObjects();
  for (const [, obj] of indirectObjects) {
    if (obj instanceof PDFDict) {
      const filter = obj.get(PDFName.of('Filter'));
      if (filter && (filter as PDFName).asString() === '/Standard') continue;
    }
    if (obj instanceof PDFRawStream) {
      const streamData = (obj as PDFRawStream & { contents: Uint8Array }).contents;
      const encrypted = await enc(streamData);
      (obj as PDFRawStream & { contents: Uint8Array }).contents = encrypted;
    }
    if (obj instanceof PDFDict) {
      await encryptStringsInDict(obj, enc);
    } else if (obj instanceof PDFArray) {
      await encryptStringsInArray(obj, enc);
    }
  }

  const PDFNumberOf = (PDFNumber as unknown as { of: (n: number) => PDFNumber }).of;

  // Crypt filter: /StdCF with AESV3
  const stdCFDict = PDFDict.withContext(context);
  stdCFDict.set(PDFName.of('Type'), PDFName.of('CryptFilter'));
  stdCFDict.set(PDFName.of('CFM'), PDFName.of('AESV3'));
  stdCFDict.set(PDFName.of('Length'), PDFNumberOf(32));

  const cfDict = PDFDict.withContext(context);
  cfDict.set(PDFName.of('StdCF'), stdCFDict);

  const encryptDict = PDFDict.withContext(context);
  encryptDict.set(PDFName.of('Filter'), PDFName.of('Standard'));
  encryptDict.set(PDFName.of('V'), PDFNumberOf(5));
  encryptDict.set(PDFName.of('R'), PDFNumberOf(5));
  encryptDict.set(PDFName.of('Length'), PDFNumberOf(256));
  encryptDict.set(PDFName.of('P'), PDFNumberOf(permissions));
  encryptDict.set(PDFName.of('O'), PDFHexStringOf(bytesToHex(keys.O)));
  encryptDict.set(PDFName.of('U'), PDFHexStringOf(bytesToHex(keys.U)));
  encryptDict.set(PDFName.of('OE'), PDFHexStringOf(bytesToHex(keys.OE)));
  encryptDict.set(PDFName.of('UE'), PDFHexStringOf(bytesToHex(keys.UE)));
  encryptDict.set(PDFName.of('Perms'), PDFHexStringOf(bytesToHex(keys.Perms)));
  encryptDict.set(PDFName.of('EncryptMetadata'), encryptMetadata ? PDFBool.True : PDFBool.False);
  encryptDict.set(PDFName.of('CF'), cfDict);
  encryptDict.set(PDFName.of('StmF'), PDFName.of('StdCF'));
  encryptDict.set(PDFName.of('StrF'), PDFName.of('StdCF'));

  const encryptRef = context.register(encryptDict);
  trailer.Encrypt = encryptRef;

  return pdfDoc.save({ useObjectStreams: false });
}
