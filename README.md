# cryptpdf

Minimal PDF encrypt/decrypt with **AES-256**. Buffer in, buffer out.

- **Encrypt** any PDF with a user and/or owner password.
- **Decrypt** PDFs protected with the same scheme.
- Zero external crypto dependencies — uses Web Crypto (Node 18+).
- Peer dependency: [pdf-lib](https://www.npmjs.com/package/pdf-lib).
- Ships ESM + CJS + TypeScript declarations.

## Install

```bash
npm install cryptpdf pdf-lib
```

## Usage

```js
import { encryptPDF, decryptPDF } from 'cryptpdf';
import fs from 'fs';

// Encrypt
const pdf = new Uint8Array(fs.readFileSync('document.pdf'));
const encrypted = await encryptPDF(pdf, 'user-password', 'owner-password');
fs.writeFileSync('encrypted.pdf', encrypted);

// Decrypt (user or owner password)
const decrypted = await decryptPDF(encrypted, 'user-password');
fs.writeFileSync('decrypted.pdf', decrypted);
```

## API

### `encryptPDF(pdfBytes, userPassword, ownerPassword?, options?)`

Encrypt a PDF buffer with AES-256.

| Parameter       | Type         | Description                                      |
| --------------- | ------------ | ------------------------------------------------ |
| `pdfBytes`      | `Uint8Array` | Input PDF                                        |
| `userPassword`  | `string`     | Password required to open the PDF                |
| `ownerPassword` | `string?`    | Owner password (defaults to `userPassword`)      |
| `options`       | `object?`    | `{ permissions?: number, encryptMetadata?: boolean }` |

Returns `Promise<Uint8Array>` — the encrypted PDF.

### `decryptPDF(pdfBytes, password)`

Decrypt a PDF buffer previously encrypted with `encryptPDF`.

| Parameter  | Type         | Description                        |
| ---------- | ------------ | ---------------------------------- |
| `pdfBytes` | `Uint8Array` | Encrypted PDF                      |
| `password` | `string`     | User or owner password             |

Returns `Promise<Uint8Array>` — the decrypted PDF.
Throws if the password is wrong or the PDF is not AES-256 (R=5, V=5) encrypted.

## How it works

- **Cipher:** AES-256-CBC per stream and string, with a random 16-byte IV prepended to each ciphertext.
- **Key derivation:** 64-round SHA-256 KDF with random 16-byte salts per user/owner password.
- **File encryption key:** 32-byte random key, wrapped in UE/OE entries using the derived password keys.
- **Streams and strings** in the PDF are individually encrypted; the Encrypt dictionary, XRef, and trailer are left in the clear per the PDF spec.
- Only AES-256 (R=5, V=5) is supported. Older schemes (RC4, AES-128) are not.

## Requirements

- Node.js >= 18 (uses `crypto.subtle`)
- `pdf-lib` >= 1.17 as a peer dependency

## License

MIT
