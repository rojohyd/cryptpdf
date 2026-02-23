/**
 * Round-trip test: create PDF with pdf-lib, encrypt, decrypt, verify.
 */
import { PDFDocument } from 'pdf-lib';
import { encryptPDF, decryptPDF } from '../dist/index.js';

async function main() {
  const doc = await PDFDocument.create();
  const page = doc.addPage([300, 400]);
  page.drawText('Hello, cryptpdf!', { x: 50, y: 350, size: 24 });
  const rawPdf = await doc.save();

  const userPass = 'user123';
  const ownerPass = 'owner456';

  console.log('Encrypting...');
  const encrypted = await encryptPDF(
    new Uint8Array(rawPdf),
    userPass,
    ownerPass,
    { encryptMetadata: true }
  );
  console.log('Encrypted length:', encrypted.length);

  console.log('Decrypting with user password...');
  const decrypted = await decryptPDF(encrypted, userPass);
  console.log('Decrypted length:', decrypted.length);

  console.log('Decrypting with owner password...');
  const decryptedWithOwner = await decryptPDF(encrypted, ownerPass);
  console.log('Decrypt with owner password OK, length:', decryptedWithOwner.length);

  // Verify decrypted PDF is valid by loading it
  const verifyDoc = await PDFDocument.load(decrypted);
  const pages = verifyDoc.getPages();
  console.log('Decrypted PDF has', pages.length, 'page(s)');

  // Wrong password should throw
  try {
    await decryptPDF(encrypted, 'wrong');
    console.error('ERROR: wrong password should throw');
    process.exit(1);
  } catch (e) {
    console.log('Wrong password correctly rejected:', e.message);
  }

  console.log('All tests passed.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
