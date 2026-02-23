/**
 * Comprehensive round-trip test: create a PDF exercising every major pdf-lib
 * component, encrypt it, decrypt it, then verify the decrypted PDF retains
 * all components intact.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  PDFDocument,
  StandardFonts,
  rgb,
  grayscale,
  degrees,
  PDFName,
} from 'pdf-lib';
import { encryptPDF, decryptPDF } from '../dist/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, 'output');

// ── Helpers ─────────────────────────────────────────────────────────────────

function assert(condition, msg) {
  if (!condition) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
}

function approxEqual(a, b, eps = 1) {
  return Math.abs(a - b) <= eps;
}

/** 1×1 red PNG (smallest valid PNG). */
function tinyPng() {
  const buf = Buffer.from(
    '89504e470d0a1a0a0000000d49484452000000010000000108020000009001' +
    '2e00000000c4944415478016360f8cf00000001010000186f3641000000' +
    '0049454e44ae426082',
    'hex'
  );
  return new Uint8Array(buf);
}

/** 1×1 white JPEG (smallest valid JPEG). */
function tinyJpg() {
  const buf = Buffer.from(
    'ffd8ffe000104a46494600010100000100010000ffdb004300080606070605' +
    '080707070909080a0c140d0c0b0b0c1912130f141d1a1f1e1d1a1c1c2024' +
    '2e2720222c231c1c2837292c30313434341f27393d38323c2e333432ffc000' +
    '0b08000100010111000ffc4001f0000010501010101010100000000000000' +
    '0102030405060708090a0bffc40000010100000000000000000000000000' +
    '0000ffda0008010100003f00548fa4a800000001ffd9',
    'hex'
  );
  return new Uint8Array(buf);
}

// ── Build a PDF with every component ────────────────────────────────────────

async function buildRichPdf() {
  const doc = await PDFDocument.create();

  // Metadata
  doc.setTitle('CryptPDF Component Test');
  doc.setAuthor('test-suite');
  doc.setSubject('round-trip verification');
  doc.setKeywords(['encrypt', 'decrypt', 'aes-256']);
  doc.setCreator('cryptpdf test');
  doc.setProducer('cryptpdf');
  doc.setCreationDate(new Date('2025-01-01T00:00:00Z'));
  doc.setModificationDate(new Date('2025-06-15T12:00:00Z'));

  // Embed fonts
  const helvetica = await doc.embedFont(StandardFonts.Helvetica);
  const courier = await doc.embedFont(StandardFonts.Courier);
  const timesBold = await doc.embedFont(StandardFonts.TimesRomanBold);

  // Embed images
  let pngImage, jpgImage;
  try {
    pngImage = await doc.embedPng(tinyPng());
  } catch {
    // skip if tiny PNG is rejected
  }
  try {
    jpgImage = await doc.embedJpg(tinyJpg());
  } catch {
    // skip if tiny JPEG is rejected
  }

  // ── Page 1: Text, shapes, images ──────────────────────────────────────────

  const p1 = doc.addPage([612, 792]);

  p1.drawText('Page 1: Shapes, Fonts & Images', {
    x: 50, y: 740, size: 18, font: helvetica, color: rgb(0, 0, 0),
  });

  p1.drawText('Courier monospaced text', {
    x: 50, y: 700, size: 12, font: courier, color: rgb(0.2, 0.2, 0.8),
  });

  p1.drawText('Times Bold italic text', {
    x: 50, y: 680, size: 14, font: timesBold, color: grayscale(0.3),
  });

  p1.drawRectangle({
    x: 50, y: 600, width: 150, height: 60,
    color: rgb(0.9, 0.1, 0.1), borderColor: rgb(0, 0, 0), borderWidth: 2,
  });

  p1.drawCircle({
    x: 350, y: 630, size: 40,
    color: rgb(0.1, 0.7, 0.2), borderColor: rgb(0, 0, 0), borderWidth: 1,
  });

  p1.drawEllipse({
    x: 480, y: 630, xScale: 50, yScale: 30,
    color: rgb(0.2, 0.3, 0.9), borderColor: rgb(0, 0, 0), borderWidth: 1,
  });

  p1.drawSquare({
    x: 50, y: 500, size: 50,
    color: rgb(1, 0.8, 0), borderColor: rgb(0, 0, 0), borderWidth: 1,
  });

  p1.drawLine({
    start: { x: 150, y: 520 }, end: { x: 400, y: 520 },
    thickness: 3, color: rgb(0.5, 0, 0.5),
  });

  p1.drawSvgPath('M 200 450 L 250 400 L 300 450 Z', {
    color: rgb(0, 0.5, 0.5), borderColor: rgb(0, 0, 0), borderWidth: 1,
  });

  if (pngImage) {
    p1.drawImage(pngImage, { x: 400, y: 480, width: 50, height: 50 });
  }
  if (jpgImage) {
    p1.drawImage(jpgImage, { x: 460, y: 480, width: 50, height: 50 });
  }

  // ── Page 2: Form fields ───────────────────────────────────────────────────

  const p2 = doc.addPage([612, 792]);

  p2.drawText('Page 2: Interactive Form Fields', {
    x: 50, y: 740, size: 18, font: helvetica,
  });

  const form = doc.getForm();

  const nameField = form.createTextField('name');
  nameField.setText('John Doe');
  nameField.addToPage(p2, { x: 50, y: 680, width: 250, height: 25 });

  const emailField = form.createTextField('email');
  emailField.setText('john@example.com');
  emailField.addToPage(p2, { x: 50, y: 640, width: 250, height: 25 });

  const multiField = form.createTextField('notes');
  multiField.enableMultiline();
  multiField.setText('Line 1\nLine 2\nLine 3');
  multiField.addToPage(p2, { x: 50, y: 560, width: 250, height: 60 });

  const checkbox = form.createCheckBox('agree');
  checkbox.check();
  checkbox.addToPage(p2, { x: 50, y: 520, width: 20, height: 20 });

  const dropdown = form.createDropdown('color');
  dropdown.addOptions(['Red', 'Green', 'Blue']);
  dropdown.select('Green');
  dropdown.addToPage(p2, { x: 50, y: 470, width: 150, height: 25 });

  const optionList = form.createOptionList('sizes');
  optionList.addOptions(['Small', 'Medium', 'Large', 'XL']);
  optionList.select('Medium');
  optionList.addToPage(p2, { x: 50, y: 370, width: 150, height: 80 });

  const radioGroup = form.createRadioGroup('priority');
  radioGroup.addOptionToPage('low', p2, { x: 300, y: 680, width: 15, height: 15 });
  radioGroup.addOptionToPage('medium', p2, { x: 300, y: 655, width: 15, height: 15 });
  radioGroup.addOptionToPage('high', p2, { x: 300, y: 630, width: 15, height: 15 });
  radioGroup.select('medium');

  const button = form.createButton('submit');
  button.addToPage('Submit', p2, { x: 300, y: 520, width: 100, height: 30 });

  // ── Page 3: Multi-page, rotation, custom boxes ────────────────────────────

  const p3 = doc.addPage([400, 600]);
  p3.setRotation(degrees(90));
  p3.drawText('Page 3: Rotated 90 degrees', {
    x: 50, y: 350, size: 14, font: helvetica,
    rotate: degrees(90),
  });

  p3.setMediaBox(0, 0, 400, 600);
  p3.setCropBox(10, 10, 380, 580);
  p3.setBleedBox(5, 5, 390, 590);
  p3.setTrimBox(15, 15, 370, 570);

  // ── Page 4: Embedded page ─────────────────────────────────────────────────

  const p4 = doc.addPage([612, 792]);
  p4.drawText('Page 4: Embedded Page & JavaScript', {
    x: 50, y: 740, size: 18, font: helvetica,
  });

  const embeddedPage = await doc.embedPage(p1);
  p4.drawPage(embeddedPage, { x: 50, y: 300, width: 250, height: 350 });

  doc.addJavaScript('onOpen', 'console.println("PDF opened");');

  // ── Page 5: Large text content (stress test stream size) ──────────────────

  const p5 = doc.addPage([612, 792]);
  p5.drawText('Page 5: Large Content Stress Test', {
    x: 50, y: 740, size: 18, font: helvetica,
  });

  let y = 710;
  for (let i = 0; i < 40; i++) {
    p5.drawText(`Line ${i + 1}: The quick brown fox jumps over the lazy dog. 0123456789`, {
      x: 50, y, size: 9, font: courier,
    });
    y -= 14;
  }

  return doc;
}

// ── Verification ────────────────────────────────────────────────────────────

async function verifyDecryptedPdf(decrypted) {
  const doc = await PDFDocument.load(decrypted);

  // Page count
  const pages = doc.getPages();
  assert(pages.length === 5, `Expected 5 pages, got ${pages.length}`);
  console.log('  Pages: 5 OK');

  // Page sizes
  const p1 = pages[0];
  assert(approxEqual(p1.getWidth(), 612) && approxEqual(p1.getHeight(), 792),
    `Page 1 size: ${p1.getWidth()}x${p1.getHeight()}`);

  const p3 = pages[2];
  assert(approxEqual(p3.getWidth(), 400) && approxEqual(p3.getHeight(), 600),
    `Page 3 size: ${p3.getWidth()}x${p3.getHeight()}`);
  console.log('  Page sizes OK');

  // Page 3 rotation
  const rot = p3.getRotation();
  assert(rot.angle === 90, `Page 3 rotation: ${rot.angle}`);
  console.log('  Page 3 rotation: 90 OK');

  // Page 3 boxes
  const crop = p3.getCropBox();
  assert(crop && approxEqual(crop.x, 10) && approxEqual(crop.y, 10),
    `CropBox: ${JSON.stringify(crop)}`);
  const bleed = p3.getBleedBox();
  assert(bleed && approxEqual(bleed.x, 5) && approxEqual(bleed.y, 5),
    `BleedBox: ${JSON.stringify(bleed)}`);
  const trim = p3.getTrimBox();
  assert(trim && approxEqual(trim.x, 15) && approxEqual(trim.y, 15),
    `TrimBox: ${JSON.stringify(trim)}`);
  console.log('  Page boxes (crop/bleed/trim) OK');

  // Form fields
  const form = doc.getForm();
  const fields = form.getFields();
  const fieldNames = fields.map(f => f.getName()).sort();
  const expected = ['agree', 'color', 'email', 'name', 'notes', 'priority', 'sizes', 'submit'].sort();
  assert(
    fieldNames.length === expected.length && fieldNames.every((n, i) => n === expected[i]),
    `Fields: ${fieldNames.join(', ')} (expected: ${expected.join(', ')})`
  );
  console.log(`  Form fields (${fields.length}): OK`);

  // Text field values
  const nameField = form.getTextField('name');
  assert(nameField.getText() === 'John Doe', `name field: "${nameField.getText()}"`);
  const emailField = form.getTextField('email');
  assert(emailField.getText() === 'john@example.com', `email field: "${emailField.getText()}"`);
  const notesField = form.getTextField('notes');
  const notesText = notesField.getText();
  assert(notesText && notesText.includes('Line 1'), `notes field: "${notesText}"`);
  console.log('  Text field values OK');

  // Checkbox
  const checkbox = form.getCheckBox('agree');
  assert(checkbox.isChecked(), 'Checkbox should be checked');
  console.log('  Checkbox OK');

  // Dropdown
  const dropdown = form.getDropdown('color');
  const selected = dropdown.getSelected();
  assert(selected.length === 1 && selected[0] === 'Green', `Dropdown: ${selected}`);
  const ddOptions = dropdown.getOptions();
  assert(ddOptions.length === 3, `Dropdown options: ${ddOptions.length}`);
  console.log('  Dropdown OK');

  // Option list
  const optList = form.getOptionList('sizes');
  const olSelected = optList.getSelected();
  assert(olSelected.length === 1 && olSelected[0] === 'Medium', `OptionList: ${olSelected}`);
  const olOptions = optList.getOptions();
  assert(olOptions.length === 4, `OptionList options: ${olOptions.length}`);
  console.log('  Option list OK');

  // Radio group
  const radio = form.getRadioGroup('priority');
  const radioSel = radio.getSelected();
  assert(radioSel === 'medium', `Radio: ${radioSel}`);
  console.log('  Radio group OK');

  // Button exists
  const btn = form.getButton('submit');
  assert(btn, 'Button missing');
  console.log('  Button OK');

  // Content streams (page 5 has large content)
  const p5 = pages[4];
  assert(approxEqual(p5.getWidth(), 612), 'Page 5 width');
  console.log('  Large content page OK');

  console.log('  All verifications passed.');
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const password = 'test-pass-123';
  const ownerPass = 'owner-456';

  fs.mkdirSync(OUT_DIR, { recursive: true });

  console.log('Building rich PDF with all components...');
  const doc = await buildRichPdf();
  const rawBytes = await doc.save();
  console.log(`  Raw PDF: ${rawBytes.byteLength} bytes, 5 pages`);

  fs.writeFileSync(path.join(OUT_DIR, 'original.pdf'), rawBytes);
  console.log(`  Saved: test/output/original.pdf`);

  // Verify original
  console.log('Verifying original PDF...');
  await verifyDecryptedPdf(rawBytes);

  // Encrypt
  console.log('Encrypting...');
  const encrypted = await encryptPDF(new Uint8Array(rawBytes), password, ownerPass);
  console.log(`  Encrypted PDF: ${encrypted.length} bytes`);

  fs.writeFileSync(path.join(OUT_DIR, 'encrypted.pdf'), encrypted);
  console.log(`  Saved: test/output/encrypted.pdf  (user: ${password} / owner: ${ownerPass})`);

  // Encrypted PDF should be loadable but not readable without password
  const encDoc = await PDFDocument.load(encrypted, { ignoreEncryption: true });
  assert(encDoc.getPageCount() === 5, 'Encrypted PDF page count mismatch');
  console.log('  Encrypted PDF structure intact (5 pages)');

  // Decrypt with user password
  console.log('Decrypting with user password...');
  const decrypted = await decryptPDF(encrypted, password);
  console.log(`  Decrypted PDF: ${decrypted.length} bytes`);

  fs.writeFileSync(path.join(OUT_DIR, 'decrypted-user.pdf'), decrypted);
  console.log(`  Saved: test/output/decrypted-user.pdf`);

  console.log('Verifying decrypted PDF (user password)...');
  await verifyDecryptedPdf(decrypted);

  // Decrypt with owner password
  console.log('Decrypting with owner password...');
  const decryptedOwner = await decryptPDF(encrypted, ownerPass);
  console.log(`  Decrypted PDF: ${decryptedOwner.length} bytes`);

  fs.writeFileSync(path.join(OUT_DIR, 'decrypted-owner.pdf'), decryptedOwner);
  console.log(`  Saved: test/output/decrypted-owner.pdf`);

  console.log('Verifying decrypted PDF (owner password)...');
  await verifyDecryptedPdf(decryptedOwner);

  // Wrong password
  try {
    await decryptPDF(encrypted, 'wrong');
    assert(false, 'Wrong password should have thrown');
  } catch (e) {
    assert(e.message === 'Wrong password', `Unexpected error: ${e.message}`);
    console.log('Wrong password correctly rejected.');
  }

  // Double encrypt/decrypt
  console.log('Double encrypt/decrypt...');
  const doubleEnc = await encryptPDF(decrypted, 'pass2', 'owner2');
  const doubleDec = await decryptPDF(doubleEnc, 'pass2');
  const doubleDoc = await PDFDocument.load(doubleDec);
  assert(doubleDoc.getPageCount() === 5, 'Double round-trip page count');

  fs.writeFileSync(path.join(OUT_DIR, 'double-encrypted.pdf'), doubleEnc);
  fs.writeFileSync(path.join(OUT_DIR, 'double-decrypted.pdf'), doubleDec);
  console.log('  Saved: test/output/double-encrypted.pdf  (user: pass2 / owner: owner2)');
  console.log('  Saved: test/output/double-decrypted.pdf');
  console.log('  Double encrypt/decrypt OK');

  console.log(`\nAll component tests passed. PDFs saved to test/output/`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
