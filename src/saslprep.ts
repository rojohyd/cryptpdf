/**
 * Minimal password preparation for PDF Rev 5: UTF-8 encode and truncate to 127 bytes.
 * Full SASLprep (RFC 4013) can be added later for strict compliance.
 */

const MAX_PASSWORD_UTF8_BYTES = 127;

/**
 * Prepare password per PDF 2.0: normalize and truncate to 127 UTF-8 bytes.
 * We use UTF-8 encode + truncate; full SASLprep would require Unicode tables.
 */
export function preparePassword(password: string): Uint8Array {
  const encoded = new TextEncoder().encode(password);
  if (encoded.length > MAX_PASSWORD_UTF8_BYTES) {
    return encoded.slice(0, MAX_PASSWORD_UTF8_BYTES);
  }
  return encoded;
}
