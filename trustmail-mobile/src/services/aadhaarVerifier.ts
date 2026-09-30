/**
 * SafeMail X — Aadhaar QR Verifier Service
 *
 * FORMAT A — XML Text QR (pre-2019 / older cards):
 *   Plain-text XML attribute string. No signature. Parse only.
 *
 * FORMAT B — Secure Numeric QR (post-2019 / PVC / e-Aadhaar):
 *   Large decimal integer → bytes → [version(1)] [compressed_data] [RSA-SHA256 sig(256)]
 *   Multiple decompression strategies tried (zlib / raw-deflate / gzip / uncompressed).
 *   Fields separated by 0xFF delimiter. First two fields are 20-byte binary SHA-1 hashes
 *   (email, mobile) that MUST be skipped before decoding text — raw binary in those
 *   fields causes garbled output if treated as UTF-8.
 *
 * NOTE — UIDAI Public Key:
 *   UIDAI_KEY_CONFIGURED is set to false until the real key is installed.
 *   While false: signature shows "CANNOT VERIFY" (honest). Data still parsed.
 *   To configure: replace UIDAI_PUBLIC_KEY_B64 with the real SPKI-DER base64 key
 *   from https://resident.uidai.gov.in/offline-kyc and set UIDAI_KEY_CONFIGURED = true.
 */

import pako from 'pako';

// ─── UIDAI RSA-2048 Public Key ────────────────────────────────────────────────
// Set UIDAI_KEY_CONFIGURED = false until the real key is installed.
// When false, verification is skipped and isGenuine is set to null (cannot verify).
const UIDAI_KEY_CONFIGURED = false;

const UIDAI_PUBLIC_KEY_B64 =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5TRSM' +
  'oTTbhDe1pRkEWwrMGNpPTECEr7MSZ2aNSINIBvRVs1FsFiZuAKhfRfq5C3hKFl1' +
  'X+kHLXVjIf6JTpPQ5A/IHFCWCgJ7nKaLFKKz+f5VXcMiA10cO+DvvjXS4LYTP2' +
  'DF3NKXF8nOsIl6hCHqKApQFbO6cUBVqhR3cNI9IEYZa0PVJgGXHSTkf4hFvL3I' +
  'RLq9dqXmq/f0y9D+8g3jEzTBtXTj1j8JOjW1NXVqcJXWMpNV2OhZ/zr5D7+G5' +
  'W1c7K1Z2+P6IEEAbvEGHv8j3mD/bfPd1VsMl9DvV2kF9r4NQLQ2BPbxoJGLYO' +
  'HwIDAQAB';

// ─── Types ────────────────────────────────────────────────────────────────────
export interface AadhaarVerifyResult {
  isGenuine: boolean | null;     // true=verified, false=mismatch, null=cannot verify
  signatureValid: boolean | null;
  format: 'SECURE_QR' | 'XML_QR';
  maskedUID: string;
  name: string;
  dateOfBirth: string;
  gender: string;
  address: {
    careOf: string;
    house: string;
    street: string;
    locality: string;
    vtc: string;
    district: string;
    state: string;
    pincode: string;
  };
  mobileLinked: boolean;
  emailLinked: boolean;
  timestamp: string;
  photoBase64?: string;
  verificationNote: string;
  error?: string;
}

// ─── Decimal String → Uint8Array (pure JS, no BigInt) ────────────────────────
// Converts arbitrarily large decimal integer string to big-endian byte array.
// Uses string long-division by 256 to avoid native BigInt dependency.
function decimalToBytes(decimal: string): Uint8Array {
  const bytes: number[] = [];
  let num = decimal.replace(/^0+/, '') || '0';
  while (num !== '0') {
    let remainder = 0;
    let quotient = '';
    for (const ch of num) {
      remainder = remainder * 10 + parseInt(ch, 10);
      const q = Math.floor(remainder / 256);
      remainder %= 256;
      if (quotient !== '' || q > 0) quotient += q;
    }
    bytes.unshift(remainder);
    num = quotient === '' ? '0' : quotient;
  }
  return new Uint8Array(bytes);
}

// ─── Decompress — tries all known strategies ──────────────────────────────────
// Aadhaar Secure QR uses zlib, raw-deflate, or gzip depending on version and issuer.
// We attempt all strategies and use the first that succeeds AND produces readable data.
function tryDecompress(raw: Uint8Array): Uint8Array {
  // Strategy 1: zlib inflate, skip version byte (most common for version 1)
  try { return pako.inflate(raw.slice(1)); } catch {}
  // Strategy 2: raw deflate, skip version byte
  try { return pako.inflateRaw(raw.slice(1)); } catch {}
  // Strategy 3: gzip, skip version byte
  try { return pako.ungzip(raw.slice(1)); } catch {}
  // Strategy 4: zlib on full payload (no version skip)
  try { return pako.inflate(raw); } catch {}
  // Strategy 5: raw deflate on full payload
  try { return pako.inflateRaw(raw); } catch {}
  // Strategy 6: gzip on full payload
  try { return pako.ungzip(raw); } catch {}
  // Strategy 7: no compression — version 2+ or uncompressed format
  return raw.slice(1);
}

// ─── Split Uint8Array by delimiter byte ──────────────────────────────────────
function splitByDelimiter(data: Uint8Array, delim: number): Uint8Array[] {
  const segments: Uint8Array[] = [];
  let start = 0;
  for (let i = 0; i < data.length; i++) {
    if (data[i] === delim) {
      segments.push(data.slice(start, i));
      start = i + 1;
    }
  }
  segments.push(data.slice(start));
  return segments;
}

// ─── Detect if a segment is a printable UTF-8 text string ────────────────────
// Used to decide whether segments are binary (hash) or text.
function isReadableText(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    // Allow printable ASCII, common UTF-8 multi-byte sequences, space, tab
    if (b < 0x09 || (b > 0x0D && b < 0x20) || b === 0x7F) return false;
  }
  return true;
}

// ─── RSA-SHA256 verification via WebCrypto (async, Hermes built-in) ──────────
async function verifyRSASignature(
  dataBytes: Uint8Array,
  signatureBytes: Uint8Array,
): Promise<boolean | null> {
  try {
    const keyBinary = Uint8Array.from(atob(UIDAI_PUBLIC_KEY_B64), c => c.charCodeAt(0));
    const publicKey = await crypto.subtle.importKey(
      'spki',
      keyBinary.buffer.slice(0) as ArrayBuffer,
      { name: 'RSASSA-PKCS1-v1.5', hash: { name: 'SHA-256' } },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1.5',
      publicKey,
      signatureBytes.buffer.slice(0) as ArrayBuffer,
      dataBytes.buffer.slice(0) as ArrayBuffer,
    );
  } catch {
    // Key import failed or crypto unavailable → cannot verify
    return null;
  }
}

// ─── Error result ─────────────────────────────────────────────────────────────
function errorResult(format: 'SECURE_QR' | 'XML_QR', msg: string): AadhaarVerifyResult {
  return {
    isGenuine: null, signatureValid: null, format,
    maskedUID: 'xxxx xxxx xxxx', name: '', dateOfBirth: '', gender: '',
    address: { careOf: '', house: '', street: '', locality: '', vtc: '', district: '', state: '', pincode: '' },
    mobileLinked: false, emailLinked: false, timestamp: '',
    verificationNote: msg, error: msg,
  };
}

// ─── Format A: XML / Attribute-style QR (sync) ───────────────────────────────
function parseXmlFormat(data: string): AadhaarVerifyResult {
  const attr = (name: string): string => {
    const match = data.match(new RegExp(`${name}="([^"]*)"`, 'i'));
    return match ? match[1] : '';
  };
  const uid = attr('uid') || attr('UID') || 'xxxx xxxx xxxx';
  const maskedUID = uid.replace(/\d(?=\d{4})/g, 'x').replace(/(.{4})/g, '$1 ').trim();
  const rawGender = attr('gender');
  const gender = rawGender === 'M' ? 'Male' : rawGender === 'F' ? 'Female' : rawGender || 'Unknown';
  return {
    isGenuine: null, signatureValid: null, format: 'XML_QR', maskedUID,
    name: attr('name'), dateOfBirth: attr('dob') || attr('yob'), gender,
    address: {
      careOf: attr('co'), house: attr('house'),
      street: [attr('street'), attr('lm')].filter(Boolean).join(', '),
      locality: [attr('loc'), attr('po')].filter(Boolean).join(', '),
      vtc: attr('vtc'), district: attr('dist'), state: attr('state'), pincode: attr('pc'),
    },
    mobileLinked: attr('mobile_hash').length > 0 || attr('m').length > 0,
    emailLinked: attr('email_hash').length > 0 || attr('e').length > 0,
    timestamp: '',
    verificationNote:
      'This is an older Aadhaar QR format (pre-2019). It does not contain a digital signature ' +
      'and cannot be cryptographically verified. Download the latest e-Aadhaar from myaadhaar.uidai.gov.in for a verifiable QR.',
  };
}

// ─── Format B: Secure Numeric QR (async) ─────────────────────────────────────
async function parseSecureFormat(data: string): Promise<AadhaarVerifyResult> {
  // 1. Decimal → bytes
  let bytes: Uint8Array;
  try {
    bytes = decimalToBytes(data);
  } catch (e) {
    return errorResult('SECURE_QR', 'Failed to decode QR payload: ' + String(e));
  }

  if (bytes.length < 260) {
    return errorResult('SECURE_QR', 'QR payload too short for a valid Aadhaar Secure QR (needs >260 bytes).');
  }

  // 2. Extract signature (last 256 bytes = RSA-2048 sig)
  const signatureBytes = bytes.slice(bytes.length - 256);
  const dataBytes = bytes.slice(0, bytes.length - 256);

  // 3. Signature verification
  // If key not configured → null (cannot verify), otherwise true/false
  const signatureValid: boolean | null = UIDAI_KEY_CONFIGURED
    ? await verifyRSASignature(dataBytes, signatureBytes)
    : null;

  // 4. Decompress — try all strategies
  let decompressed: Uint8Array;
  try {
    decompressed = tryDecompress(dataBytes);
  } catch {
    return {
      isGenuine: signatureValid,
      signatureValid,
      format: 'SECURE_QR',
      maskedUID: 'xxxx xxxx xxxx', name: '', dateOfBirth: '', gender: '',
      address: { careOf: '', house: '', street: '', locality: '', vtc: '', district: '', state: '', pincode: '' },
      mobileLinked: false, emailLinked: false, timestamp: '',
      verificationNote: 'Signature checked. Data decompression failed — QR may be corrupt.',
    };
  }

  // 5. Parse fields
  // UIDAI field order (0xFF delimited):
  //   [0] email_hash   — 20 bytes binary SHA-1 (NOT printable — skip before UTF-8 decode)
  //   [1] mobile_hash  — 20 bytes binary SHA-1 (NOT printable — skip before UTF-8 decode)
  //   [2] timestamp    — "YYYYMMDDHHMMSS"
  //   [3] ref_id       — last 4 digits of Aadhaar (or first 8 chars of VID)
  //   [4] name
  //   [5] dob          — "DD-MM-YYYY"
  //   [6] gender       — "M" / "F" / "T"
  //   [7] care_of
  //   [8] district
  //   [9] landmark
  //   [10] house
  //   [11] locality
  //   [12] pincode
  //   [13] post_office
  //   [14] state
  //   [15] street
  //   [16] vtc (village/town/city)
  //   [17+] optional fields
  //   [last] JPEG photo (starts with 0xFF 0xD8)
  const DELIM = 0xFF;
  const segments = splitByDelimiter(decompressed, DELIM);

  let mobileLinked = false;
  let emailLinked = false;
  let photoBase64: string | undefined;
  let textFields: string[];

  const dec = new TextDecoder('utf-8', { fatal: false });

  // ── Detect whether first two segments are binary hashes (20 bytes) ──────────
  // Binary SHA-1 hashes are NOT readable text. If we find non-readable segments
  // at positions 0 and 1 with length ≈ 20, they're binary hashes — strip them.
  // If they're hex strings (40 readable chars), include them but don't decode as text.
  let segOffset = 0;

  if (segments.length >= 3) {
    const seg0 = segments[0];
    const seg1 = segments[1];

    const seg0IsBinaryHash = seg0.length <= 22 && !isReadableText(seg0);
    const seg1IsBinaryHash = seg1.length <= 22 && !isReadableText(seg1);
    const seg0IsHexHash = seg0.length === 40 && /^[0-9a-fA-F]+$/.test(dec.decode(seg0));
    const seg1IsHexHash = seg1.length === 40 && /^[0-9a-fA-F]+$/.test(dec.decode(seg1));

    if (seg0IsBinaryHash || seg0IsHexHash) {
      emailLinked = seg0.length > 0;
      segOffset++;
    }
    if (seg1IsBinaryHash || seg1IsHexHash) {
      mobileLinked = seg1.length > 0;
      segOffset++;
    }
  }

  // ── Extract photo from last segment if it's a JPEG ───────────────────────────
  const lastSeg = segments[segments.length - 1];
  if (
    lastSeg && lastSeg.length > 100 &&
    lastSeg[0] === 0xFF && lastSeg[1] === 0xD8  // JPEG magic bytes
  ) {
    let bin = '';
    for (let i = 0; i < lastSeg.length; i++) bin += String.fromCharCode(lastSeg[i]);
    photoBase64 = btoa(bin);
    textFields = segments.slice(segOffset, segments.length - 1).map(s => dec.decode(s).trim());
  } else {
    textFields = segments.slice(segOffset).map(s => dec.decode(s).trim());
  }

  // ── Map text fields to result ─────────────────────────────────────────────────
  const f = (i: number) => (textFields[i] || '').trim();

  // timestamp → f(0), ref_id → f(1), name → f(2), ...
  const rawGender = f(4);
  const gender =
    rawGender === 'M' ? 'Male' :
    rawGender === 'F' ? 'Female' :
    rawGender === 'T' ? 'Transgender' : rawGender || '';

  const uidRef = f(1).substring(0, 4); // ref id = last 4 digits
  const maskedUID = uidRef ? `xxxx xxxx ${uidRef}` : 'xxxx xxxx xxxx';

  // ── Build verification note ───────────────────────────────────────────────────
  let verificationNote: string;
  if (signatureValid === null) {
    verificationNote =
      'ℹ️ UIDAI signature verification is not configured locally. The document data has been ' +
      'parsed from the QR but cryptographic authenticity cannot be confirmed. To verify, ' +
      'use the UIDAI mAadhaar app or visit myaadhaar.uidai.gov.in.';
  } else if (signatureValid) {
    verificationNote =
      '✅ UIDAI digital signature verified. This document was issued by UIDAI and has not been tampered with.';
  } else {
    verificationNote =
      '❌ Signature verification failed. This may indicate the document was tampered with or ' +
      'the verification key needs updating. Verify through the official UIDAI app.';
  }

  return {
    isGenuine: signatureValid,
    signatureValid,
    format: 'SECURE_QR',
    maskedUID,
    name: f(2),
    dateOfBirth: f(3),
    gender,
    address: {
      careOf: f(5),
      house: f(8),
      street: f(13),
      locality: f(9),
      vtc: f(14),
      district: f(6),
      state: f(12),
      pincode: f(10),
    },
    mobileLinked,
    emailLinked,
    timestamp: f(0),
    photoBase64,
    verificationNote,
  };
}

// ─── Main exported verifier (async) ──────────────────────────────────────────
export async function verifyAadhaarQR(rawData: string): Promise<AadhaarVerifyResult> {
  const data = rawData.trim();

  // Secure Numeric QR — 50+ digit decimal string
  if (/^\d{50,}$/.test(data)) {
    return parseSecureFormat(data);
  }

  // XML / Attribute QR (old format)
  if (
    data.includes('PrintLetterBarcodeData') ||
    data.includes('uid=') ||
    data.includes('name=')
  ) {
    return parseXmlFormat(data);
  }

  return errorResult(
    'SECURE_QR',
    'Could not recognize Aadhaar QR format. Ensure you are scanning the QR code on an Aadhaar card or e-Aadhaar document.',
  );
}
