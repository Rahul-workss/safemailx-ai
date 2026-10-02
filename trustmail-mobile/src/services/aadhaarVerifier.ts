/**
 * SafeMail X — Aadhaar QR Verifier Service
 *
 * Based on reverse-engineering of pyaadhaar (tanmoysrt/pyaadhaar) and
 * UIDAI QR Code User Manual v3 (2019).
 *
 * Secure QR format (post-2019 PVC / e-Aadhaar):
 *   1. Data is a BASE-10 encoded big integer (decimal string from QR scanner)
 *   2. Convert to bytes: big-endian, strip leading zeros
 *   3. Decompress with GZIP (wbits = 16+15, i.e. zlib.decompress(data, 16+MAX_WBITS))
 *      — NOT plain zlib inflate, NOT raw deflate — strictly GZIP.
 *   4. Result: binary stream, fields delimited by byte 0xFF (decimal 255)
 *   5. Decode each field as ISO-8859-1 (Latin-1), NOT UTF-8
 *   6. Last 256 bytes of the ORIGINAL byte array = RSA-SHA256 signature
 *      (signature is over the bytes BEFORE decompression, minus the sig itself)
 *
 * Field order (0-indexed, 0xFF delimited):
 *   [0]  email_mobile_status  — single digit: "0"=none, "1"=email, "2"=mobile, "3"=both
 *   [1]  referenceid          — first 4 chars = last 4 digits of Aadhaar
 *   [2]  name
 *   [3]  dob                  — DD-MM-YYYY or YYYY
 *   [4]  gender               — M / F / T
 *   [5]  careof               — care of (c/o)
 *   [6]  district
 *   [7]  landmark
 *   [8]  house
 *   [9]  location             — locality
 *   [10] pincode
 *   [11] postoffice
 *   [12] state
 *   [13] street
 *   [14] subdistrict
 *   [15] vtc                  — village / town / city
 *   (Optional Vx version formats may have version field at [0] and mobile last-4 at end)
 *   Photo: after the last text field, extracted as JPEG-2000 or JPEG binary
 *
 * References:
 *   https://github.com/tanmoysrt/pyaadhaar
 *   https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf
 */

import pako from 'pako';

// ─── Types ────────────────────────────────────────────────────────────────────
export interface AadhaarVerifyResult {
  isGenuine: boolean | null;     // true=sig verified, false=mismatch, null=cannot verify
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

// ─── UIDAI key config ─────────────────────────────────────────────────────────
// Set true and replace key bytes when you have the real UIDAI production key.
// From: https://resident.uidai.gov.in/offline-kyc (Offline eKYC SDK)
const UIDAI_KEY_CONFIGURED = false;
const UIDAI_PUBLIC_KEY_B64 = ''; // Replace with actual SPKI-DER base64 key

// ─── Decimal String → Uint8Array (no BigInt, pure JS string division) ─────────
// Converts an arbitrarily large base-10 string to a big-endian byte array.
// Equivalent to Python's: int(s).to_bytes(5000, 'big').lstrip(b'\x00')
function decimalToBytes(decimal: string): Uint8Array {
  const bytes: number[] = [];
  let num = decimal.replace(/^0+/, '') || '0';
  while (num !== '0') {
    let rem = 0;
    let quot = '';
    for (const ch of num) {
      rem = rem * 10 + parseInt(ch, 10);
      const q = Math.floor(rem / 256);
      rem %= 256;
      if (quot !== '' || q > 0) quot += q;
    }
    bytes.unshift(rem);
    num = quot === '' ? '0' : quot;
  }
  return new Uint8Array(bytes);
}

// ─── GZIP decompress via pako ─────────────────────────────────────────────────
// CRITICAL: Aadhaar Secure QR uses GZIP, not raw zlib/deflate.
// Python equivalent: zlib.decompress(data, 16 + zlib.MAX_WBITS)
// pako.ungzip() is the correct equivalent.
function gzipDecompress(data: Uint8Array): Uint8Array {
  // pako.ungzip handles wbits=16+MAX_WBITS (gzip format)
  return pako.ungzip(data);
}

// ─── Split byte array by delimiter value ─────────────────────────────────────
function splitByByte(data: Uint8Array, delim: number): Uint8Array[] {
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

// ─── Decode bytes as ISO-8859-1 (Latin-1) ────────────────────────────────────
// CRITICAL: Aadhaar fields are encoded as Latin-1 (ISO-8859-1), NOT UTF-8.
// Using UTF-8 on Latin-1 bytes causes the garbled output we were seeing.
function decodeLatin1(bytes: Uint8Array): string {
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}

// ─── RSA-SHA256 via WebCrypto (Hermes built-in) ───────────────────────────────
async function verifyRSASignature(
  dataBytes: Uint8Array,
  sigBytes: Uint8Array,
): Promise<boolean | null> {
  if (!UIDAI_KEY_CONFIGURED || !UIDAI_PUBLIC_KEY_B64) return null;
  try {
    const keyBin = Uint8Array.from(atob(UIDAI_PUBLIC_KEY_B64), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      'spki',
      keyBin.buffer.slice(0) as ArrayBuffer,
      { name: 'RSASSA-PKCS1-v1.5', hash: { name: 'SHA-256' } },
      false, ['verify'],
    );
    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1.5', key,
      sigBytes.buffer.slice(0) as ArrayBuffer,
      dataBytes.buffer.slice(0) as ArrayBuffer,
    );
  } catch {
    return null;
  }
}

// ─── Error result helper ──────────────────────────────────────────────────────
function errorResult(format: 'SECURE_QR' | 'XML_QR', msg: string): AadhaarVerifyResult {
  return {
    isGenuine: null, signatureValid: null, format,
    maskedUID: 'xxxx xxxx xxxx', name: '', dateOfBirth: '', gender: '',
    address: { careOf: '', house: '', street: '', locality: '', vtc: '', district: '', state: '', pincode: '' },
    mobileLinked: false, emailLinked: false, timestamp: '',
    verificationNote: msg, error: msg,
  };
}

// ─── Format A: Old XML QR (pre-2019, no signature) ───────────────────────────
function parseXmlFormat(data: string): AadhaarVerifyResult {
  const attr = (name: string): string => {
    const m = data.match(new RegExp(`${name}="([^"]*)"`, 'i'));
    return m ? m[1] : '';
  };
  const uid = attr('uid') || attr('UID') || '';
  const maskedUID = uid
    ? uid.replace(/\d(?=\d{4})/g, 'x').replace(/(.{4})/g, '$1 ').trim()
    : 'xxxx xxxx xxxx';
  const rawGender = attr('gender');
  const gender = rawGender === 'M' ? 'Male' : rawGender === 'F' ? 'Female' : rawGender || '';
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
      'This is an older Aadhaar QR format (pre-2019). It contains demographic data but ' +
      'no digital signature, so tamper-detection is not possible. For cryptographic ' +
      'verification, use a fresh e-Aadhaar downloaded from myaadhaar.uidai.gov.in.',
  };
}

// ─── Format B: Secure Numeric QR (post-2019) ─────────────────────────────────
async function parseSecureFormat(decimal: string): Promise<AadhaarVerifyResult> {
  // Step 1: Decimal string → bytes
  let bytes: Uint8Array;
  try {
    bytes = decimalToBytes(decimal);
  } catch (e) {
    return errorResult('SECURE_QR', 'Could not decode QR payload: ' + String(e));
  }
  if (bytes.length < 260) {
    return errorResult('SECURE_QR', 'QR data too short to be Aadhaar Secure QR.');
  }

  // Step 2: Last 256 bytes = RSA-SHA256 signature
  const sigBytes = bytes.slice(bytes.length - 256);
  const dataBytes = bytes.slice(0, bytes.length - 256);

  // Step 3: Signature verification (null if key not configured)
  const signatureValid = await verifyRSASignature(dataBytes, sigBytes);

  // Step 4: GZIP decompress (NOT zlib/inflate — must use ungzip)
  let decompressed: Uint8Array;
  try {
    decompressed = gzipDecompress(dataBytes);
  } catch (e1) {
    // Fallback 1: try plain zlib inflate
    try {
      decompressed = pako.inflate(dataBytes);
    } catch {
      // Fallback 2: try raw deflate
      try {
        decompressed = pako.inflateRaw(dataBytes);
      } catch {
        return {
          isGenuine: signatureValid, signatureValid, format: 'SECURE_QR',
          maskedUID: 'xxxx xxxx xxxx', name: '', dateOfBirth: '', gender: '',
          address: { careOf: '', house: '', street: '', locality: '', vtc: '', district: '', state: '', pincode: '' },
          mobileLinked: false, emailLinked: false, timestamp: '',
          verificationNote:
            'Signature checked. Could not decompress the data payload. ' +
            'The QR may use an unsupported compression format.',
        };
      }
    }
  }

  // Step 5: Split by 0xFF delimiter, decode each field as ISO-8859-1
  const segments = splitByByte(decompressed, 0xFF);

  // Step 6: Detect Vx version marker (newer format extension)
  // If decompressed starts with "V" + digit (e.g. "V3"), it has an extra version field
  // and an extra last-4-digits-of-mobile field at the end.
  let fieldOffset = 0;
  const firstTwoBytes = decodeLatin1(segments[0]?.slice(0, 2) || new Uint8Array());
  const hasVersionMarker = firstTwoBytes.length >= 2 &&
    firstTwoBytes[0] === 'V' && /\d/.test(firstTwoBytes[1]);
  if (hasVersionMarker) {
    fieldOffset = 1; // skip version field at [0], mobile-last4 is at the end
  }

  // Step 7: Extract photo — last segment that starts with JPEG or JPEG-2000 magic bytes
  let photoBase64: string | undefined;
  let textSegments = [...segments];

  const lastSeg = textSegments[textSegments.length - 1];
  // JPEG: 0xFF 0xD8  |  JPEG-2000: 0x00 0x00 0x00 0x0C 0x6A 0x50
  if (lastSeg && lastSeg.length > 100 &&
    ((lastSeg[0] === 0xFF && lastSeg[1] === 0xD8) ||
     (lastSeg[0] === 0x00 && lastSeg[1] === 0x00 && lastSeg[3] === 0x0C))) {
    let bin = '';
    for (let i = 0; i < lastSeg.length; i++) bin += String.fromCharCode(lastSeg[i]);
    photoBase64 = btoa(bin);
    textSegments = textSegments.slice(0, textSegments.length - 1);
  }

  // Step 8: Decode text fields as ISO-8859-1
  const fields = textSegments.map(s => decodeLatin1(s).trim());

  // Step 9: Map fields per UIDAI spec
  // Without Vx marker:
  //   [0]=email_mobile_status [1]=referenceid [2]=name [3]=dob [4]=gender
  //   [5]=careof [6]=district [7]=landmark [8]=house [9]=location
  //   [10]=pincode [11]=postoffice [12]=state [13]=street [14]=subdistrict [15]=vtc
  // With Vx marker (fieldOffset=1):
  //   [0]=version [1]=email_mobile_status [2]=referenceid [3]=name ...
  const f = (i: number) => (fields[fieldOffset + i] || '').trim();

  // email_mobile_status: "0"=none, "1"=email only, "2"=mobile only, "3"=both
  const emailMobileStatus = parseInt(f(0) || '0', 10);
  const emailLinked = emailMobileStatus === 1 || emailMobileStatus === 3;
  const mobileLinked = emailMobileStatus === 2 || emailMobileStatus === 3;

  // Reference ID: first 4 chars = last 4 digits of Aadhaar number
  const refId = f(1);
  const last4 = refId.substring(0, 4);
  const maskedUID = last4 ? `xxxx xxxx ${last4}` : 'xxxx xxxx xxxx';

  // Gender normalisation
  const rawGender = f(4);
  const gender =
    rawGender === 'M' ? 'Male' :
    rawGender === 'F' ? 'Female' :
    rawGender === 'T' ? 'Transgender' : rawGender;

  // Verification note
  let verificationNote: string;
  if (signatureValid === null) {
    verificationNote =
      'ℹ️ UIDAI digital signature could not be verified (verification key not configured). ' +
      'Demographic data has been parsed from the QR. To verify authenticity, use the official ' +
      'UIDAI mAadhaar app or visit myaadhaar.uidai.gov.in.';
  } else if (signatureValid) {
    verificationNote =
      '✅ UIDAI digital signature verified. This document was issued by UIDAI and has not been tampered with.';
  } else {
    verificationNote =
      '❌ Signature verification failed. This may indicate tampering. ' +
      'Verify through the official UIDAI mAadhaar app.';
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
      district: f(6),
      house: f(8),
      locality: f(9),
      pincode: f(10),
      state: f(12),
      street: f(13),
      vtc: f(15),
    },
    mobileLinked,
    emailLinked,
    timestamp: '',
    photoBase64,
    verificationNote,
  };
}

// ─── Main export ──────────────────────────────────────────────────────────────
export async function verifyAadhaarQR(rawData: string): Promise<AadhaarVerifyResult> {
  const data = rawData.trim();

  // Secure Numeric QR: 50+ digit decimal string
  if (/^\d{50,}$/.test(data)) {
    return parseSecureFormat(data);
  }

  // Old XML QR
  if (
    data.includes('PrintLetterBarcodeData') ||
    data.includes('uid=') ||
    data.includes('name=')
  ) {
    return parseXmlFormat(data);
  }

  return errorResult(
    'SECURE_QR',
    'Could not recognize the Aadhaar QR format. Ensure you are scanning the QR on an Aadhaar card or e-Aadhaar document.',
  );
}
