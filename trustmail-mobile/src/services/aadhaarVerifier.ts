/**
 * SafeMail X — Aadhaar QR Verifier (Backend-powered)
 *
 * The Aadhaar Secure QR decoding is done server-side via the
 * POST /api/instant/aadhaar endpoint, which uses Python's stdlib
 * zlib (gzip mode) + ISO-8859-1 — the same algorithm as pyaadhaar.
 *
 * Why backend?
 *   - Python's native int handles 6000+ digit decimals in microseconds.
 *     A JS pure-string division loop for the same number takes 30–60 seconds
 *     on mobile hardware (O(n²) in digit count).
 *   - pako.ungzip() in Hermes/React Native has shown inconsistent results
 *     with UIDAI's specific gzip variant.
 *   - The Python implementation is identical to the proven pyaadhaar library.
 *
 * Privacy:
 *   The backend endpoint logs nothing and stores nothing. It computes
 *   the result in-memory and returns it immediately.
 *   All verification stays local — we do NOT send data to UIDAI or
 *   any third party. Only the user's own Render backend is called.
 */

import { decodeAadhaarQR } from '../api';


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

// ─── Old XML QR parser (pure local, pre-2019 format) ─────────────────────────
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
      'This is an older Aadhaar QR format (pre-2019). It contains demographic data ' +
      'but has no digital signature — tamper detection is not possible. ' +
      'Download a fresh e-Aadhaar from myaadhaar.uidai.gov.in for cryptographic verification.',
  };
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


// ─── Backend Aadhaar decode (Secure Numeric QR, post-2019) ───────────────────
async function decodeViaBackend(decimal: string): Promise<AadhaarVerifyResult> {
  let json: any;
  try {
    json = await decodeAadhaarQR(decimal);
  } catch (e: any) {
    const msg = e?.message || 'Unknown error';
    return errorResult(
      'SECURE_QR',
      msg.includes('HTTP 401')
        ? 'Please log in to use the Aadhaar verifier.'
        : `Could not reach the verification server. ${msg}`,
    );
  }

  if (!json || !json.success) {
    return errorResult('SECURE_QR', json?.error || 'Decode failed on server.');
  }

  const addr = json.address || {};
  const uid4 = (json.uid_last4 || '').trim();
  const maskedUID = uid4 ? `xxxx xxxx ${uid4}` : 'xxxx xxxx xxxx';

  const signatureValid = json.signature_valid;
  let verificationNote: string;
  if (signatureValid === true) {
    verificationNote =
      '✅ UIDAI digital signature verified. The data in this QR code has been cryptographically confirmed ' +
      'as authentic and unaltered using the official UIDAI RSA-2048 public key. This Aadhaar card is genuine.';
  } else if (signatureValid === false) {
    verificationNote =
      '🚨 UIDAI signature verification FAILED. The QR data does not match the UIDAI cryptographic signature. ' +
      'This card may be tampered, forged, or damaged. Do NOT accept this document for any official purpose. ' +
      'Report suspected fraud at cybercrime.gov.in or call 1930.';
  } else {
    verificationNote =
      '⚠️ Signature could not be verified. This typically means UIDAI has rotated their signing certificate ' +
      'since the last public key update in our system. The data was extracted from the QR, but authenticity ' +
      'cannot be confirmed. Verify using the official mAadhaar app or myaadhaar.uidai.gov.in.';
  }

  return {
    isGenuine: json.signature_valid ?? null,
    signatureValid: json.signature_valid ?? null,
    format: 'SECURE_QR',
    maskedUID,
    name: json.name || '',
    dateOfBirth: json.dob || '',
    gender: json.gender || '',
    address: {
      careOf: addr.careOf || '',
      house: addr.house || '',
      street: addr.street || '',
      locality: addr.locality || '',
      vtc: addr.vtc || '',
      district: addr.district || '',
      state: addr.state || '',
      pincode: addr.pincode || '',
    },
    mobileLinked: !!json.mobile_linked,
    emailLinked: !!json.email_linked,
    timestamp: '',
    photoBase64: json.photo_base64 || undefined,
    verificationNote,
  };
}

// ─── Main export ──────────────────────────────────────────────────────────────
export async function verifyAadhaarQR(rawData: string): Promise<AadhaarVerifyResult> {
  const data = rawData.trim();

  // Secure Numeric QR — 50+ digit decimal string → backend decode
  if (/^\d{50,}$/.test(data)) {
    return decodeViaBackend(data);
  }

  // Old XML QR — local parse only
  if (
    data.includes('PrintLetterBarcodeData') ||
    data.includes('uid=') ||
    data.includes('name=')
  ) {
    return parseXmlFormat(data);
  }

  return errorResult(
    'SECURE_QR',
    'Could not recognize the Aadhaar QR format. ' +
    'Ensure you are scanning the QR on an Aadhaar card or e-Aadhaar document.',
  );
}
