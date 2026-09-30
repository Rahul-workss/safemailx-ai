/**
 * SafeMail X — Government Document QR Detector
 * Classifies QR payloads into specific government document types
 * so the verifier can route to the correct parsing/verification logic.
 */

export type GovDocType =
  | 'AADHAAR_SECURE'      // New numeric-only large integer QR (signed, post-2019)
  | 'AADHAAR_XML'         // Old XML text QR (unsigned, pre-2019)
  | 'COWIN_VACCINATION'   // CoWIN vaccination certificate
  | 'DIGILOCKER_DOC'      // DigiLocker issued document
  | 'DRIVING_LICENSE'     // State DL QR
  | 'CBSE_CERTIFICATE'    // CBSE marksheet / certificate
  | 'PAN_CARD'            // PAN card QR
  | 'PASSPORT'            // Passport MRZ/QR
  | 'VOTER_ID'            // Voter ID card
  | 'INCOME_TAX_NOTICE'   // Income Tax portal notice QR
  | 'COURT_DOCUMENT'      // e-Court document
  | 'PROPERTY_DOCUMENT'   // IGRS / property registration
  | 'GOV_GENERIC'         // Other .gov.in / .nic.in domain
  | 'NOT_GOV_DOC';        // Not a government document

export interface GovDocDetectResult {
  type: GovDocType;
  isGovDoc: boolean;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  rawData: string;
  extractedUrl?: string;
  description: string;
}

// ─── Known official government domains ────────────────────────────────────────
const GOV_DOMAINS = [
  'uidai.gov.in', 'resident.uidai.gov.in',
  'cowin.gov.in', 'selfregistration.cowin.gov.in',
  'digilocker.gov.in', 'api.digitallocker.gov.in',
  'cbse.gov.in', 'cbseresults.nic.in', 'cbse.nic.in',
  'mparivahan.gov.in', 'parivahan.gov.in',
  'incometax.gov.in', 'efiling.incometax.gov.in',
  'ecourts.gov.in', 'services.ecourts.gov.in',
  'igrs.gov.in', 'doris.gov.in', 'registration.gov.in',
  'passportindia.gov.in', 'passport.gov.in',
  'nvsp.in', 'electoralsearch.in',
];

// ─── Detection logic ──────────────────────────────────────────────────────────
export function detectGovDocType(rawData: string): GovDocDetectResult {
  // IMPORTANT: trim() strips trailing newlines, spaces, \r that expo-camera
  // appends and that break regex matching.
  const data = rawData.trim();

  // ── 1. Aadhaar Secure QR ────────────────────────────────────────────────────
  // Post-2019 PVC / e-Aadhaar QR.
  // Format: very large pure-decimal integer (the RSA-signed payload as a big number).
  // Typically 2000–8000 digits. expo-camera returns it as a plain digit string.
  //
  // Detection rules (any one is sufficient):
  //   a) 50+ consecutive digits (main case)
  //   b) Shorter but clearly a large integer (rare edge case)
  //
  // NOTE: threshold is 50 (not 100) because some older Aadhaar PVC cards
  // have shorter payloads, and expo-camera may occasionally truncate.
  // We also tolerate a single leading digit group with possible space splitting
  // from some decoders (handled by stripping spaces before check).
  const digitsOnly = data.replace(/\s/g, ''); // strip any internal whitespace
  if (/^\d{50,}$/.test(digitsOnly)) {
    return {
      type: 'AADHAAR_SECURE',
      isGovDoc: true,
      confidence: digitsOnly.length > 500 ? 'HIGH' : 'MEDIUM',
      // Pass the cleaned (whitespace-stripped) string so the verifier can parse it
      rawData: digitsOnly,
      description: 'Aadhaar Secure QR (digitally signed by UIDAI)',
    };
  }

  // ── 2. Aadhaar XML QR (pre-2019) ────────────────────────────────────────────
  // Older Aadhaar cards have a plain-text XML QR with demographic data.
  // Not cryptographically signed — can only be parsed, not verified.
  if (
    data.includes('PrintLetterBarcodeData') ||
    data.includes('uid=') ||
    (data.includes('<') && data.includes('name=') && data.includes('dob='))
  ) {
    return {
      type: 'AADHAAR_XML',
      isGovDoc: true,
      confidence: 'HIGH',
      rawData: data,
      description: 'Aadhaar Card QR (contains demographic data)',
    };
  }

  // ── 3. CoWIN Vaccination Certificate ────────────────────────────────────────
  if (
    data.toLowerCase().includes('cowin') ||
    data.includes('Co-WIN') ||
    data.toLowerCase().includes('vaccination') ||
    data.toLowerCase().includes('vaccine') ||
    (data.startsWith('http') && data.includes('cowin.gov.in'))
  ) {
    return {
      type: 'COWIN_VACCINATION',
      isGovDoc: true,
      confidence: 'HIGH',
      rawData: data,
      extractedUrl: data.startsWith('http') ? data : undefined,
      description: 'COVID-19 Vaccination Certificate (CoWIN)',
    };
  }

  // ── 4. DigiLocker document ───────────────────────────────────────────────────
  if (
    data.toLowerCase().includes('digilocker') ||
    data.toLowerCase().includes('digitallocker')
  ) {
    return {
      type: 'DIGILOCKER_DOC',
      isGovDoc: true,
      confidence: 'HIGH',
      rawData: data,
      extractedUrl: data.startsWith('http') ? data : undefined,
      description: 'DigiLocker Official Document',
    };
  }

  // ── 5. CBSE / Board Certificates ────────────────────────────────────────────
  if (
    data.toLowerCase().includes('cbse') ||
    data.toLowerCase().includes('cbseresults') ||
    data.includes('CERTIFICATE NO') ||
    data.includes('DigiResult')
  ) {
    return {
      type: 'CBSE_CERTIFICATE',
      isGovDoc: true,
      confidence: 'HIGH',
      rawData: data,
      extractedUrl: data.startsWith('http') ? data : undefined,
      description: 'CBSE / Board Certificate',
    };
  }

  // ── 6. Driving License (mParivahan) ─────────────────────────────────────────
  if (
    data.toLowerCase().includes('mparivahan') ||
    data.toLowerCase().includes('parivahan') ||
    data.includes('DRIVING LICENSE') ||
    data.includes('DL No') ||
    (data.startsWith('http') && data.includes('parivahan.gov.in'))
  ) {
    return {
      type: 'DRIVING_LICENSE',
      isGovDoc: true,
      confidence: 'HIGH',
      rawData: data,
      extractedUrl: data.startsWith('http') ? data : undefined,
      description: 'Driving License (mParivahan)',
    };
  }

  // ── 7. PAN Card ──────────────────────────────────────────────────────────────
  if (
    /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(data) ||
    (data.includes('PAN') && data.includes('Income Tax'))
  ) {
    return {
      type: 'PAN_CARD',
      isGovDoc: true,
      confidence: 'MEDIUM',
      rawData: data,
      description: 'PAN Card',
    };
  }

  // ── 8. Income Tax / e-Filing ─────────────────────────────────────────────────
  if (
    data.includes('incometax.gov.in') ||
    data.toLowerCase().includes('efiling')
  ) {
    return {
      type: 'INCOME_TAX_NOTICE',
      isGovDoc: true,
      confidence: 'HIGH',
      rawData: data,
      extractedUrl: data.startsWith('http') ? data : undefined,
      description: 'Income Tax Department Document',
    };
  }

  // ── 9. e-Court documents ─────────────────────────────────────────────────────
  if (
    data.toLowerCase().includes('ecourts') ||
    data.includes('eCourt') ||
    data.includes('CNR')
  ) {
    return {
      type: 'COURT_DOCUMENT',
      isGovDoc: true,
      confidence: 'HIGH',
      rawData: data,
      extractedUrl: data.startsWith('http') ? data : undefined,
      description: 'e-Court Judicial Document',
    };
  }

  // ── 10. Generic .gov.in / .nic.in URL ───────────────────────────────────────
  if (data.startsWith('http')) {
    try {
      const url = new URL(data);
      const isGovDomain =
        url.hostname.endsWith('.gov.in') ||
        url.hostname.endsWith('.nic.in') ||
        GOV_DOMAINS.some(d => url.hostname === d || url.hostname.endsWith('.' + d));
      if (isGovDomain) {
        return {
          type: 'GOV_GENERIC',
          isGovDoc: true,
          confidence: 'HIGH',
          rawData: data,
          extractedUrl: data,
          description: `Government document (${url.hostname})`,
        };
      }
    } catch {
      // Not a URL
    }
  }

  return {
    type: 'NOT_GOV_DOC',
    isGovDoc: false,
    confidence: 'HIGH',
    rawData: data,
    description: 'Not a government document QR',
  };
}
