/**
 * SafeMail X — Government Document Verifier Screen
 *
 * Renders after a government document QR is detected in QRScannerScreen.
 * Routes to the correct sub-verifier based on document type.
 * Aadhaar: full cryptographic verification (offline).
 * DigiLocker / CoWIN / DL / CBSE: guided online portal verification.
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  View, Text, ScrollView, TouchableOpacity, StyleSheet,
  Animated, Image, Linking, Platform, ActivityIndicator,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import type { GovDocDetectResult } from '../services/govDocDetector';
import { verifyAadhaarQR, type AadhaarVerifyResult } from '../services/aadhaarVerifier';

// ─── Colors ───────────────────────────────────────────────────────────────────
const C = {
  bg: '#06080f',
  cyan: '#00f3ff',
  green: '#34c759',
  rose: '#ff3d71',
  gold: '#ffaa00',
  violet: '#8c52ff',
  frost: '#e8eaf0',
  muted: 'rgba(255,255,255,0.45)',
};

// ─── Props ────────────────────────────────────────────────────────────────────
interface Props {
  detection: GovDocDetectResult;
  onClose: () => void;
  onScanAnother: () => void;
}

// ─── Small glass card ─────────────────────────────────────────────────────────
function Card({
  children, accent, style,
}: { children: React.ReactNode; accent?: string; style?: any }) {
  return (
    <View style={[styles.card, accent ? { borderLeftColor: accent, borderLeftWidth: 3 } : undefined, style]}>
      {children}
    </View>
  );
}

// ─── Row: label + value ───────────────────────────────────────────────────────
function Row({ label, value, accent }: { label: string; value: string; accent?: string }) {
  if (!value || value.trim() === '') return null;
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={[styles.rowValue, accent ? { color: accent } : undefined]}>{value}</Text>
    </View>
  );
}

// ─── Verification Badge ───────────────────────────────────────────────────────
function VerifyBadge({ valid }: { valid: boolean | null }) {
  if (valid === null) {
    return (
      <View style={[styles.badge, { backgroundColor: 'rgba(255,170,0,0.15)', borderColor: C.gold }]}>
        <Ionicons name="help-circle-outline" size={14} color={C.gold} />
        <Text style={[styles.badgeText, { color: C.gold }]}>CANNOT VERIFY</Text>
      </View>
    );
  }
  const color = valid ? C.green : C.rose;
  return (
    <View style={[styles.badge, { backgroundColor: `${color}18`, borderColor: color }]}>
      <Ionicons name={valid ? 'shield-checkmark' : 'shield-half'} size={14} color={color} />
      <Text style={[styles.badgeText, { color }]}>
        {valid ? 'UIDAI SIGNATURE VERIFIED' : 'SIGNATURE MISMATCH'}
      </Text>
    </View>
  );
}

// ─── Aadhaar Result Card ──────────────────────────────────────────────────────
function AadhaarResultCard({ result }: { result: AadhaarVerifyResult }) {
  const slideIn = useRef(new Animated.Value(30)).current;
  const fadeIn = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn, { toValue: 1, duration: 450, useNativeDriver: true }),
      Animated.spring(slideIn, { toValue: 0, tension: 70, friction: 11, useNativeDriver: true }),
    ]).start();
  }, []);

  const isGenuine = result.isGenuine;
  const headerColor = isGenuine === true ? C.green : isGenuine === false ? C.rose : C.gold;
  const headerIcon = isGenuine === true ? 'shield-checkmark' : isGenuine === false ? 'shield-half' : 'shield-outline';
  const headerTitle = isGenuine === true ? 'Genuine Aadhaar' : isGenuine === false ? 'Verification Failed' : 'Parsed (Unverified)';

  return (
    <Animated.ScrollView
      style={{ opacity: fadeIn, transform: [{ translateY: slideIn }] }}
      contentContainerStyle={{ padding: 20, paddingBottom: 100 }}
      showsVerticalScrollIndicator={false}
    >
      {/* Hero badge */}
      <View style={[styles.heroBadgeContainer, { borderColor: `${headerColor}50` }]}>
        <View style={[styles.heroBadgeIconRing, { borderColor: headerColor, backgroundColor: `${headerColor}18` }]}>
          <Ionicons name={headerIcon as any} size={36} color={headerColor} />
        </View>
        <Text style={[styles.heroTitle, { color: headerColor }]}>{headerTitle}</Text>
        <Text style={styles.heroSub}>Aadhaar QR · {result.format === 'SECURE_QR' ? 'Secure QR' : 'XML QR'}</Text>
        <VerifyBadge valid={result.signatureValid} />
      </View>

      {/* Photo (if extracted from secure QR) */}
      {result.photoBase64 ? (
        <Card accent={headerColor} style={{ marginBottom: 14, alignItems: 'center' }}>
          <Text style={styles.sectionLabel}>Document Photo</Text>
          <Image
            source={{ uri: `data:image/jpeg;base64,${result.photoBase64}` }}
            style={styles.aadhaarPhoto}
            resizeMode="cover"
          />
          <Text style={[styles.photoCaption, { color: result.isGenuine ? C.green : C.gold }]}>
            {result.isGenuine
              ? '✅ Photo extracted from verified UIDAI payload'
              : 'Photo extracted — signature unverified'}
          </Text>
        </Card>
      ) : null}

      {/* Identity details */}
      <Card accent={C.cyan} style={{ marginBottom: 14 }}>
        <Text style={styles.sectionLabel}>Identity Details</Text>
        <Row label="Aadhaar (Masked)" value={result.maskedUID} accent={C.cyan} />
        <Row label="Full Name" value={result.name} />
        <Row label="Date of Birth" value={result.dateOfBirth} />
        <Row label="Gender" value={result.gender} />
      </Card>

      {/* Address */}
      {(result.address.state || result.address.district) ? (
        <Card accent={C.violet} style={{ marginBottom: 14 }}>
          <Text style={styles.sectionLabel}>Registered Address</Text>
          {result.address.careOf ? <Row label="Care Of" value={result.address.careOf} /> : null}
          {result.address.house ? <Row label="House" value={result.address.house} /> : null}
          {result.address.street ? <Row label="Street" value={result.address.street} /> : null}
          {result.address.locality ? <Row label="Locality" value={result.address.locality} /> : null}
          {result.address.vtc ? <Row label="Village / Town" value={result.address.vtc} /> : null}
          {result.address.district ? <Row label="District" value={result.address.district} /> : null}
          {result.address.state ? <Row label="State" value={result.address.state} /> : null}
          {result.address.pincode ? <Row label="PIN Code" value={result.address.pincode} /> : null}
        </Card>
      ) : null}

      {/* Linked accounts */}
      <Card style={{ marginBottom: 14 }}>
        <Text style={styles.sectionLabel}>Linked Accounts</Text>
        <View style={styles.linkedRow}>
          <Ionicons name="call" size={14} color={result.mobileLinked ? C.green : C.rose} />
          <Text style={[styles.linkedText, { color: result.mobileLinked ? C.green : C.rose }]}>
            {result.mobileLinked ? 'Mobile number is linked' : 'No mobile linked'}
          </Text>
        </View>
        <View style={styles.linkedRow}>
          <Ionicons name="mail" size={14} color={result.emailLinked ? C.green : C.gold} />
          <Text style={[styles.linkedText, { color: result.emailLinked ? C.green : C.gold }]}>
            {result.emailLinked ? 'Email is linked' : 'No email linked'}
          </Text>
        </View>
      </Card>

      {/* Verification note */}
      <Card
        accent={result.signatureValid === true ? C.green : result.signatureValid === false ? C.rose : C.gold}
        style={{ marginBottom: 14 }}
      >
        <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 8 }}>
          <Ionicons name="information-circle" size={15} color={C.cyan} style={{ marginRight: 6 }} />
          <Text style={styles.sectionLabel}>Verification Note</Text>
        </View>
        <Text style={styles.noteText}>{result.verificationNote}</Text>
      </Card>

      {/* Privacy note */}
      <View style={styles.privacyNote}>
        <Ionicons name="lock-closed" size={12} color="rgba(255,255,255,0.3)" />
        <Text style={styles.privacyText}>
          SafeMail X never stores or transmits Aadhaar data. All verification is done locally on your device.
        </Text>
      </View>
    </Animated.ScrollView>
  );
}

// ─── Generic Government Doc Card (Online Verification) ───────────────────────
interface DocConfig {
  icon: string;
  color: string;
  title: string;
  subtitle: string;
  verifyUrl?: string;
  verifyLabel?: string;
  howTo: string;
  warning?: string;
}

function GenericGovDocCard({
  detection, config,
}: { detection: GovDocDetectResult; config: DocConfig }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeIn, { toValue: 1, duration: 400, useNativeDriver: true }).start();
  }, []);

  const openVerify = () => {
    const url = detection.extractedUrl || config.verifyUrl;
    if (url) Linking.openURL(url);
  };

  return (
    <Animated.ScrollView
      style={{ opacity: fadeIn }}
      contentContainerStyle={{ padding: 20, paddingBottom: 100 }}
      showsVerticalScrollIndicator={false}
    >
      {/* Hero */}
      <View style={[styles.heroBadgeContainer, { borderColor: `${config.color}50` }]}>
        <View style={[styles.heroBadgeIconRing, { borderColor: config.color, backgroundColor: `${config.color}18` }]}>
          <Ionicons name={config.icon as any} size={36} color={config.color} />
        </View>
        <Text style={[styles.heroTitle, { color: config.color }]}>{config.title}</Text>
        <Text style={styles.heroSub}>{config.subtitle}</Text>
        <View style={[styles.badge, { backgroundColor: `${config.color}18`, borderColor: config.color }]}>
          <Ionicons name="globe" size={13} color={config.color} />
          <Text style={[styles.badgeText, { color: config.color }]}>ONLINE VERIFICATION AVAILABLE</Text>
        </View>
      </View>

      {/* QR URL found */}
      {detection.extractedUrl && (
        <Card accent={C.cyan} style={{ marginBottom: 14 }}>
          <Text style={styles.sectionLabel}>Decoded URL</Text>
          <Text style={styles.urlText} numberOfLines={3}>{detection.extractedUrl}</Text>
          <View style={styles.domainCheck}>
            <Ionicons
              name={detection.extractedUrl.includes('.gov.in') || detection.extractedUrl.includes('.nic.in')
                ? 'shield-checkmark' : 'warning'}
              size={13}
              color={detection.extractedUrl.includes('.gov.in') || detection.extractedUrl.includes('.nic.in')
                ? C.green : C.gold}
            />
            <Text style={[styles.domainCheckText, {
              color: detection.extractedUrl.includes('.gov.in') || detection.extractedUrl.includes('.nic.in')
                ? C.green : C.gold,
            }]}>
              {detection.extractedUrl.includes('.gov.in') || detection.extractedUrl.includes('.nic.in')
                ? 'Official Government Domain (.gov.in / .nic.in)'
                : 'Non-official domain — verify carefully before opening'}
            </Text>
          </View>
        </Card>
      )}

      {/* How to verify */}
      <Card accent={C.violet} style={{ marginBottom: 14 }}>
        <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
          <Ionicons name="checkmark-circle" size={15} color={C.violet} style={{ marginRight: 6 }} />
          <Text style={styles.sectionLabel}>How to Verify</Text>
        </View>
        <Text style={styles.noteText}>{config.howTo}</Text>
      </Card>

      {/* Warning if any */}
      {config.warning && (
        <Card accent={C.rose} style={{ marginBottom: 14 }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 8 }}>
            <Ionicons name="warning" size={15} color={C.rose} style={{ marginRight: 6 }} />
            <Text style={[styles.sectionLabel, { color: C.rose }]}>Warning</Text>
          </View>
          <Text style={styles.noteText}>{config.warning}</Text>
        </Card>
      )}

      {/* Verify button */}
      {(detection.extractedUrl || config.verifyUrl) && (
        <TouchableOpacity style={[styles.verifyBtn, { backgroundColor: config.color }]} onPress={openVerify}>
          <Ionicons name="open-outline" size={18} color="#000" style={{ marginRight: 8 }} />
          <Text style={styles.verifyBtnText}>{config.verifyLabel || 'Open Official Verification Portal'}</Text>
        </TouchableOpacity>
      )}
    </Animated.ScrollView>
  );
}

// ─── Doc configs per type ─────────────────────────────────────────────────────
function getDocConfig(detection: GovDocDetectResult): DocConfig {
  switch (detection.type) {
    case 'COWIN_VACCINATION':
      return {
        icon: 'medical',
        color: C.green,
        title: 'Vaccination Certificate',
        subtitle: 'CoWIN · Government of India',
        verifyUrl: 'https://selfregistration.cowin.gov.in/',
        verifyLabel: 'Open CoWIN Portal',
        howTo: 'Open the CoWIN official portal and enter your registered mobile number to view and verify your vaccination certificate. The portal will show the exact vaccines received, dates, and beneficiary name.',
        warning: 'Fraudsters create fake vaccination certificates to bypass verification. Always verify via CoWIN portal, not by looking at the certificate alone.',
      };
    case 'DIGILOCKER_DOC':
      return {
        icon: 'folder-open',
        color: C.cyan,
        title: 'DigiLocker Document',
        subtitle: 'National eGov Division · MeitY',
        verifyUrl: 'https://digilocker.gov.in',
        verifyLabel: 'Open DigiLocker',
        howTo: 'Open DigiLocker and navigate to the shared document. DigiLocker documents are digitally signed by the issuing authority. Click the verification link in the QR to confirm authenticity.',
        warning: 'Scammers have created fake DigiLocker share links. Always confirm the URL begins with digilocker.gov.in before trusting the document.',
      };
    case 'DRIVING_LICENSE':
      return {
        icon: 'car',
        color: C.violet,
        title: 'Driving License',
        subtitle: 'Ministry of Road Transport · mParivahan',
        verifyUrl: 'https://mparivahan.gov.in',
        verifyLabel: 'Verify on mParivahan',
        howTo: 'Open mParivahan app or website. Enter the driving license number shown on the card. The portal will display the holder\'s name, validity, vehicle classes, and issuing RTO. Any mismatch = suspicious.',
        warning: 'Fake driving licenses can be difficult to spot visually. Always verify the DL number on the official mParivahan portal for high-stakes situations.',
      };
    case 'CBSE_CERTIFICATE':
      return {
        icon: 'school',
        color: C.gold,
        title: 'CBSE / Board Certificate',
        subtitle: 'Central Board of Secondary Education',
        verifyUrl: 'https://cbse.gov.in',
        verifyLabel: 'Verify on CBSE Portal',
        howTo: 'Use the CBSE result verification portal with the roll number and year. Alternatively, scan the QR code link which should redirect to an official CBSE or DigiLocker verification page.',
        warning: 'Academic fraud is common in India. Fake marksheets and certificates are used in job applications. Always verify marks with the official board portal before trusting.',
      };
    case 'INCOME_TAX_NOTICE':
      return {
        icon: 'document-text',
        color: C.gold,
        title: 'Income Tax Document',
        subtitle: 'Income Tax Department · Government of India',
        verifyUrl: 'https://incometax.gov.in',
        verifyLabel: 'Open Income Tax Portal',
        howTo: 'Log in to incometax.gov.in with your PAN number to view all official notices. Any genuine IT notice will be available there. Cross-check the notice number shown in the QR.',
        warning: '⚠️ The Income Tax Department NEVER sends QR codes in unofficial documents demanding immediate payment. If this QR came via WhatsApp or email from an unknown sender, it is a scam.',
      };
    case 'COURT_DOCUMENT':
      return {
        icon: 'business',
        color: C.violet,
        title: 'e-Court Judicial Document',
        subtitle: 'National Informatics Centre · eCourts',
        verifyUrl: 'https://services.ecourts.gov.in',
        verifyLabel: 'Verify on eCourts Portal',
        howTo: 'Enter the CNR (Case Number Record) on the eCourts portal to verify the case details. The portal will show the court name, case type, hearing dates, and current status.',
        warning: '⚠️ Scammers send fake court summons with QR codes claiming digital arrest. Real court summons are NEVER delivered via WhatsApp. If you received this from an unknown caller, it is a scam.',
      };
    default:
      return {
        icon: 'shield',
        color: C.cyan,
        title: 'Government Document',
        subtitle: detection.description,
        verifyUrl: detection.extractedUrl,
        verifyLabel: 'Open Official Portal',
        howTo: 'This appears to be a government-issued document. Use the link or document number to verify on the issuing authority\'s official website.',
        warning: detection.extractedUrl && !detection.extractedUrl.includes('.gov.in')
          ? '⚠️ This document links to a non-.gov.in domain. Government documents should always link to official .gov.in portals.'
          : undefined,
      };
  }
}

// ─── Main Screen ──────────────────────────────────────────────────────────────
export default function GovDocVerifierScreen({ detection, onClose, onScanAnother }: Props) {
  const insets = useSafeAreaInsets();
  const [aadhaarResult, setAadhaarResult] = useState<AadhaarVerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const headerFade = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.timing(headerFade, { toValue: 1, duration: 300, useNativeDriver: true }).start();

    // Auto-verify Aadhaar on mount
    if (detection.type === 'AADHAAR_SECURE' || detection.type === 'AADHAAR_XML') {
      setLoading(true);
      // Use setTimeout to yield the JS thread so loading spinner appears
      setTimeout(() => {
        const result = verifyAadhaarQR(detection.rawData);
        setAadhaarResult(result);
        setLoading(false);
      }, 80);
    }
  }, []);

  const isAadhaar = detection.type === 'AADHAAR_SECURE' || detection.type === 'AADHAAR_XML';
  const docConfig = isAadhaar ? null : getDocConfig(detection);

  return (
    <View style={[styles.root, { paddingTop: insets.top }]}>
      {/* Header */}
      <Animated.View style={[styles.header, { opacity: headerFade }]}>
        <TouchableOpacity onPress={onClose} style={styles.backBtn}>
          <Ionicons name="chevron-back" size={20} color="rgba(255,255,255,0.7)" />
          <Text style={styles.backLabel}>Back</Text>
        </TouchableOpacity>
        <View style={styles.headerPill}>
          <Ionicons name="shield-checkmark" size={11} color={C.cyan} />
          <Text style={styles.headerPillText}>GOV DOC VERIFIER</Text>
        </View>
        <View style={{ width: 70 }} />
      </Animated.View>

      {/* Loading */}
      {loading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={C.cyan} />
          <Text style={styles.loadingText}>Verifying document signature...</Text>
          <Text style={styles.loadingSubText}>Checking UIDAI cryptographic proof • Offline</Text>
        </View>
      ) : isAadhaar && aadhaarResult ? (
        <AadhaarResultCard result={aadhaarResult} />
      ) : isAadhaar ? (
        <View style={styles.loadingContainer}>
          <Text style={{ color: C.rose }}>Verification failed. Please try scanning again.</Text>
        </View>
      ) : (
        <GenericGovDocCard detection={detection} config={docConfig!} />
      )}

      {/* Bottom CTA */}
      {!loading && (
        <View style={[styles.bottomBar, { paddingBottom: insets.bottom + 12 }]}>
          <TouchableOpacity style={styles.scanAnotherBtn} onPress={onScanAnother}>
            <Ionicons name="qr-code-outline" size={16} color={C.cyan} style={{ marginRight: 6 }} />
            <Text style={styles.scanAnotherText}>Scan Another Document</Text>
          </TouchableOpacity>
        </View>
      )}
    </View>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: C.bg,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingBottom: 14,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255,255,255,0.07)',
  },
  backBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    width: 70,
  },
  backLabel: {
    color: 'rgba(255,255,255,0.7)',
    fontSize: 15,
    marginLeft: 2,
  },
  headerPill: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(0,243,255,0.1)',
    paddingHorizontal: 14,
    paddingVertical: 6,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(0,243,255,0.3)',
    gap: 6,
  },
  headerPillText: {
    color: C.cyan,
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1.5,
  },
  loadingContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 14,
  },
  loadingText: {
    color: C.frost,
    fontSize: 16,
    fontWeight: '600',
  },
  loadingSubText: {
    color: C.muted,
    fontSize: 12,
    textAlign: 'center',
  },

  // Hero badge
  heroBadgeContainer: {
    alignItems: 'center',
    paddingVertical: 28,
    marginBottom: 20,
    borderRadius: 24,
    borderWidth: 1,
    backgroundColor: 'rgba(255,255,255,0.03)',
    gap: 10,
  },
  heroBadgeIconRing: {
    width: 80,
    height: 80,
    borderRadius: 40,
    borderWidth: 2,
    alignItems: 'center',
    justifyContent: 'center',
  },
  heroTitle: {
    fontSize: 22,
    fontWeight: '800',
    letterSpacing: -0.3,
  },
  heroSub: {
    color: C.muted,
    fontSize: 13,
  },
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingVertical: 5,
    borderRadius: 20,
    borderWidth: 1,
    gap: 5,
    marginTop: 4,
  },
  badgeText: {
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1,
  },

  // Card
  card: {
    backgroundColor: 'rgba(255,255,255,0.05)',
    borderRadius: 18,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.09)',
    padding: 16,
  },
  sectionLabel: {
    color: C.cyan,
    fontSize: 10,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 1.2,
    marginBottom: 10,
  },

  // Row
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 8,
    gap: 12,
  },
  rowLabel: {
    color: 'rgba(255,255,255,0.45)',
    fontSize: 12,
    flex: 1,
  },
  rowValue: {
    color: C.frost,
    fontSize: 13,
    fontWeight: '600',
    flex: 2,
    textAlign: 'right',
  },

  // Photo
  aadhaarPhoto: {
    width: 90,
    height: 90,
    borderRadius: 12,
    marginBottom: 8,
    borderWidth: 2,
    borderColor: 'rgba(0,243,255,0.3)',
  },
  photoCaption: {
    fontSize: 11,
    fontWeight: '600',
    textAlign: 'center',
  },

  // Linked row
  linkedRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 6,
    gap: 8,
  },
  linkedText: {
    fontSize: 13,
    fontWeight: '500',
  },

  // Notes
  noteText: {
    color: 'rgba(255,255,255,0.75)',
    fontSize: 13,
    lineHeight: 20,
  },
  privacyNote: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 6,
    paddingHorizontal: 4,
    marginBottom: 20,
  },
  privacyText: {
    color: 'rgba(255,255,255,0.25)',
    fontSize: 11,
    lineHeight: 16,
    flex: 1,
  },

  // URL display
  urlText: {
    color: 'rgba(255,255,255,0.8)',
    fontSize: 12,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    marginBottom: 10,
  },
  domainCheck: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  domainCheckText: {
    fontSize: 12,
    fontWeight: '600',
  },

  // Verify button
  verifyBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 16,
    borderRadius: 16,
    marginBottom: 12,
  },
  verifyBtnText: {
    color: '#000',
    fontSize: 15,
    fontWeight: '700',
  },

  // Bottom bar
  bottomBar: {
    paddingHorizontal: 20,
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255,255,255,0.07)',
    backgroundColor: C.bg,
  },
  scanAnotherBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(0,243,255,0.08)',
    padding: 14,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: 'rgba(0,243,255,0.2)',
  },
  scanAnotherText: {
    color: C.cyan,
    fontSize: 14,
    fontWeight: '600',
  },
});
