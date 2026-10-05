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
  Dimensions,
} from 'react-native';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import type { GovDocDetectResult } from '../services/govDocDetector';
import { verifyAadhaarQR, type AadhaarVerifyResult } from '../services/aadhaarVerifier';

const { width: SW } = Dimensions.get('window');

// ─── Colors ───────────────────────────────────────────────────────────────────
const C = {
  bg: '#060a1a',
  cardBg: 'rgba(8,16,50,0.75)',
  cardBorder: 'rgba(40,80,180,0.25)',
  cyan: '#00d4ff',
  cyanDim: 'rgba(0,212,255,0.15)',
  green: '#34c759',
  rose: '#ff3d71',
  gold: '#ffaa00',
  goldDim: 'rgba(255,170,0,0.15)',
  violet: '#8c52ff',
  frost: '#e8eaf6',
  muted: 'rgba(255,255,255,0.45)',
  rowIcon: 'rgba(100,160,255,0.75)',
};

// ─── Props ────────────────────────────────────────────────────────────────────
interface Props {
  detection: GovDocDetectResult;
  onClose: () => void;
  onScanAnother: () => void;
}

// ─── Glass Card wrapper ───────────────────────────────────────────────────────
function GlassCard({
  children, style, accentColor,
}: { children: React.ReactNode; style?: any; accentColor?: string }) {
  return (
    <View style={[styles.glassCard, accentColor ? { borderLeftColor: accentColor, borderLeftWidth: 2.5 } : undefined, style]}>
      {children}
    </View>
  );
}

// ─── Section Header (icon + label) ────────────────────────────────────────────
function SectionHeader({ icon, label, color }: { icon: keyof typeof Ionicons.glyphMap; label: string; color?: string }) {
  return (
    <View style={styles.sectionHeader}>
      <View style={[styles.sectionIconRing, { borderColor: color || C.cyan, backgroundColor: `${color || C.cyan}18` }]}>
        <Ionicons name={icon} size={14} color={color || C.cyan} />
      </View>
      <Text style={[styles.sectionLabel, { color: color || C.cyan }]}>{label}</Text>
    </View>
  );
}

// ─── Icon Row (icon + label + value) ─────────────────────────────────────────
function IconRow({
  icon, label, value, valueColor, rightElement,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  value?: string;
  valueColor?: string;
  rightElement?: React.ReactNode;
}) {
  if (!value && !rightElement) return null;
  return (
    <View style={styles.iconRow}>
      <Ionicons name={icon} size={14} color={C.rowIcon} style={styles.iconRowIcon} />
      <Text style={styles.iconRowLabel}>{label}</Text>
      {rightElement ? (
        rightElement
      ) : (
        <Text style={[styles.iconRowValue, valueColor ? { color: valueColor } : undefined]} numberOfLines={2}>
          {value}
        </Text>
      )}
    </View>
  );
}

// ─── Verification Result Banner (horizontal split) ────────────────────────────
function VerificationResultBanner({ result }: { result: AadhaarVerifyResult }) {
  const slideIn = useRef(new Animated.Value(-20)).current;
  const fadeIn = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn, { toValue: 1, duration: 500, useNativeDriver: true }),
      Animated.spring(slideIn, { toValue: 0, tension: 80, friction: 10, useNativeDriver: true }),
    ]).start();
  }, []);

  const sig = result.signatureValid;
  const accentColor = sig === true ? C.green : sig === false ? C.rose : C.gold;
  const iconName: keyof typeof Ionicons.glyphMap =
    sig === true ? 'shield-checkmark' : sig === false ? 'shield-half' : 'shield-outline';
  const statusLabel =
    sig === true ? 'SIGNATURE VALID' : sig === false ? 'SIGNATURE INVALID' : 'SIGNATURE UNVERIFIABLE';
  const statusSub =
    sig === true
      ? 'UIDAI cryptographic signature verified.'
      : sig === false
      ? 'Signature mismatch — possible forgery.'
      : 'Document processed, but signature\ncould not be verified.';

  return (
    <Animated.View style={{ opacity: fadeIn, transform: [{ translateY: slideIn }], marginBottom: 14 }}>
      <LinearGradient
        colors={['rgba(10,18,55,0.95)', 'rgba(5,10,35,0.98)']}
        style={[styles.banner, { borderColor: `${accentColor}40` }]}
      >
        {/* Glowing wave decoration */}
        <LinearGradient
          colors={[`${accentColor}00`, `${accentColor}18`, `${accentColor}00`]}
          start={{ x: 0, y: 0.5 }}
          end={{ x: 1, y: 0.5 }}
          style={styles.bannerWave}
          pointerEvents="none"
        />

        {/* Left column */}
        <View style={styles.bannerLeft}>
          <Text style={styles.bannerEyebrow}>VERIFICATION RESULT</Text>

          <View style={[styles.bannerIconRing, { borderColor: accentColor, backgroundColor: `${accentColor}20` }]}>
            <Ionicons name={iconName} size={22} color={accentColor} />
          </View>

          {result.name ? (
            <Text style={styles.bannerName} numberOfLines={1}>{result.name}</Text>
          ) : null}

          <Text style={[styles.bannerStatus, { color: accentColor }]}>{statusLabel}</Text>
          <Text style={styles.bannerSub}>{statusSub}</Text>
        </View>

        {/* Right column — decorative doc illustration */}
        <View style={styles.bannerRight} pointerEvents="none">
          <View style={styles.docIllustration}>
            <Ionicons name="document-text" size={44} color="rgba(100,140,255,0.35)" />
            {/* Warning/check badge overlay */}
            <View style={[styles.docBadge, { backgroundColor: accentColor }]}>
              <Ionicons
                name={sig === true ? 'checkmark' : sig === false ? 'close' : 'warning'}
                size={10}
                color="#000"
              />
            </View>
          </View>
        </View>
      </LinearGradient>
    </Animated.View>
  );
}

// ─── Document Preview Card ────────────────────────────────────────────────────
function DocumentPreviewCard({ result }: { result: AadhaarVerifyResult }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeIn, { toValue: 1, duration: 450, delay: 100, useNativeDriver: true }).start();
  }, []);

  return (
    <Animated.View style={{ opacity: fadeIn, marginBottom: 12 }}>
      <GlassCard>
        {/* Card header */}
        <View style={styles.previewHeader}>
          <SectionHeader icon="document-outline" label="DOCUMENT PREVIEW" />
          <Ionicons name="scan-outline" size={16} color={C.muted} />
        </View>

        <View style={styles.previewBody}>
          {/* Aadhaar card mockup */}
          <View style={styles.aadhaarMockupContainer}>
            <LinearGradient
              colors={['rgba(20,30,80,0.9)', 'rgba(10,20,60,0.95)']}
              style={styles.aadhaarMockup}
            >
              {/* Tricolor stripe at top */}
              <View style={styles.tricolorStripe}>
                <View style={[styles.tricolorBand, { backgroundColor: '#FF8C00' }]} />
                <View style={[styles.tricolorBand, { backgroundColor: '#FFFFFF' }]} />
                <View style={[styles.tricolorBand, { backgroundColor: '#138808' }]} />
              </View>

              {/* Person silhouette + blurred details */}
              <View style={styles.aadhaarMockupBody}>
                {result.photoBase64 ? (
                  <Image
                    source={{ uri: `data:image/jpeg;base64,${result.photoBase64}` }}
                    style={styles.aadhaarMockupPhoto}
                    resizeMode="cover"
                    blurRadius={8}
                  />
                ) : (
                  <View style={styles.aadhaarMockupPhotoPlaceholder}>
                    <Ionicons name="person" size={24} color="rgba(255,255,255,0.25)" />
                  </View>
                )}
                <View style={styles.aadhaarMockupLines}>
                  <View style={styles.shimmerLine} />
                  <View style={[styles.shimmerLine, { width: '60%' }]} />
                  <View style={[styles.shimmerLine, { width: '80%', marginTop: 8 }]} />
                  <View style={[styles.shimmerLine, { width: '70%' }]} />
                </View>
              </View>

              {/* Search button */}
              <TouchableOpacity style={styles.zoomBtn} activeOpacity={0.7}>
                <Ionicons name="search-outline" size={14} color={C.frost} />
              </TouchableOpacity>
            </LinearGradient>
          </View>

          {/* Extracted photo */}
          {result.photoBase64 ? (
            <View style={styles.extractedPhotoBox}>
              <Text style={styles.extractedPhotoLabel}>EXTRACTED{'\n'}PHOTO</Text>
              <Image
                source={{ uri: `data:image/jpeg;base64,${result.photoBase64}` }}
                style={styles.extractedPhoto}
                resizeMode="cover"
              />
            </View>
          ) : (
            <View style={styles.extractedPhotoBox}>
              <Text style={styles.extractedPhotoLabel}>EXTRACTED{'\n'}PHOTO</Text>
              <View style={styles.extractedPhotoPlaceholder}>
                <Ionicons name="person-outline" size={26} color={C.muted} />
              </View>
            </View>
          )}
        </View>
      </GlassCard>
    </Animated.View>
  );
}

// ─── Identity Details Card ─────────────────────────────────────────────────────
function IdentityDetailsCard({ result }: { result: AadhaarVerifyResult }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeIn, { toValue: 1, duration: 450, delay: 150, useNativeDriver: true }).start();
  }, []);

  return (
    <Animated.View style={{ opacity: fadeIn, marginBottom: 12 }}>
      <GlassCard>
        <SectionHeader icon="person-circle-outline" label="IDENTITY DETAILS" />
        <IconRow icon="reader-outline" label="Document Type" value="Aadhaar Card" valueColor={C.cyan} />
        <IconRow icon="grid-outline" label="Document Number" value={result.maskedUID || 'xxxx xxxx xxxx'} valueColor="rgba(255,255,255,0.9)" />
        <IconRow icon="calendar-outline" label="Date of Birth" value={result.dateOfBirth} />
        <IconRow icon="person-outline" label="Gender" value={result.gender} />
      </GlassCard>
    </Animated.View>
  );
}

// ─── Registered Address Card ──────────────────────────────────────────────────
function RegisteredAddressCard({ result }: { result: AadhaarVerifyResult }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeIn, { toValue: 1, duration: 450, delay: 200, useNativeDriver: true }).start();
  }, []);

  const addr = result.address;
  const hasAddress = addr.state || addr.district || addr.locality || addr.vtc || addr.pincode;
  if (!hasAddress) return null;

  return (
    <Animated.View style={{ opacity: fadeIn, marginBottom: 12 }}>
      <GlassCard style={{ overflow: 'hidden' }}>
        {/* Decorative location pin background */}
        <View style={styles.decorativePinContainer} pointerEvents="none">
          <Ionicons name="location" size={90} color="rgba(0,160,255,0.07)" />
        </View>

        <SectionHeader icon="location-outline" label="REGISTERED ADDRESS" color="#4da6ff" />

        {addr.careOf ? <IconRow icon="eye-outline" label="Care Of" value={addr.careOf} /> : null}
        {addr.house ? <IconRow icon="home-outline" label="House" value={addr.house} /> : null}
        {addr.street ? <IconRow icon="navigate-outline" label="Street" value={addr.street} /> : null}
        {addr.locality ? <IconRow icon="person-outline" label="Locality" value={addr.locality} /> : null}
        {addr.vtc ? <IconRow icon="business-outline" label="Village/Town" value={addr.vtc} /> : null}
        {addr.district ? <IconRow icon="map-outline" label="District" value={addr.district} /> : null}
        {addr.state ? <IconRow icon="flag-outline" label="State" value={addr.state} /> : null}
        {addr.pincode ? <IconRow icon="people-outline" label="PIN Code" value={addr.pincode} /> : null}
      </GlassCard>
    </Animated.View>
  );
}

// ─── Linked Accounts Card ─────────────────────────────────────────────────────
function LinkedAccountsCard({ result }: { result: AadhaarVerifyResult }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeIn, { toValue: 1, duration: 450, delay: 250, useNativeDriver: true }).start();
  }, []);

  return (
    <Animated.View style={{ opacity: fadeIn, marginBottom: 12 }}>
      <GlassCard>
        <SectionHeader icon="link-outline" label="LINKED ACCOUNTS" />
        <IconRow
          icon="call-outline"
          label="Mobile number is linked"
          rightElement={
            <Ionicons
              name={result.mobileLinked ? 'checkmark-circle' : 'close-circle'}
              size={20}
              color={result.mobileLinked ? C.green : C.rose}
            />
          }
        />
        <IconRow
          icon="mail-outline"
          label="Email is linked"
          rightElement={
            <Ionicons
              name={result.emailLinked ? 'checkmark-circle' : 'close-circle'}
              size={20}
              color={result.emailLinked ? C.green : C.rose}
            />
          }
        />
      </GlassCard>
    </Animated.View>
  );
}

// ─── Verification Note Card ───────────────────────────────────────────────────
function VerificationNoteCard({ result }: { result: AadhaarVerifyResult }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeIn, { toValue: 1, duration: 450, delay: 300, useNativeDriver: true }).start();
  }, []);

  const sig = result.signatureValid;
  const accentColor = sig === true ? C.green : sig === false ? C.rose : C.gold;

  return (
    <Animated.View style={{ opacity: fadeIn, marginBottom: 14 }}>
      <GlassCard accentColor={accentColor}>
        <View style={styles.noteCardHeader}>
          <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8, flex: 1 }}>
            <View style={[styles.noteIconRing, { borderColor: accentColor, backgroundColor: `${accentColor}20` }]}>
              <Ionicons name="alert-circle-outline" size={14} color={accentColor} />
            </View>
            <Text style={[styles.sectionLabel, { color: accentColor }]}>VERIFICATION NOTE</Text>
          </View>
          <Ionicons name="chevron-forward" size={16} color={C.muted} />
        </View>
        <Text style={styles.noteText} numberOfLines={4}>{result.verificationNote}</Text>
      </GlassCard>
    </Animated.View>
  );
}

// ─── Aadhaar Result Card ──────────────────────────────────────────────────────
function AadhaarResultCard({ result, onScanAnother }: { result: AadhaarVerifyResult; onScanAnother: () => void }) {
  return (
    <ScrollView
      style={{ flex: 1 }}
      contentContainerStyle={styles.scrollContent}
      showsVerticalScrollIndicator={false}
    >
      <VerificationResultBanner result={result} />
      <DocumentPreviewCard result={result} />
      <IdentityDetailsCard result={result} />
      <RegisteredAddressCard result={result} />
      <LinkedAccountsCard result={result} />
      <VerificationNoteCard result={result} />

      {/* Privacy note */}
      <View style={styles.privacyNote}>
        <Ionicons name="lock-closed" size={11} color="rgba(255,255,255,0.25)" />
        <Text style={styles.privacyText}>
          SafeMail X never stores or transmits Aadhaar data. All verification is done locally on your device.
        </Text>
      </View>
    </ScrollView>
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
      contentContainerStyle={styles.scrollContent}
      showsVerticalScrollIndicator={false}
    >
      {/* Hero */}
      <LinearGradient
        colors={['rgba(10,18,55,0.95)', 'rgba(5,10,35,0.98)']}
        style={[styles.genericHero, { borderColor: `${config.color}40` }]}
      >
        <View style={[styles.genericHeroIconRing, { borderColor: config.color, backgroundColor: `${config.color}18` }]}>
          <Ionicons name={config.icon as any} size={36} color={config.color} />
        </View>
        <Text style={[styles.genericHeroTitle, { color: config.color }]}>{config.title}</Text>
        <Text style={styles.genericHeroSub}>{config.subtitle}</Text>
        <View style={[styles.genericHeroBadge, { backgroundColor: `${config.color}18`, borderColor: config.color }]}>
          <Ionicons name="globe-outline" size={12} color={config.color} />
          <Text style={[styles.genericHeroBadgeText, { color: config.color }]}>ONLINE VERIFICATION AVAILABLE</Text>
        </View>
      </LinearGradient>

      {/* QR URL found */}
      {detection.extractedUrl && (
        <GlassCard accentColor={C.cyan} style={{ marginBottom: 12 }}>
          <SectionHeader icon="link-outline" label="DECODED URL" />
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
        </GlassCard>
      )}

      {/* How to verify */}
      <GlassCard accentColor={C.violet} style={{ marginBottom: 12 }}>
        <SectionHeader icon="checkmark-circle-outline" label="HOW TO VERIFY" color={C.violet} />
        <Text style={styles.noteText}>{config.howTo}</Text>
      </GlassCard>

      {/* Warning */}
      {config.warning && (
        <GlassCard accentColor={C.rose} style={{ marginBottom: 12 }}>
          <SectionHeader icon="warning-outline" label="WARNING" color={C.rose} />
          <Text style={styles.noteText}>{config.warning}</Text>
        </GlassCard>
      )}

      {/* Verify button */}
      {(detection.extractedUrl || config.verifyUrl) && (
        <TouchableOpacity
          style={[styles.verifyBtn, { backgroundColor: config.color }]}
          onPress={openVerify}
          activeOpacity={0.8}
        >
          <Ionicons name="open-outline" size={17} color="#000" style={{ marginRight: 8 }} />
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
        icon: 'medical', color: C.green,
        title: 'Vaccination Certificate', subtitle: 'CoWIN · Government of India',
        verifyUrl: 'https://selfregistration.cowin.gov.in/', verifyLabel: 'Open CoWIN Portal',
        howTo: 'Open the CoWIN official portal and enter your registered mobile number to view and verify your vaccination certificate. The portal will show the exact vaccines received, dates, and beneficiary name.',
        warning: 'Fraudsters create fake vaccination certificates to bypass verification. Always verify via CoWIN portal, not by looking at the certificate alone.',
      };
    case 'DIGILOCKER_DOC':
      return {
        icon: 'folder-open', color: C.cyan,
        title: 'DigiLocker Document', subtitle: 'National eGov Division · MeitY',
        verifyUrl: 'https://digilocker.gov.in', verifyLabel: 'Open DigiLocker',
        howTo: 'Open DigiLocker and navigate to the shared document. DigiLocker documents are digitally signed by the issuing authority. Click the verification link in the QR to confirm authenticity.',
        warning: 'Scammers have created fake DigiLocker share links. Always confirm the URL begins with digilocker.gov.in before trusting the document.',
      };
    case 'DRIVING_LICENSE':
      return {
        icon: 'car', color: C.violet,
        title: 'Driving License', subtitle: 'Ministry of Road Transport · mParivahan',
        verifyUrl: 'https://mparivahan.gov.in', verifyLabel: 'Verify on mParivahan',
        howTo: 'Open mParivahan app or website. Enter the driving license number shown on the card. The portal will display the holder\'s name, validity, vehicle classes, and issuing RTO. Any mismatch = suspicious.',
        warning: 'Fake driving licenses can be difficult to spot visually. Always verify the DL number on the official mParivahan portal for high-stakes situations.',
      };
    case 'CBSE_CERTIFICATE':
      return {
        icon: 'school', color: C.gold,
        title: 'CBSE / Board Certificate', subtitle: 'Central Board of Secondary Education',
        verifyUrl: 'https://cbse.gov.in', verifyLabel: 'Verify on CBSE Portal',
        howTo: 'Use the CBSE result verification portal with the roll number and year. Alternatively, scan the QR code link which should redirect to an official CBSE or DigiLocker verification page.',
        warning: 'Academic fraud is common in India. Fake marksheets and certificates are used in job applications. Always verify marks with the official board portal before trusting.',
      };
    case 'INCOME_TAX_NOTICE':
      return {
        icon: 'document-text', color: C.gold,
        title: 'Income Tax Document', subtitle: 'Income Tax Department · Government of India',
        verifyUrl: 'https://incometax.gov.in', verifyLabel: 'Open Income Tax Portal',
        howTo: 'Log in to incometax.gov.in with your PAN number to view all official notices. Any genuine IT notice will be available there. Cross-check the notice number shown in the QR.',
        warning: '⚠️ The Income Tax Department NEVER sends QR codes in unofficial documents demanding immediate payment. If this QR came via WhatsApp or email from an unknown sender, it is a scam.',
      };
    case 'COURT_DOCUMENT':
      return {
        icon: 'business', color: C.violet,
        title: 'e-Court Judicial Document', subtitle: 'National Informatics Centre · eCourts',
        verifyUrl: 'https://services.ecourts.gov.in', verifyLabel: 'Verify on eCourts Portal',
        howTo: 'Enter the CNR (Case Number Record) on the eCourts portal to verify the case details. The portal will show the court name, case type, hearing dates, and current status.',
        warning: '⚠️ Scammers send fake court summons with QR codes claiming digital arrest. Real court summons are NEVER delivered via WhatsApp. If you received this from an unknown caller, it is a scam.',
      };
    default:
      return {
        icon: 'shield', color: C.cyan,
        title: 'Government Document', subtitle: detection.description,
        verifyUrl: detection.extractedUrl, verifyLabel: 'Open Official Portal',
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

    if (detection.type === 'AADHAAR_SECURE' || detection.type === 'AADHAAR_XML') {
      setLoading(true);
      verifyAadhaarQR(detection.rawData)
        .then(result => {
          setAadhaarResult(result);
          setLoading(false);
        })
        .catch(() => {
          setLoading(false);
        });
    }
  }, []);

  const isAadhaar = detection.type === 'AADHAAR_SECURE' || detection.type === 'AADHAAR_XML';
  const docConfig = isAadhaar ? null : getDocConfig(detection);

  return (
    <View style={[styles.root, { paddingTop: insets.top }]}>
      {/* ── Header ── */}
      <Animated.View style={[styles.header, { opacity: headerFade }]}>
        <TouchableOpacity onPress={onScanAnother} style={styles.backBtn} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
          <Ionicons name="chevron-back" size={18} color="rgba(255,255,255,0.7)" />
          <Text style={styles.backLabel}>Back</Text>
        </TouchableOpacity>

        <View style={styles.headerPill}>
          <Ionicons name="shield-checkmark" size={12} color={C.cyan} />
          <Text style={styles.headerPillText}>GOV DOC VERIFIER</Text>
        </View>

        <View style={{ width: 70 }} />
      </Animated.View>

      {/* ── Content ── */}
      {loading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={C.cyan} />
          <Text style={styles.loadingText}>Verifying document signature...</Text>
          <Text style={styles.loadingSubText}>Checking UIDAI cryptographic proof • Offline</Text>
        </View>
      ) : isAadhaar && aadhaarResult ? (
        <AadhaarResultCard result={aadhaarResult} onScanAnother={onScanAnother} />
      ) : isAadhaar ? (
        <View style={styles.loadingContainer}>
          <Ionicons name="alert-circle-outline" size={44} color={C.rose} />
          <Text style={[styles.loadingText, { color: C.rose }]}>Verification failed</Text>
          <Text style={styles.loadingSubText}>Please try scanning again.</Text>
        </View>
      ) : (
        <GenericGovDocCard detection={detection} config={docConfig!} />
      )}

      {/* ── Bottom CTA ── */}
      {!loading && (
        <View style={[styles.bottomBar, { paddingBottom: insets.bottom + 10 }]}>
          <TouchableOpacity style={styles.scanAnotherBtn} onPress={onScanAnother} activeOpacity={0.8}>
            <Ionicons name="document-outline" size={17} color={C.cyan} />
            <Text style={styles.scanAnotherText}>Scan Another Document</Text>
            <Ionicons name="chevron-forward" size={16} color={C.cyan} style={{ marginLeft: 'auto' }} />
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
  scrollContent: {
    padding: 16,
    paddingBottom: 20,
  },

  // ── Header ──
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255,255,255,0.07)',
  },
  backBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    width: 70,
    gap: 3,
  },
  backLabel: {
    color: 'rgba(255,255,255,0.7)',
    fontSize: 14,
  },
  headerPill: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(0,212,255,0.1)',
    paddingHorizontal: 14,
    paddingVertical: 7,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(0,212,255,0.3)',
    gap: 6,
  },
  headerPillText: {
    color: C.cyan,
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1.5,
  },

  // ── Loading ──
  loadingContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 14,
    padding: 24,
  },
  loadingText: {
    color: C.frost,
    fontSize: 16,
    fontWeight: '600',
    textAlign: 'center',
  },
  loadingSubText: {
    color: C.muted,
    fontSize: 12,
    textAlign: 'center',
  },

  // ── Glass Card ──
  glassCard: {
    backgroundColor: C.cardBg,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: C.cardBorder,
    padding: 16,
    marginBottom: 12,
  },

  // ── Section Header ──
  sectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 14,
    gap: 9,
  },
  sectionIconRing: {
    width: 26,
    height: 26,
    borderRadius: 13,
    borderWidth: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  sectionLabel: {
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1.3,
    textTransform: 'uppercase',
    color: C.cyan,
  },

  // ── Icon Row ──
  iconRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 10,
    gap: 10,
    minHeight: 22,
  },
  iconRowIcon: {
    width: 18,
  },
  iconRowLabel: {
    color: 'rgba(255,255,255,0.45)',
    fontSize: 13,
    flex: 1,
  },
  iconRowValue: {
    color: 'rgba(255,255,255,0.88)',
    fontSize: 13,
    fontWeight: '500',
    textAlign: 'right',
    flex: 1.2,
  },

  // ── Verification Result Banner ──
  banner: {
    borderRadius: 18,
    borderWidth: 1,
    flexDirection: 'row',
    alignItems: 'center',
    padding: 18,
    paddingRight: 14,
    overflow: 'hidden',
    minHeight: 130,
  },
  bannerWave: {
    position: 'absolute',
    left: 0,
    right: 0,
    height: 2,
    bottom: '40%',
  },
  bannerLeft: {
    flex: 1,
    gap: 5,
  },
  bannerEyebrow: {
    color: 'rgba(255,255,255,0.4)',
    fontSize: 9,
    fontWeight: '700',
    letterSpacing: 1.8,
    textTransform: 'uppercase',
    marginBottom: 2,
  },
  bannerIconRing: {
    width: 44,
    height: 44,
    borderRadius: 22,
    borderWidth: 1.5,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 6,
  },
  bannerName: {
    color: '#fff',
    fontSize: 17,
    fontWeight: '700',
    letterSpacing: -0.3,
  },
  bannerStatus: {
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.8,
    textTransform: 'uppercase',
  },
  bannerSub: {
    color: 'rgba(255,255,255,0.5)',
    fontSize: 11,
    lineHeight: 16,
    marginTop: 2,
  },
  bannerRight: {
    width: 80,
    height: 90,
    alignItems: 'center',
    justifyContent: 'center',
  },
  docIllustration: {
    width: 64,
    height: 78,
    borderRadius: 10,
    backgroundColor: 'rgba(30,50,130,0.4)',
    borderWidth: 1,
    borderColor: 'rgba(80,120,255,0.25)',
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
  },
  docBadge: {
    position: 'absolute',
    bottom: -4,
    right: -4,
    width: 20,
    height: 20,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1.5,
    borderColor: C.bg,
  },

  // ── Document Preview ──
  previewHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 14,
  },
  previewBody: {
    flexDirection: 'row',
    gap: 12,
    alignItems: 'flex-start',
  },
  aadhaarMockupContainer: {
    flex: 1,
    borderRadius: 10,
    overflow: 'hidden',
    minHeight: 100,
  },
  aadhaarMockup: {
    flex: 1,
    minHeight: 100,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: 'rgba(80,120,255,0.2)',
    overflow: 'hidden',
  },
  tricolorStripe: {
    flexDirection: 'row',
    height: 5,
  },
  tricolorBand: {
    flex: 1,
  },
  aadhaarMockupBody: {
    flexDirection: 'row',
    padding: 10,
    gap: 10,
    alignItems: 'center',
  },
  aadhaarMockupPhoto: {
    width: 44,
    height: 54,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.15)',
  },
  aadhaarMockupPhotoPlaceholder: {
    width: 44,
    height: 54,
    borderRadius: 6,
    backgroundColor: 'rgba(255,255,255,0.07)',
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.1)',
  },
  aadhaarMockupLines: {
    flex: 1,
    gap: 5,
  },
  shimmerLine: {
    height: 6,
    borderRadius: 3,
    backgroundColor: 'rgba(255,255,255,0.12)',
    width: '100%',
  },
  zoomBtn: {
    position: 'absolute',
    bottom: 8,
    right: 8,
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: 'rgba(0,0,0,0.55)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.2)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  extractedPhotoBox: {
    width: 90,
    alignItems: 'center',
    gap: 6,
  },
  extractedPhotoLabel: {
    color: 'rgba(255,255,255,0.4)',
    fontSize: 8,
    fontWeight: '700',
    letterSpacing: 1.2,
    textAlign: 'center',
    textTransform: 'uppercase',
  },
  extractedPhoto: {
    width: 80,
    height: 96,
    borderRadius: 10,
    borderWidth: 1.5,
    borderColor: 'rgba(0,212,255,0.3)',
  },
  extractedPhotoPlaceholder: {
    width: 80,
    height: 96,
    borderRadius: 10,
    borderWidth: 1.5,
    borderColor: 'rgba(255,255,255,0.1)',
    backgroundColor: 'rgba(255,255,255,0.05)',
    alignItems: 'center',
    justifyContent: 'center',
  },

  // ── Address decorative pin ──
  decorativePinContainer: {
    position: 'absolute',
    bottom: -10,
    right: -10,
    opacity: 1,
  },

  // ── Verification Note Card ──
  noteCardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 10,
  },
  noteIconRing: {
    width: 24,
    height: 24,
    borderRadius: 12,
    borderWidth: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  noteText: {
    color: 'rgba(255,255,255,0.65)',
    fontSize: 12.5,
    lineHeight: 19,
  },

  // ── Privacy note ──
  privacyNote: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 6,
    paddingHorizontal: 2,
    marginTop: 4,
    marginBottom: 8,
  },
  privacyText: {
    color: 'rgba(255,255,255,0.22)',
    fontSize: 10.5,
    lineHeight: 15,
    flex: 1,
  },

  // ── URL display (generic doc) ──
  urlText: {
    color: 'rgba(255,255,255,0.75)',
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
    flex: 1,
  },

  // ── Generic hero ──
  genericHero: {
    borderRadius: 18,
    borderWidth: 1,
    alignItems: 'center',
    paddingVertical: 28,
    paddingHorizontal: 20,
    marginBottom: 14,
    gap: 10,
  },
  genericHeroIconRing: {
    width: 80,
    height: 80,
    borderRadius: 40,
    borderWidth: 2,
    alignItems: 'center',
    justifyContent: 'center',
  },
  genericHeroTitle: {
    fontSize: 22,
    fontWeight: '800',
    letterSpacing: -0.3,
  },
  genericHeroSub: {
    color: C.muted,
    fontSize: 13,
  },
  genericHeroBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingVertical: 5,
    borderRadius: 20,
    borderWidth: 1,
    gap: 5,
    marginTop: 4,
  },
  genericHeroBadgeText: {
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1,
  },

  // ── Verify button (generic) ──
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

  // ── Bottom bar + Scan Another ──
  bottomBar: {
    paddingHorizontal: 16,
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255,255,255,0.07)',
    backgroundColor: C.bg,
  },
  scanAnotherBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    backgroundColor: 'rgba(0,212,255,0.07)',
    paddingVertical: 15,
    paddingHorizontal: 22,
    borderRadius: 30,
    borderWidth: 1,
    borderColor: 'rgba(0,212,255,0.35)',
    // Glow on iOS
    shadowColor: C.cyan,
    shadowOffset: { width: 0, height: 0 },
    shadowRadius: 12,
    shadowOpacity: 0.25,
  },
  scanAnotherText: {
    color: C.cyan,
    fontSize: 15,
    fontWeight: '600',
    flex: 1,
  },
});
