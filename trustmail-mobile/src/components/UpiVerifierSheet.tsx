/**
 * SafeMail X — UPI QR Forensic Scanner Sheet (Assistive Touch)
 * Liquid glass theme — matches App.tsx TmCard / Indigo Nocturne design system.
 *
 * Dedicated UPI QR Forensic Scanner & Security Auditor:
 *   • Live Camera Viewfinder for instant QR scanning
 *   • Gallery QR Screenshot Scanner (WhatsApp / Payment screenshots)
 *   • Comprehensive NPCI & Banking Forensic Audit
 *   • Pre-filled Debit Trap Detection (OLX / Marketplace scam detector)
 *   • Impersonation & P2P-disguised-as-merchant Audit
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator, Animated, Dimensions,
  Linking, StyleSheet, Text,
  TouchableOpacity, View, ScrollView,
} from 'react-native';
import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import { CameraView, useCameraPermissions, BarcodeScanningResult } from 'expo-camera';
import * as ImagePicker from 'expo-image-picker';
import { TM } from './LiquidGlass';
import { scanQrCode } from '../api';

const { width: SW } = Dimensions.get('window');

// ── Known NPCI Bank / PSP Handles ─────────────────────────────────────────────
const KNOWN_HANDLES: Record<string, string> = {
  oksbi: 'State Bank of India (GPay)',
  okhdfcbank: 'HDFC Bank (GPay)',
  okaxis: 'Axis Bank (GPay)',
  okicici: 'ICICI Bank (GPay)',
  ybl: 'Yes Bank (PhonePe)',
  axl: 'Axis Bank (PhonePe)',
  ibl: 'IndusInd Bank (PhonePe)',
  upi: 'BHIM / NPCI Official',
  paytm: 'Paytm Payments Bank',
  apl: 'Amazon Pay (Axis Bank)',
  kotak: 'Kotak Mahindra Bank',
  airtel: 'Airtel Payments Bank',
  freecharge: 'Axis Bank (Freecharge)',
  jupiteraxis: 'Jupiter (Axis Bank)',
  pnb: 'Punjab National Bank',
  cnrb: 'Canara Bank',
  barodampay: 'Bank of Baroda',
  mahb: 'Bank of Maharashtra',
  nsdl: 'NSDL Payments Bank',
  ikwik: 'MobiKwik',
  sliceaxis: 'Slice (Axis Bank)',
  federal: 'Federal Bank',
  fbl: 'Federal Bank',
  indus: 'IndusInd Bank',
  idbi: 'IDBI Bank',
};

// ── Merchant Category Codes ───────────────────────────────────────────────────
const MCC_MAP: Record<string, string> = {
  '5411': 'Grocery & Supermarkets',
  '5812': 'Eating Places & Restaurants',
  '5814': 'Fast Food Restaurants',
  '5912': 'Drug Stores & Pharmacies',
  '5541': 'Service Stations & Fuel',
  '4814': 'Telecommunications & Recharge',
  '4900': 'Utilities (Electricity/Water/Gas)',
  '6012': 'Financial Institutions / Banking',
  '5311': 'Department Stores',
  '5999': 'Miscellaneous Retail Stores',
  '7399': 'Business Services',
  '8220': 'Colleges & Universities',
  '8211': 'Schools & Educational Services',
  '4121': 'Taxicabs & Ridesharing',
  '4722': 'Travel Agencies & Tour Operators',
  '0000': 'Personal P2P Account (Unverified)',
};

// ── Deceptive Scam Keywords in VPA or Note ───────────────────────────────────
const DECEPTIVE_KEYWORDS = [
  'support', 'customercare', 'helpdesk', 'refund', 'cashback',
  'prize', 'reward', 'lottery', 'winner', 'gift', 'bonus',
  'kyc', 'uidai', 'aadhaar', 'panupdate', 'electricity',
  'billdesk', 'tollfree', 'helpline', 'emergency', 'verification',
];

export interface UpiForensicReport {
  raw: string;
  isUpi: boolean;
  isMaliciousUrl: boolean;
  payeeName: string;
  payeeVpa: string;
  handle: string;
  bankName: string | null;
  amount: string | null;
  mcc: string | null;
  mccCategory: string;
  note: string | null;
  refId: string | null;
  isDebitTrap: boolean;
  isP2PDisguised: boolean;
  isImpersonating: boolean;
  signals: string[];
  riskScore: number;
  verdict: 'CRITICAL SCAM TRAP' | 'HIGH RISK PAYMENT' | 'UNVERIFIED P2P' | 'VERIFIED MERCHANT' | 'INVALID QR';
  color: string;
}

export function parseAndAnalyzeUpiQr(data: string): UpiForensicReport {
  const clean = (data || '').trim();
  const lower = clean.toLowerCase();

  // 1. Check if it's a URL wrapped to disguise as UPI
  if (lower.startsWith('http://') || lower.startsWith('https://')) {
    return {
      raw: clean,
      isUpi: false,
      isMaliciousUrl: true,
      payeeName: 'External Web Link',
      payeeVpa: 'Non-UPI Destination',
      handle: '',
      bankName: null,
      amount: null,
      mcc: null,
      mccCategory: 'Web Phishing Redirect',
      note: null,
      refId: null,
      isDebitTrap: false,
      isP2PDisguised: false,
      isImpersonating: true,
      signals: [
        'QR does NOT contain a UPI payment protocol.',
        'Redirects to an external web browser page instead of UPI payment app.',
        'Common Quishing technique used to phish banking credentials.',
      ],
      riskScore: 88,
      verdict: 'HIGH RISK PAYMENT',
      color: TM.rose,
    };
  }

  // 2. Parse UPI Query Parameters
  const queryPart = clean.includes('?') ? clean.split('?')[1] : clean;
  const params = new URLSearchParams(queryPart);

  const payeeVpa = params.get('pa') || (clean.includes('@') ? clean : '');
  const payeeName = decodeURIComponent(params.get('pn') || 'Unknown Beneficiary').replace(/\+/g, ' ');
  const amount = params.get('am');
  const mcc = params.get('mc');
  const note = params.get('tn') ? decodeURIComponent(params.get('tn')!).replace(/\+/g, ' ') : null;
  const refId = params.get('tr') || params.get('tid') || null;

  const parts = payeeVpa.toLowerCase().split('@');
  const username = parts[0] || '';
  const handle = parts[1] || '';
  const bankName = KNOWN_HANDLES[handle] || null;

  const signals: string[] = [];
  let riskScore = 10;
  let isDebitTrap = false;
  let isP2PDisguised = false;
  let isImpersonating = false;

  // A. Debit Amount Trap Check
  if (amount && parseFloat(amount) > 0) {
    isDebitTrap = true;
    riskScore += 45;
    signals.push(`🚨 PRE-FILLED DEBIT REQUEST FOR ₹${amount}: Scanning this QR will directly deduct money from your account!`);
  }

  // B. Deceptive Keywords Audit
  const fullTextToInspect = `${username} ${note || ''} ${payeeName}`.toLowerCase();
  for (const kw of DECEPTIVE_KEYWORDS) {
    if (fullTextToInspect.includes(kw)) {
      isImpersonating = true;
      riskScore += 35;
      signals.push(`Deceptive keyword "${kw.toUpperCase()}" detected in payment details — characteristic of fake refund/support fraud.`);
      break;
    }
  }

  // C. P2P vs Merchant Category Check
  const mccCategory = mcc ? (MCC_MAP[mcc] || `MCC Code: ${mcc}`) : 'Individual P2P Account';
  if (!mcc || mcc === '0000') {
    isP2PDisguised = true;
    riskScore += 15;
    signals.push('Personal P2P Account: Not registered with NPCI as an official merchant/business.');
  }

  // D. Bank Handle Audit
  if (!bankName && handle) {
    riskScore += 20;
    signals.push(`Unverified Bank Handle "@${handle}" — not in trusted NPCI registry.`);
  }

  // E. Brand Name Mismatch
  if (/(sbi|hdfc|icici|axis|police|cyber|electricity|uidai|airtel|jio)/i.test(payeeName) && isP2PDisguised) {
    riskScore += 40;
    isImpersonating = true;
    signals.push(`Severe Discrepancy: Beneficiary name claims to be "${payeeName}" but routes to an individual unverified personal VPA.`);
  }

  riskScore = Math.min(100, Math.max(0, riskScore));

  let verdict: UpiForensicReport['verdict'] = 'VERIFIED MERCHANT';
  let color = TM.emerald;

  if (isDebitTrap || riskScore >= 70) {
    verdict = 'CRITICAL SCAM TRAP';
    color = TM.rose;
  } else if (riskScore >= 45) {
    verdict = 'HIGH RISK PAYMENT';
    color = TM.rose;
  } else if (isP2PDisguised) {
    verdict = 'UNVERIFIED P2P';
    color = TM.gold;
  } else {
    signals.push('Verified merchant category and recognized banking PSP.');
  }

  return {
    raw: clean,
    isUpi: Boolean(payeeVpa),
    isMaliciousUrl: false,
    payeeName,
    payeeVpa,
    handle,
    bankName,
    amount,
    mcc,
    mccCategory,
    note,
    refId,
    isDebitTrap,
    isP2PDisguised,
    isImpersonating,
    signals,
    riskScore,
    verdict,
    color,
  };
}

interface Props {
  visible: boolean;
  onClose: () => void;
}

export default function UpiVerifierSheet({ visible, onClose }: Props) {
  const [mode, setMode] = useState<'IDLE' | 'CAMERA' | 'ANALYZING' | 'RESULT'>('IDLE');
  const [report, setReport] = useState<UpiForensicReport | null>(null);
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [scannedOnce, setScannedOnce] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(24)).current;

  useEffect(() => {
    if (visible) {
      setMode('IDLE');
      setReport(null);
      setErrorMsg(null);
      setScannedOnce(false);
      Animated.parallel([
        Animated.timing(fadeIn, { toValue: 1, duration: 220, useNativeDriver: true }),
        Animated.spring(slideUp, { toValue: 0, tension: 80, friction: 10, useNativeDriver: true }),
      ]).start();
    } else {
      Animated.parallel([
        Animated.timing(fadeIn, { toValue: 0, duration: 150, useNativeDriver: true }),
        Animated.timing(slideUp, { toValue: 24, duration: 150, useNativeDriver: true }),
      ]).start();
    }
  }, [visible]);

  // ── Launch Live Camera Scanner ──
  const handleStartCamera = async () => {
    setErrorMsg(null);
    if (!cameraPermission?.granted) {
      const res = await requestCameraPermission();
      if (!res.granted) {
        setErrorMsg('Camera permission is required to scan QR codes.');
        return;
      }
    }
    setScannedOnce(false);
    setMode('CAMERA');
  };

  // ── Handle Camera Barcode Found ──
  const handleBarCodeScanned = (scanningResult: BarcodeScanningResult) => {
    if (scannedOnce) return;
    setScannedOnce(true);
    const data = scanningResult.data;
    if (data) {
      const rep = parseAndAnalyzeUpiQr(data);
      setReport(rep);
      setMode('RESULT');
    }
  };

  // ── Pick QR Image from Gallery ──
  const handlePickGallery = async () => {
    setErrorMsg(null);
    try {
      const res = await ImagePicker.launchImageLibraryAsync({
        mediaTypes: ['images'],
        allowsEditing: false,
        quality: 0.9,
      });

      if (res.canceled || !res.assets?.[0]?.uri) return;

      setMode('ANALYZING');
      const asset = res.assets[0];
      const fileName = asset.fileName || 'upi_qr_scan.jpg';
      const mime = asset.mimeType || 'image/jpeg';

      const scanResult = await scanQrCode({
        uri: asset.uri,
        name: fileName,
        mimeType: mime,
      });

      if (scanResult.decoded_payloads && scanResult.decoded_payloads.length > 0) {
        const rawPayload = scanResult.decoded_payloads[0];
        const rep = parseAndAnalyzeUpiQr(rawPayload);
        setReport(rep);
        setMode('RESULT');
      } else if (scanResult.upi_details?.raw) {
        const rep = parseAndAnalyzeUpiQr(scanResult.upi_details.raw);
        setReport(rep);
        setMode('RESULT');
      } else {
        setErrorMsg('No readable QR code found in this image. Ensure the QR is clear and well-lit.');
        setMode('IDLE');
      }
    } catch (e: any) {
      setErrorMsg(e?.message || 'Could not scan image from gallery.');
      setMode('IDLE');
    }
  };

  if (!visible) return null;

  return (
    <Animated.View style={[S.shell, { opacity: fadeIn, transform: [{ translateY: slideUp }] }]}>
      <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
      <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.48)' }]} />
      <LinearGradient
        colors={['rgba(255,255,255,0.08)', 'rgba(255,255,255,0.01)', 'rgba(255,255,255,0.00)', 'rgba(255,255,255,0.03)']}
        start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
        style={StyleSheet.absoluteFillObject}
      />
      <View style={S.shimmer} />

      {/* Header */}
      <View style={S.header}>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          <View style={[S.iconRing, { borderColor: `${TM.emerald}80`, backgroundColor: 'rgba(111,217,184,0.12)' }]}>
            <Ionicons name="qr-code-outline" size={13} color={TM.emerald} />
          </View>
          <Text style={[S.title, { color: TM.emerald }]}>UPI QR FORENSIC SCANNER</Text>
        </View>
        <TouchableOpacity onPress={onClose} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
          <Ionicons name="close" size={18} color={TM.frost4} />
        </TouchableOpacity>
      </View>

      <LinearGradient
        colors={['transparent', `${TM.emerald}40`, 'transparent']}
        start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }}
        style={{ height: 1, marginBottom: 12 }}
      />

      {/* ── Mode 1: IDLE / Scanner Launchpad ── */}
      {mode === 'IDLE' && (
        <View style={{ gap: 12 }}>
          <Text style={S.subtitle}>
            Instantly inspect physical, merchant, or screenshot QR codes for auto-debit traps, brand impersonation & fake handles.
          </Text>

          {errorMsg && (
            <View style={S.errorBox}>
              <Ionicons name="alert-circle" size={14} color={TM.rose} />
              <Text style={S.errorText}>{errorMsg}</Text>
            </View>
          )}

          {/* Primary Button: Live Camera */}
          <TouchableOpacity style={S.primaryScanBtn} activeOpacity={0.84} onPress={handleStartCamera}>
            <LinearGradient colors={['rgba(111,217,184,0.22)', 'rgba(111,217,184,0.08)']} style={S.scanBtnGrad}>
              <View style={[S.actionIconCircle, { backgroundColor: 'rgba(111,217,184,0.18)', borderColor: TM.emerald }]}>
                <Ionicons name="camera-outline" size={20} color={TM.emerald} />
              </View>
              <View style={{ flex: 1 }}>
                <Text style={S.scanBtnTitle}>Scan QR with Camera</Text>
                <Text style={S.scanBtnSub}>Scan payment counter, printout, or screen</Text>
              </View>
              <Ionicons name="chevron-forward" size={16} color={TM.frost3} />
            </LinearGradient>
          </TouchableOpacity>

          {/* Secondary Button: Gallery Screenshot */}
          <TouchableOpacity style={S.primaryScanBtn} activeOpacity={0.84} onPress={handlePickGallery}>
            <LinearGradient colors={['rgba(138,143,240,0.18)', 'rgba(138,143,240,0.06)']} style={S.scanBtnGrad}>
              <View style={[S.actionIconCircle, { backgroundColor: 'rgba(138,143,240,0.18)', borderColor: TM.violetGlow }]}>
                <Ionicons name="images-outline" size={20} color={TM.violetGlow} />
              </View>
              <View style={{ flex: 1 }}>
                <Text style={[S.scanBtnTitle, { color: TM.violetGlow }]}>Pick QR from Gallery</Text>
                <Text style={S.scanBtnSub}>WhatsApp, payment request, or screenshot</Text>
              </View>
              <Ionicons name="chevron-forward" size={16} color={TM.frost3} />
            </LinearGradient>
          </TouchableOpacity>

          {/* NPCI Golden Security Rule */}
          <View style={S.securityRuleBox}>
            <Ionicons name="shield-checkmark" size={14} color={TM.emerald} />
            <Text style={S.securityRuleText}>
              <Text style={{ fontWeight: '700', color: TM.emerald }}>NPCI Rule: </Text>
              Entering UPI PIN always <Text style={{ fontWeight: '700', color: '#fff' }}>DEDUCTS</Text> money. You <Text style={{ fontWeight: '700', color: '#fff' }}>NEVER</Text> need to enter a PIN to receive cashback or payment.
            </Text>
          </View>
        </View>
      )}

      {/* ── Mode 2: Live Camera Viewfinder ── */}
      {mode === 'CAMERA' && (
        <View style={{ alignItems: 'center' }}>
          <View style={S.cameraContainer}>
            <CameraView
              style={StyleSheet.absoluteFillObject}
              facing="back"
              barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
              onBarcodeScanned={handleBarCodeScanned}
            />
            {/* Viewfinder reticle overlay */}
            <View style={S.reticleFrame}>
              <View style={[S.reticleCorner, { top: 0, left: 0, borderTopWidth: 2, borderLeftWidth: 2 }]} />
              <View style={[S.reticleCorner, { top: 0, right: 0, borderTopWidth: 2, borderRightWidth: 2 }]} />
              <View style={[S.reticleCorner, { bottom: 0, left: 0, borderBottomWidth: 2, borderLeftWidth: 2 }]} />
              <View style={[S.reticleCorner, { bottom: 0, right: 0, borderBottomWidth: 2, borderRightWidth: 2 }]} />
              <Text style={S.reticleLabel}>ALIGN UPI QR</Text>
            </View>
          </View>

          <TouchableOpacity style={S.cancelBtn} onPress={() => setMode('IDLE')}>
            <Text style={S.cancelBtnText}>Cancel Camera</Text>
          </TouchableOpacity>
        </View>
      )}

      {/* ── Mode 3: Analyzing Indicator ── */}
      {mode === 'ANALYZING' && (
        <View style={{ paddingVertical: 36, alignItems: 'center', gap: 12 }}>
          <ActivityIndicator size="large" color={TM.emerald} />
          <Text style={{ color: TM.frost2, fontSize: 13, fontWeight: '600' }}>Decoding QR & Inspecting Security Signals…</Text>
        </View>
      )}

      {/* ── Mode 4: Forensic Breakdown Result ── */}
      {mode === 'RESULT' && report && (
        <ScrollView style={{ maxHeight: 380 }} showsVerticalScrollIndicator={false}>
          {/* Verdict Banner */}
          <View style={[S.verdictBanner, { borderColor: `${report.color}55`, backgroundColor: `${report.color}15` }]}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
              <Ionicons
                name={report.verdict === 'VERIFIED MERCHANT' ? 'shield-checkmark' : 'warning'}
                size={20}
                color={report.color}
              />
              <Text style={[S.verdictTitle, { color: report.color }]}>{report.verdict}</Text>
            </View>
            <Text style={S.riskScoreBadge}>Risk {report.riskScore}/100</Text>
          </View>

          {/* Critical Auto-Debit Warning */}
          {report.isDebitTrap && (
            <View style={S.debitTrapAlert}>
              <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Ionicons name="alert-circle" size={16} color={TM.rose} />
                <Text style={S.debitTrapHeading}>AUTO-DEBIT TRAP DETECTED</Text>
              </View>
              <Text style={S.debitTrapBody}>
                This QR code is pre-coded with an outgoing debit of <Text style={{ fontWeight: '800', color: '#fff' }}>₹{report.amount}</Text>.
                Do NOT authorize or enter your UPI PIN.
              </Text>
            </View>
          )}

          {/* Essential Info Grid */}
          <View style={S.infoGrid}>
            {/* Payee Name */}
            <View style={S.infoRow}>
              <Text style={S.infoLabel}>BENEFICIARY NAME</Text>
              <Text style={S.infoValue}>{report.payeeName}</Text>
            </View>

            {/* UPI ID / VPA */}
            <View style={S.infoRow}>
              <Text style={S.infoLabel}>RECEIVING UPI ID</Text>
              <Text style={[S.infoValue, { color: TM.emerald, fontFamily: 'monospace' }]}>{report.payeeVpa || 'None'}</Text>
            </View>

            {/* Bank / Provider */}
            <View style={S.infoRow}>
              <Text style={S.infoLabel}>BANK / PSP HANDLE</Text>
              <Text style={S.infoValue}>{report.bankName || `@${report.handle || 'Unknown'}`}</Text>
            </View>

            {/* Merchant Category */}
            <View style={S.infoRow}>
              <Text style={S.infoLabel}>ACCOUNT CLASSIFICATION</Text>
              <Text style={[S.infoValue, { color: report.isP2PDisguised ? TM.gold : TM.frost }]}>
                {report.mccCategory}
              </Text>
            </View>

            {/* Transaction Note */}
            {report.note && (
              <View style={S.infoRow}>
                <Text style={S.infoLabel}>EMBEDDED NOTE</Text>
                <Text style={S.infoValue}>"{report.note}"</Text>
              </View>
            )}
          </View>

          {/* Forensic Signals */}
          <View style={S.signalsCard}>
            <Text style={S.signalsHeader}>SECURITY AUDIT SIGNALS</Text>
            {report.signals.map((sig, i) => (
              <View key={i} style={S.signalItem}>
                <Ionicons name="information-circle-outline" size={12} color={report.color} style={{ marginTop: 2 }} />
                <Text style={[S.signalText, { color: TM.frost2 }]}>{sig}</Text>
              </View>
            ))}
          </View>

          {/* Scan Another Button */}
          <TouchableOpacity style={S.rescanBtn} activeOpacity={0.82} onPress={() => setMode('IDLE')}>
            <LinearGradient colors={[TM.violetSoft, TM.violet, TM.ink3]} style={S.rescanBtnGrad}>
              <Ionicons name="refresh-outline" size={15} color={TM.frost} />
              <Text style={S.rescanBtnText}>Scan Another QR Code</Text>
            </LinearGradient>
          </TouchableOpacity>
        </ScrollView>
      )}
    </Animated.View>
  );
}

const S = StyleSheet.create({
  shell: {
    borderRadius: 22,
    borderWidth: 1,
    borderColor: `${TM.emerald}45`,
    padding: 16,
    width: 324,
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 18 },
    shadowOpacity: 0.85,
    shadowRadius: 22,
    elevation: 12,
  },
  shimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1.2, backgroundColor: 'rgba(255,255,255,0.35)' },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 },
  iconRing: { width: 26, height: 26, borderRadius: 13, borderWidth: 1, alignItems: 'center', justifyContent: 'center' },
  title: { fontSize: 11, fontWeight: '800', letterSpacing: 1.5, textTransform: 'uppercase' },
  subtitle: { color: TM.frost4, fontSize: 11, lineHeight: 16, marginBottom: 4 },
  errorBox: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    backgroundColor: 'rgba(255,61,113,0.12)',
    borderWidth: 1,
    borderColor: 'rgba(255,61,113,0.35)',
    borderRadius: 12,
    padding: 10,
  },
  errorText: { color: TM.rose, fontSize: 11, flex: 1 },
  primaryScanBtn: { borderRadius: 16, overflow: 'hidden', borderWidth: 1, borderColor: 'rgba(255,255,255,0.08)' },
  scanBtnGrad: { flexDirection: 'row', alignItems: 'center', gap: 12, padding: 12 },
  actionIconCircle: { width: 40, height: 40, borderRadius: 20, borderWidth: 1, alignItems: 'center', justifyContent: 'center' },
  scanBtnTitle: { color: TM.frost, fontSize: 13, fontWeight: '700' },
  scanBtnSub: { color: TM.frost4, fontSize: 10, marginTop: 2 },
  securityRuleBox: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 8,
    backgroundColor: 'rgba(111,217,184,0.06)',
    borderWidth: 1,
    borderColor: 'rgba(111,217,184,0.22)',
    borderRadius: 12,
    padding: 10,
    marginTop: 4,
  },
  securityRuleText: { color: TM.frost3, fontSize: 10.5, lineHeight: 15, flex: 1 },
  cameraContainer: { width: 290, height: 260, borderRadius: 16, overflow: 'hidden', position: 'relative' },
  reticleFrame: {
    position: 'absolute',
    top: 35,
    left: 50,
    width: 190,
    height: 190,
    alignItems: 'center',
    justifyContent: 'center',
  },
  reticleCorner: { position: 'absolute', width: 24, height: 24, borderColor: TM.emerald },
  reticleLabel: {
    color: TM.emerald,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 1.5,
    backgroundColor: 'rgba(0,0,0,0.6)',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
  },
  cancelBtn: { marginTop: 12, paddingVertical: 8, paddingHorizontal: 16 },
  cancelBtnText: { color: TM.frost4, fontSize: 12, fontWeight: '600' },
  verdictBanner: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 12,
    borderRadius: 14,
    borderWidth: 1,
    marginBottom: 10,
  },
  verdictTitle: { fontSize: 13, fontWeight: '800', letterSpacing: 0.5 },
  riskScoreBadge: { color: TM.frost3, fontSize: 11, fontWeight: '700' },
  debitTrapAlert: {
    backgroundColor: 'rgba(255,61,113,0.14)',
    borderWidth: 1,
    borderColor: 'rgba(255,61,113,0.45)',
    borderRadius: 12,
    padding: 10,
    marginBottom: 10,
  },
  debitTrapHeading: { color: TM.rose, fontSize: 11, fontWeight: '800', letterSpacing: 0.5 },
  debitTrapBody: { color: TM.frost2, fontSize: 11, lineHeight: 15 },
  infoGrid: {
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
    padding: 12,
    gap: 10,
    marginBottom: 10,
  },
  infoRow: { gap: 2 },
  infoLabel: { color: TM.frost4, fontSize: 9.5, fontWeight: '800', letterSpacing: 0.5 },
  infoValue: { color: TM.frost, fontSize: 12, fontWeight: '600' },
  signalsCard: {
    backgroundColor: 'rgba(255,255,255,0.02)',
    borderRadius: 12,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.05)',
    padding: 10,
    gap: 6,
    marginBottom: 12,
  },
  signalsHeader: { color: TM.frost4, fontSize: 9.5, fontWeight: '800', letterSpacing: 0.5, marginBottom: 2 },
  signalItem: { flexDirection: 'row', alignItems: 'flex-start', gap: 6 },
  signalText: { fontSize: 11, lineHeight: 15, flex: 1 },
  rescanBtn: { borderRadius: 12, overflow: 'hidden', marginBottom: 4 },
  rescanBtnGrad: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    paddingVertical: 10,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: 'rgba(242,234,253,0.22)',
  },
  rescanBtnText: { color: TM.frost, fontSize: 12, fontWeight: '700' },
});
