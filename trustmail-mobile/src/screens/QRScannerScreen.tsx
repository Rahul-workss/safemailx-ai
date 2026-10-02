/**
 * SafeMail X — QR Scanner Screen (Redesigned)
 *
 * Two modes selectable via a pill toggle at the top:
 *   1. SCAN QR       — Security-aware general QR scanner (URLs, UPI, Wi-Fi, Text)
 *   2. VERIFY DOC    — Official document verifier (Aadhaar, DigiLocker, DL, CBSE…)
 *
 * Smart cross-mode routing:
 *   • In SCAN QR mode   → scans a gov-doc QR  → offers redirect to VERIFY DOC
 *   • In VERIFY DOC mode → scans a URL/UPI QR  → offers redirect to SCAN QR
 *
 * Camera overlays change per mode:
 *   • SCAN QR   : square QR reticle (cyan)
 *   • VERIFY DOC: landscape card outline (violet)
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView,
  Animated, Dimensions, Platform, Modal,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { CameraView, useCameraPermissions, BarcodeScanningResult } from 'expo-camera';
import * as ImagePicker from 'expo-image-picker';
import { scanQrCode, scanUrl, QRScanResult } from '../api';
import { detectGovDocType, type GovDocDetectResult } from '../services/govDocDetector';
import GovDocVerifierScreen from './GovDocVerifierScreen';

const { width: SW } = Dimensions.get('window');

// ─── Design Tokens (aligned with global theme.ts) ────────────────────────────
const C = {
  bg:       '#06080f',
  surface:  'rgba(255,255,255,0.05)',
  border:   'rgba(255,255,255,0.09)',
  cyan:     '#00f3ff',
  violet:   '#8c52ff',
  rose:     '#ff3d71',
  gold:     '#ffaa00',
  green:    '#34c759',
  frost:    '#e8eaf0',
  frost2:   '#a39ab8',
  frost4:   '#4a5568',
  ink3:     '#151538',
};

// ─── Types ────────────────────────────────────────────────────────────────────
type ScanMode = 'SCAN_QR' | 'VERIFY_DOC';
type ScreenState = 'CAMERA' | 'ANALYZING' | 'VERDICT' | 'GOV_DOC' | 'CROSS_ROUTE';

// ─── Glass Card ───────────────────────────────────────────────────────────────
function GlassCard({ children, style, accent }: { children: React.ReactNode; style?: any; accent?: string }) {
  return (
    <View style={[{
      backgroundColor: 'rgba(255,255,255,0.05)',
      borderRadius: 20,
      borderWidth: 1,
      borderColor: accent ? `${accent}40` : 'rgba(255,255,255,0.1)',
      padding: 20,
    }, style]}>
      {children}
    </View>
  );
}

// ─── Mode Toggle Pill ─────────────────────────────────────────────────────────
function ModeToggle({ mode, onChange }: { mode: ScanMode; onChange: (m: ScanMode) => void }) {
  const slide = useRef(new Animated.Value(mode === 'SCAN_QR' ? 0 : 1)).current;

  useEffect(() => {
    Animated.spring(slide, {
      toValue: mode === 'SCAN_QR' ? 0 : 1,
      tension: 80, friction: 12, useNativeDriver: false,
    }).start();
  }, [mode]);

  const left = slide.interpolate({ inputRange: [0, 1], outputRange: ['0%', '50%'] });

  return (
    <View style={styles.toggleContainer}>
      {/* Sliding pill */}
      <Animated.View style={[styles.togglePill, { left }]} />
      <TouchableOpacity style={styles.toggleOption} onPress={() => onChange('SCAN_QR')}>
        <Ionicons name="scan-outline" size={13} color={mode === 'SCAN_QR' ? '#000' : C.frost2} style={{ marginRight: 4 }} />
        <Text style={[styles.toggleLabel, mode === 'SCAN_QR' && styles.toggleLabelActive]}>Scan QR</Text>
      </TouchableOpacity>
      <TouchableOpacity style={styles.toggleOption} onPress={() => onChange('VERIFY_DOC')}>
        <Ionicons name="shield-checkmark-outline" size={13} color={mode === 'VERIFY_DOC' ? '#000' : C.frost2} style={{ marginRight: 4 }} />
        <Text style={[styles.toggleLabel, mode === 'VERIFY_DOC' && styles.toggleLabelActive]}>Verify Document</Text>
      </TouchableOpacity>
    </View>
  );
}

// ─── QR Scan Frame (square, cyan) ─────────────────────────────────────────────
function ScanFrame() {
  const pulse = useRef(new Animated.Value(0.4)).current;
  const sweep = useRef(new Animated.Value(0)).current;
  const FRAME = SW * 0.65;
  const CORNER = 30;

  useEffect(() => {
    Animated.loop(Animated.sequence([
      Animated.timing(pulse, { toValue: 0.9, duration: 1200, useNativeDriver: true }),
      Animated.timing(pulse, { toValue: 0.4, duration: 1200, useNativeDriver: true }),
    ])).start();
    Animated.loop(Animated.timing(sweep, { toValue: 1, duration: 2000, useNativeDriver: true })).start();
  }, []);

  const sweepY = sweep.interpolate({ inputRange: [0, 1], outputRange: [0, FRAME - 4] });
  const corner = (pos: any) => ({ position: 'absolute' as const, width: CORNER, height: CORNER, ...pos });

  return (
    <View style={{ width: FRAME, height: FRAME, alignSelf: 'center' }}>
      <Animated.View style={[corner({ top: 0, left: 0 }), { borderTopWidth: 3, borderLeftWidth: 3, borderColor: C.cyan, borderTopLeftRadius: 12, opacity: pulse }]} />
      <Animated.View style={[corner({ top: 0, right: 0 }), { borderTopWidth: 3, borderRightWidth: 3, borderColor: C.cyan, borderTopRightRadius: 12, opacity: pulse }]} />
      <Animated.View style={[corner({ bottom: 0, left: 0 }), { borderBottomWidth: 3, borderLeftWidth: 3, borderColor: C.cyan, borderBottomLeftRadius: 12, opacity: pulse }]} />
      <Animated.View style={[corner({ bottom: 0, right: 0 }), { borderBottomWidth: 3, borderRightWidth: 3, borderColor: C.cyan, borderBottomRightRadius: 12, opacity: pulse }]} />
      <Animated.View style={{ position: 'absolute', left: 8, right: 8, height: 2, backgroundColor: C.cyan, opacity: 0.7, transform: [{ translateY: sweepY }], shadowColor: C.cyan, shadowRadius: 10, shadowOpacity: 0.8 }} />
    </View>
  );
}

// ─── Document Card Frame (landscape card, violet) ─────────────────────────────
function DocFrame() {
  const pulse = useRef(new Animated.Value(0.4)).current;
  const sweep = useRef(new Animated.Value(0)).current;
  const W = SW * 0.85;
  const H = W * 0.62; // landscape card aspect ratio
  const CORNER = 24;

  useEffect(() => {
    Animated.loop(Animated.sequence([
      Animated.timing(pulse, { toValue: 1, duration: 900, useNativeDriver: true }),
      Animated.timing(pulse, { toValue: 0.3, duration: 900, useNativeDriver: true }),
    ])).start();
    Animated.loop(Animated.timing(sweep, { toValue: 1, duration: 2400, useNativeDriver: true })).start();
  }, []);

  const sweepY = sweep.interpolate({ inputRange: [0, 1], outputRange: [0, H - 3] });
  const corner = (pos: any) => ({ position: 'absolute' as const, width: CORNER, height: CORNER, ...pos });

  return (
    <View style={{ width: W, height: H, alignSelf: 'center' }}>
      <Animated.View style={[corner({ top: 0, left: 0 }), { borderTopWidth: 3, borderLeftWidth: 3, borderColor: C.violet, borderTopLeftRadius: 10, opacity: pulse }]} />
      <Animated.View style={[corner({ top: 0, right: 0 }), { borderTopWidth: 3, borderRightWidth: 3, borderColor: C.violet, borderTopRightRadius: 10, opacity: pulse }]} />
      <Animated.View style={[corner({ bottom: 0, left: 0 }), { borderBottomWidth: 3, borderLeftWidth: 3, borderColor: C.violet, borderBottomLeftRadius: 10, opacity: pulse }]} />
      <Animated.View style={[corner({ bottom: 0, right: 0 }), { borderBottomWidth: 3, borderRightWidth: 3, borderColor: C.violet, borderBottomRightRadius: 10, opacity: pulse }]} />
      <Animated.View style={{ position: 'absolute', left: 6, right: 6, height: 2, backgroundColor: C.violet, opacity: 0.65, transform: [{ translateY: sweepY }], shadowColor: C.violet, shadowRadius: 8, shadowOpacity: 0.8 }} />
    </View>
  );
}

// ─── Analyzing View ───────────────────────────────────────────────────────────
function AnalyzingView({ mode }: { mode: ScanMode }) {
  const spin = useRef(new Animated.Value(0)).current;
  const pulse = useRef(new Animated.Value(0.8)).current;
  const color = mode === 'VERIFY_DOC' ? C.violet : C.cyan;

  useEffect(() => {
    Animated.loop(Animated.timing(spin, { toValue: 1, duration: 1800, useNativeDriver: true })).start();
    Animated.loop(Animated.sequence([
      Animated.timing(pulse, { toValue: 1.1, duration: 800, useNativeDriver: true }),
      Animated.timing(pulse, { toValue: 0.8, duration: 800, useNativeDriver: true }),
    ])).start();
  }, []);

  const rotate = spin.interpolate({ inputRange: [0, 1], outputRange: ['0deg', '360deg'] });
  const layers = mode === 'VERIFY_DOC'
    ? ['Document Detection', 'Signature Extraction', 'UIDAI RSA Verification', 'Data Parsing', 'Verdict']
    : ['QR Decode', 'URL Extract', 'Phishing Check', 'UPI Scam Detect', 'Verdict'];

  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <Animated.View style={{ transform: [{ rotate }, { scale: pulse }] }}>
        <View style={{ width: 90, height: 90, borderRadius: 45, borderWidth: 2, borderColor: color, borderTopColor: 'transparent', alignItems: 'center', justifyContent: 'center', shadowColor: color, shadowRadius: 20, shadowOpacity: 0.6 }}>
          <Ionicons name={mode === 'VERIFY_DOC' ? 'shield-checkmark' : 'qr-code'} size={32} color={color} />
        </View>
      </Animated.View>
      <Text style={{ fontSize: 24, fontWeight: '700', color: '#fff', marginTop: 32, marginBottom: 8, textAlign: 'center' }}>
        {mode === 'VERIFY_DOC' ? 'Verifying Document' : 'Analyzing QR Code'}
      </Text>
      <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 14, textAlign: 'center', marginBottom: 12 }}>
        {mode === 'VERIFY_DOC' ? 'Checking UIDAI digital signature…' : 'Decoding & checking for threats…'}
      </Text>
      {layers.map((layer, i) => (
        <Text key={i} style={{ color: `${color}60`, fontSize: 11, marginTop: 5, letterSpacing: 0.8 }}>▶ {layer}</Text>
      ))}
    </View>
  );
}

// ─── Cross-route Prompt Modal ─────────────────────────────────────────────────
function CrossRouteModal({
  visible, message, actionLabel, actionColor, onAccept, onDismiss,
}: {
  visible: boolean; message: string; actionLabel: string; actionColor: string;
  onAccept: () => void; onDismiss: () => void;
}) {
  return (
    <Modal visible={visible} transparent animationType="fade">
      <View style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.75)', justifyContent: 'flex-end', padding: 24 }}>
        <GlassCard accent={actionColor} style={{ marginBottom: 16 }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 12 }}>
            <Ionicons name="swap-horizontal" size={18} color={actionColor} style={{ marginRight: 8 }} />
            <Text style={{ color: actionColor, fontSize: 12, fontWeight: '700', letterSpacing: 1, textTransform: 'uppercase' }}>Smart Routing</Text>
          </View>
          <Text style={{ color: C.frost, fontSize: 15, lineHeight: 22, marginBottom: 20 }}>{message}</Text>
          <TouchableOpacity
            style={{ backgroundColor: actionColor, borderRadius: 14, padding: 14, alignItems: 'center', marginBottom: 10 }}
            onPress={onAccept}
          >
            <Text style={{ color: '#000', fontSize: 15, fontWeight: '700' }}>{actionLabel}</Text>
          </TouchableOpacity>
          <TouchableOpacity style={{ alignItems: 'center', padding: 10 }} onPress={onDismiss}>
            <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: 14 }}>Stay in current mode</Text>
          </TouchableOpacity>
        </GlassCard>
      </View>
    </Modal>
  );
}

// ─── Verdict View (Scan QR results) ──────────────────────────────────────────
function VerdictView({ result, onRetry, onClose }: { result: QRScanResult; onRetry: () => void; onClose: () => void }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(40)).current;
  const scoreAnim = useRef(new Animated.Value(0)).current;
  const [displayScore, setDisplayScore] = useState(0);

  const isDangerous = result.overall_verdict === 'dangerous';
  const isSuspicious = result.overall_verdict === 'suspicious';
  const color = isDangerous ? C.rose : isSuspicious ? C.gold : C.green;
  const label = isDangerous ? '🔴 DANGEROUS' : isSuspicious ? '🟡 SUSPICIOUS' : result.overall_verdict === 'no_qr_found' ? '⚪ NO QR FOUND' : '🟢 SAFE';
  const scoreVal = Math.round(result.overall_risk_score * 100);

  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn, { toValue: 1, duration: 500, useNativeDriver: true }),
      Animated.spring(slideUp, { toValue: 0, tension: 70, friction: 10, useNativeDriver: true }),
    ]).start();
    scoreAnim.addListener(({ value }) => setDisplayScore(Math.round(value)));
    Animated.timing(scoreAnim, { toValue: scoreVal, duration: 1200, useNativeDriver: false }).start();
    return () => scoreAnim.removeAllListeners();
  }, []);

  return (
    <Animated.ScrollView
      contentContainerStyle={{ padding: 24, paddingBottom: 120 }}
      showsVerticalScrollIndicator={false}
      style={{ opacity: fadeIn, transform: [{ translateY: slideUp }] }}
    >
      {/* Risk Score Circle */}
      <View style={{ alignItems: 'center', marginBottom: 28 }}>
        <View style={{ width: 130, height: 130, borderRadius: 65, backgroundColor: `${color}18`, borderWidth: 2, borderColor: color, alignItems: 'center', justifyContent: 'center', shadowColor: color, shadowRadius: 24, shadowOpacity: 0.6, marginBottom: 16 }}>
          <Ionicons name="qr-code" size={28} color={color} style={{ marginBottom: 4 }} />
          <Text style={{ fontSize: 32, fontWeight: '800', color }}>{displayScore}</Text>
          <Text style={{ fontSize: 9, color: 'rgba(255,255,255,0.5)', letterSpacing: 1 }}>RISK SCORE</Text>
        </View>
        <Text style={{ fontSize: 20, fontWeight: '800', color, letterSpacing: 0.5 }}>{label}</Text>
      </View>

      {/* Summary */}
      <GlassCard style={{ marginBottom: 16 }} accent={color}>
        <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
          <Ionicons name="shield-checkmark" size={16} color={color} style={{ marginRight: 8 }} />
          <Text style={{ color, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Security Verdict</Text>
        </View>
        <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 14, lineHeight: 21 }}>{result.summary}</Text>
      </GlassCard>

      {/* Decoded Content */}
      {result.qr_codes_found > 0 && (
        <GlassCard style={{ marginBottom: 16 }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
            <Ionicons name="scan" size={16} color={C.cyan} style={{ marginRight: 8 }} />
            <Text style={{ color: C.cyan, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Decoded Content</Text>
            <View style={{ marginLeft: 'auto', backgroundColor: 'rgba(0,243,255,0.1)', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 10 }}>
              <Text style={{ color: C.cyan, fontSize: 9, fontWeight: '700' }}>{result.qr_codes_found} QR{result.qr_codes_found > 1 ? 's' : ''}</Text>
            </View>
          </View>
          {result.decoded_payloads.map((p, i) => (
            <View key={i} style={{ flexDirection: 'row', marginBottom: 8, paddingLeft: 8, borderLeftWidth: 2, borderLeftColor: C.cyan }}>
              <Text style={{ color: 'rgba(255,255,255,0.8)', fontSize: 12, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', flex: 1 }} numberOfLines={2}>{p}</Text>
            </View>
          ))}
        </GlassCard>
      )}

      {/* UPI Payment Card */}
      {result.is_upi_payment && result.upi_details && (
        <GlassCard style={{ marginBottom: 16 }} accent={C.gold}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 12 }}>
            <Text style={{ fontSize: 18, marginRight: 8 }}>💳</Text>
            <Text style={{ color: C.gold, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>UPI Payment QR</Text>
          </View>
          <View style={{ gap: 8 }}>
            {result.upi_details.payee_name && (
              <View style={{ flexDirection: 'row' }}>
                <Text style={{ color: C.frost2, fontSize: 12, width: 80 }}>Payee</Text>
                <Text style={{ color: C.frost, fontSize: 14, fontWeight: '700', flex: 1 }}>{result.upi_details.payee_name}</Text>
              </View>
            )}
            {result.upi_details.payee_vpa && (
              <View style={{ flexDirection: 'row' }}>
                <Text style={{ color: C.frost2, fontSize: 12, width: 80 }}>UPI ID</Text>
                <Text style={{ color: C.frost, fontSize: 13, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', flex: 1 }}>{result.upi_details.payee_vpa}</Text>
              </View>
            )}
            {result.upi_details.amount && (
              <View style={{ flexDirection: 'row', marginTop: 4 }}>
                <Text style={{ color: C.frost2, fontSize: 12, width: 80 }}>Amount</Text>
                <Text style={{ color: C.rose, fontSize: 18, fontWeight: '800' }}>₹{result.upi_details.amount}</Text>
              </View>
            )}
            {result.upi_details.note && (
              <View style={{ flexDirection: 'row' }}>
                <Text style={{ color: C.frost2, fontSize: 12, width: 80 }}>Note</Text>
                <Text style={{ color: 'rgba(255,255,255,0.6)', fontSize: 13, fontStyle: 'italic', flex: 1 }}>{result.upi_details.note}</Text>
              </View>
            )}
          </View>
          <View style={{ backgroundColor: 'rgba(255,61,113,0.1)', padding: 12, borderRadius: 12, marginTop: 14, borderWidth: 1, borderColor: 'rgba(255,61,113,0.2)' }}>
            <Text style={{ color: C.rose, fontSize: 12, fontWeight: '600', lineHeight: 18 }}>
              ⚠️ SafeMail X verifies the QR format, NOT the payee identity.{'\n'}
              Never pay via QR from unknown callers or messages.
            </Text>
          </View>
        </GlassCard>
      )}

      {/* URL Security Analysis */}
      {result.url_verdicts.filter(v => !v.url.startsWith('upi://')).length > 0 && (
        <GlassCard style={{ marginBottom: 16 }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 14 }}>
            <Ionicons name="globe-outline" size={16} color={C.violet} style={{ marginRight: 8 }} />
            <Text style={{ color: C.violet, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>URL Security Analysis</Text>
          </View>
          {result.url_verdicts.filter(v => !v.url.startsWith('upi://')).map((v, i) => {
            const vc = v.verdict === 'phishing' ? C.rose : v.verdict === 'suspicious' ? C.gold : C.green;
            return (
              <View key={i} style={{ marginBottom: 14, paddingLeft: 10, borderLeftWidth: 2, borderLeftColor: vc }}>
                <Text style={{ color: 'rgba(255,255,255,0.75)', fontSize: 12, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' }} numberOfLines={1}>{v.url}</Text>
                <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 6, gap: 8 }}>
                  <View style={{ backgroundColor: `${vc}20`, paddingHorizontal: 8, paddingVertical: 3, borderRadius: 10 }}>
                    <Text style={{ color: vc, fontSize: 10, fontWeight: '700', textTransform: 'uppercase' }}>{v.verdict}</Text>
                  </View>
                  <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: 10 }}>{Math.round(v.risk_score * 100)}% risk</Text>
                </View>
                {v.summary ? <Text style={{ color: 'rgba(255,255,255,0.6)', fontSize: 12, marginTop: 6, lineHeight: 18 }}>{v.summary}</Text> : null}
              </View>
            );
          })}
        </GlassCard>
      )}

      {/* CTAs */}
      {isDangerous && (
        <View style={{ backgroundColor: 'rgba(255,61,113,0.12)', borderRadius: 16, padding: 16, alignItems: 'center', marginBottom: 12, borderWidth: 1, borderColor: 'rgba(255,61,113,0.3)' }}>
          <Ionicons name="ban" size={22} color={C.rose} style={{ marginBottom: 6 }} />
          <Text style={{ color: C.rose, fontSize: 15, fontWeight: '700' }}>Do NOT Open This Link</Text>
          <Text style={{ color: 'rgba(255,255,255,0.5)', fontSize: 12, marginTop: 4, textAlign: 'center' }}>This QR contains a dangerous or phishing URL.</Text>
        </View>
      )}
      <TouchableOpacity style={{ backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: 16, padding: 16, alignItems: 'center', marginBottom: 12, borderWidth: 1, borderColor: 'rgba(255,255,255,0.1)' }} onPress={onRetry}>
        <Text style={{ color: 'rgba(255,255,255,0.8)', fontSize: 15, fontWeight: '600' }}>Scan Another QR</Text>
      </TouchableOpacity>
      <TouchableOpacity style={{ alignItems: 'center', padding: 12 }} onPress={onClose}>
        <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 15 }}>Close</Text>
      </TouchableOpacity>
    </Animated.ScrollView>
  );
}

// ─── Main QR Scanner Screen ───────────────────────────────────────────────────
export default function QRScannerScreen({ onClose }: { onClose: () => void }) {
  const [permission, requestPermission] = useCameraPermissions();
  const [mode, setMode] = useState<ScanMode>('SCAN_QR');
  const [state, setState] = useState<ScreenState>('CAMERA');
  const [result, setResult] = useState<QRScanResult | null>(null);
  const [govDocDetection, setGovDocDetection] = useState<GovDocDetectResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanned, setScanned] = useState(false);
  const [torch, setTorch] = useState(false);

  // Cross-route modal state
  const [crossRouteVisible, setCrossRouteVisible] = useState(false);
  const [crossRouteData, setCrossRouteData] = useState<{
    message: string; actionLabel: string; actionColor: string;
    onAccept: () => void;
  } | null>(null);

  useEffect(() => {
    if (!permission?.granted) requestPermission();
  }, []);

  // ── Smart Cross-Route helpers ──────────────────────────────────────────────
  const offerDocRedirect = useCallback((detection: GovDocDetectResult) => {
    setCrossRouteData({
      message: `🏛️ Official Document Detected!\n\n"${detection.description}" QR found while in Scan QR mode.\n\nSwitch to Verify Document mode for full parsing & UIDAI signature verification?`,
      actionLabel: '🛡️ Switch to Verify Document',
      actionColor: C.violet,
      onAccept: () => {
        setCrossRouteVisible(false);
        setMode('VERIFY_DOC');
        setGovDocDetection(detection);
        setState('GOV_DOC');
      },
    });
    setCrossRouteVisible(true);
  }, []);

  const offerScanRedirect = useCallback((res: QRScanResult) => {
    setCrossRouteData({
      message: `🔗 Standard QR Link Detected!\n\nA URL or UPI QR was found while in Verify Document mode.\n\nSwitch to Scan QR mode for full security & phishing analysis?`,
      actionLabel: '🔍 Switch to Scan QR',
      actionColor: C.cyan,
      onAccept: () => {
        setCrossRouteVisible(false);
        setMode('SCAN_QR');
        setResult(res);
        setState('VERDICT');
      },
    });
    setCrossRouteVisible(true);
  }, []);

  const dismissCrossRoute = useCallback(() => {
    setCrossRouteVisible(false);
    // Recover camera (stay in current mode)
    setScanned(false);
    setState('CAMERA');
  }, []);

  // ── Route payload to the right flow ──────────────────────────────────────
  const routePayload = useCallback(async (
    data: string,
    backendResult?: QRScanResult | null,
  ) => {
    const govDetection = detectGovDocType(data);

    if (mode === 'SCAN_QR') {
      // In Scan QR mode, offer to redirect if it's a gov doc
      if (govDetection.isGovDoc && !data.startsWith('http')) {
        offerDocRedirect(govDetection);
        return;
      }
    }

    if (mode === 'VERIFY_DOC') {
      // In Verify Doc mode, offer to redirect if it's a plain URL / UPI
      if (!govDetection.isGovDoc && (data.startsWith('http') || data.toLowerCase().startsWith('upi://'))) {
        if (backendResult) {
          offerScanRedirect(backendResult);
        } else {
          setScanned(false);
          setState('CAMERA');
        }
        return;
      }
      // Gov doc in Verify Doc mode → go straight to verifier
      if (govDetection.isGovDoc) {
        setGovDocDetection(govDetection);
        setState('GOV_DOC');
        return;
      }
    }

    // Scan QR mode: show verdict
    if (backendResult) {
      setResult(backendResult);
      setState('VERDICT');
    }
  }, [mode, offerDocRedirect, offerScanRedirect]);

  // ── Live barcode scanner ──────────────────────────────────────────────────
  const handleBarCodeScanned = useCallback(async (scanResult: BarcodeScanningResult) => {
    if (scanned) return;
    setScanned(true);
    const data = scanResult.data;

    // Fast-path gov doc detection (no backend call needed for raw payloads)
    const govDetection = detectGovDocType(data);
    if (govDetection.isGovDoc && !data.startsWith('http')) {
      if (mode === 'VERIFY_DOC') {
        setGovDocDetection(govDetection);
        setState('GOV_DOC');
        return;
      }
      if (mode === 'SCAN_QR') {
        offerDocRedirect(govDetection);
        return;
      }
    }

    setState('ANALYZING');

    try {
      // UPI fast parse (instant, no network)
      if (data.toLowerCase().startsWith('upi://pay')) {
        const params = new URLSearchParams(data.split('?')[1] || '');
        const upiResult: QRScanResult = {
          qr_codes_found: 1,
          decoded_payloads: [data],
          urls_found: [],
          non_url_payloads: [],
          url_verdicts: [{
            url: data,
            verdict: 'suspicious',
            risk_score: 0.65,
            summary: `UPI payment QR. Payee: ${params.get('pn') || '?'} (${params.get('pa') || '?'})${params.get('am') ? `, Amount: ₹${params.get('am')}` : ''}. Verify before paying.`,
          }],
          overall_verdict: 'suspicious',
          overall_risk_score: 0.65,
          summary: '⚠️ Payment QR detected. Never pay via QR from unknown sources.',
          is_upi_payment: true,
          upi_details: {
            raw: data,
            payee_name: params.get('pn') || 'Unknown',
            payee_vpa: params.get('pa') || 'Unknown',
            amount: params.get('am'),
            note: params.get('tn'),
          },
        };
        await routePayload(data, upiResult);
        return;
      }

      // HTTP URL path
      if (data.startsWith('http://') || data.startsWith('https://')) {
        const urlGov = detectGovDocType(data);
        if (urlGov.isGovDoc) {
          if (mode === 'VERIFY_DOC') {
            setGovDocDetection(urlGov);
            setState('GOV_DOC');
            return;
          }
          offerDocRedirect(urlGov);
          return;
        }
        try {
          const urlResult = await scanUrl(data);
          const normScore = urlResult.risk_score / 100;
          const verdict = urlResult.verdict === 'phishing' ? 'dangerous'
            : urlResult.verdict === 'suspicious' ? 'suspicious' : 'safe';
          const res: QRScanResult = {
            qr_codes_found: 1,
            decoded_payloads: [data],
            urls_found: [data],
            non_url_payloads: [],
            url_verdicts: [{ url: data, verdict: urlResult.verdict, risk_score: normScore, summary: urlResult.summary }],
            overall_verdict: verdict,
            overall_risk_score: normScore,
            summary: urlResult.summary,
            is_upi_payment: false,
            upi_details: null,
          };
          await routePayload(data, res);
        } catch {
          const res: QRScanResult = {
            qr_codes_found: 1, decoded_payloads: [data], urls_found: [data],
            non_url_payloads: [], url_verdicts: [{ url: data, verdict: 'unknown', risk_score: 0.3, summary: 'URL found but could not be fully analyzed. Proceed with caution.' }],
            overall_verdict: 'suspicious', overall_risk_score: 0.3,
            summary: 'QR URL could not be fully analyzed. Proceed with caution.',
            is_upi_payment: false, upi_details: null,
          };
          await routePayload(data, res);
        }
        return;
      }

      // Text / generic QR
      const res: QRScanResult = {
        qr_codes_found: 1, decoded_payloads: [data], urls_found: [],
        non_url_payloads: [data], url_verdicts: [],
        overall_verdict: 'safe', overall_risk_score: 0,
        summary: `QR contains text data: "${data.substring(0, 120)}"`,
        is_upi_payment: false, upi_details: null,
      };
      await routePayload(data, res);
    } catch (e: any) {
      setError(e.message || 'QR analysis failed');
      setState('CAMERA');
      setScanned(false);
    }
  }, [scanned, mode, routePayload, offerDocRedirect]);

  // ── Shared image → backend pipeline ──────────────────────────────────────
  const processImage = useCallback(async (uri: string, name: string, mimeType: string) => {
    setState('ANALYZING');
    try {
      const res = await scanQrCode({ uri, name, mimeType: mimeType || 'image/jpeg' });

      if (res.qr_codes_found === 0) {
        setError('No QR code found. Crop tighter around the QR code and try again.');
        setState('CAMERA');
        return;
      }

      const allPayloads = [...(res.decoded_payloads || []), ...(res.non_url_payloads || [])];
      for (const payload of allPayloads) {
        const govDetection = detectGovDocType(payload);
        if (govDetection.isGovDoc) {
          if (mode === 'VERIFY_DOC') {
            setGovDocDetection(govDetection);
            setState('GOV_DOC');
            return;
          }
          // In SCAN_QR mode — offer cross-route
          offerDocRedirect(govDetection);
          return;
        }
      }

      // Check if it's a URL/UPI in VERIFY_DOC mode
      if (mode === 'VERIFY_DOC' && (res.urls_found.length > 0 || res.is_upi_payment)) {
        offerScanRedirect(res);
        return;
      }

      setResult(res);
      setState('VERDICT');
    } catch (e: any) {
      setError(e.message || 'Scan failed. Try the Gallery option instead.');
      setState('CAMERA');
    }
  }, [mode, offerDocRedirect, offerScanRedirect]);

  // ── Camera capture ────────────────────────────────────────────────────────
  const handleCapture = useCallback(async () => {
    try {
      const permResult = await ImagePicker.requestCameraPermissionsAsync();
      if (!permResult.granted) { setError('Camera permission required.'); return; }
      const pickerResult = await ImagePicker.launchCameraAsync({
        mediaTypes: ['images'],
        quality: 1.0,
        allowsEditing: true,
        exif: false,
      });
      if (pickerResult.canceled || !pickerResult.assets?.[0]) return;
      const asset = pickerResult.assets[0];
      await processImage(asset.uri, 'qr_capture.jpg', asset.mimeType || 'image/jpeg');
    } catch (e: any) {
      setError(e.message || 'Capture failed.');
      setState('CAMERA');
    }
  }, [processImage]);

  // ── Gallery pick ──────────────────────────────────────────────────────────
  const handleGalleryPick = useCallback(async () => {
    try {
      const pickerResult = await ImagePicker.launchImageLibraryAsync({
        mediaTypes: ['images'],
        quality: 1.0,
        allowsEditing: true,
      });
      if (pickerResult.canceled || !pickerResult.assets?.[0]) return;
      const asset = pickerResult.assets[0];
      await processImage(asset.uri, asset.fileName || 'qr_gallery.jpg', asset.mimeType || 'image/jpeg');
    } catch (e: any) {
      setError(e.message || 'Gallery scan failed.');
      setState('CAMERA');
    }
  }, [processImage]);

  const handleRetry = useCallback(() => {
    setResult(null);
    setGovDocDetection(null);
    setError(null);
    setScanned(false);
    setState('CAMERA');
  }, []);

  // ── Mode toggle resets scanner ────────────────────────────────────────────
  const handleModeChange = useCallback((newMode: ScanMode) => {
    setMode(newMode);
    handleRetry();
  }, [handleRetry]);

  // ── Gov doc full-screen (replaces entire screen) ──────────────────────────
  if (state === 'GOV_DOC' && govDocDetection) {
    return (
      <GovDocVerifierScreen
        detection={govDocDetection}
        onClose={onClose}
        onScanAnother={handleRetry}
      />
    );
  }

  // ── Camera permission screen ──────────────────────────────────────────────
  if (!permission?.granted && state === 'CAMERA') {
    return (
      <View style={{ flex: 1, backgroundColor: C.bg, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
        <Ionicons name="camera-outline" size={64} color={C.frost4} />
        <Text style={{ color: C.frost, fontSize: 18, fontWeight: '700', marginTop: 20, textAlign: 'center' }}>Camera Access Required</Text>
        <Text style={{ color: 'rgba(255,255,255,0.5)', fontSize: 14, textAlign: 'center', marginTop: 10, lineHeight: 20 }}>SafeMail X needs camera access to scan QR codes.</Text>
        <TouchableOpacity style={{ backgroundColor: C.cyan, borderRadius: 16, paddingHorizontal: 32, paddingVertical: 14, marginTop: 24 }} onPress={requestPermission}>
          <Text style={{ color: '#000', fontSize: 15, fontWeight: '700' }}>Grant Camera Access</Text>
        </TouchableOpacity>
        <TouchableOpacity style={{ marginTop: 16 }} onPress={handleGalleryPick}>
          <Text style={{ color: C.cyan, fontSize: 14 }}>Or pick from Gallery</Text>
        </TouchableOpacity>
        <TouchableOpacity style={{ marginTop: 20 }} onPress={onClose}>
          <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 14 }}>Close</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const accentColor = mode === 'VERIFY_DOC' ? C.violet : C.cyan;

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      {/* Cross-route modal */}
      {crossRouteData && (
        <CrossRouteModal
          visible={crossRouteVisible}
          message={crossRouteData.message}
          actionLabel={crossRouteData.actionLabel}
          actionColor={crossRouteData.actionColor}
          onAccept={crossRouteData.onAccept}
          onDismiss={dismissCrossRoute}
        />
      )}

      {/* ── Header ────────────────────────────────────────────────────── */}
      <View style={styles.header}>
        <TouchableOpacity onPress={onClose} style={styles.backBtn}>
          <Ionicons name="chevron-back" size={20} color="rgba(255,255,255,0.7)" />
          <Text style={{ color: 'rgba(255,255,255,0.7)', fontSize: 15, marginLeft: 2 }}>Back</Text>
        </TouchableOpacity>

        {/* Live indicator */}
        <View style={[styles.livePill, { borderColor: `${accentColor}50`, backgroundColor: `${accentColor}12` }]}>
          <View style={[styles.liveDot, { backgroundColor: accentColor }]} />
          <Text style={[styles.liveText, { color: accentColor }]}>
            {mode === 'VERIFY_DOC' ? 'VERIFY DOC' : 'QR SCANNER'}
          </Text>
        </View>

        {/* Torch */}
        <TouchableOpacity style={{ width: 70, alignItems: 'flex-end' }} onPress={() => setTorch(!torch)}>
          <Ionicons name={torch ? 'flash' : 'flash-outline'} size={22} color={torch ? C.gold : 'rgba(255,255,255,0.4)'} />
        </TouchableOpacity>
      </View>

      {/* ── Mode Toggle ────────────────────────────────────────────────── */}
      {(state === 'CAMERA') && (
        <View style={{ paddingHorizontal: 20, paddingBottom: 4 }}>
          <ModeToggle mode={mode} onChange={handleModeChange} />
        </View>
      )}

      {/* ── Error Banner ────────────────────────────────────────────────── */}
      {error && (
        <View style={{ backgroundColor: 'rgba(255,61,113,0.15)', paddingHorizontal: 16, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: 'rgba(255,61,113,0.3)' }}>
          <Text style={{ color: C.rose, fontSize: 13 }}>{error}</Text>
        </View>
      )}

      {/* ── Content ──────────────────────────────────────────────────────── */}
      {state === 'ANALYZING' ? (
        <AnalyzingView mode={mode} />
      ) : state === 'VERDICT' && result ? (
        <VerdictView result={result} onRetry={handleRetry} onClose={onClose} />
      ) : (
        <View style={{ flex: 1 }}>
          <View style={{ flex: 1, overflow: 'hidden' }}>
            {permission?.granted ? (
              <CameraView
                style={{ flex: 1 }}
                facing="back"
                enableTorch={torch}
                barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
                onBarcodeScanned={scanned ? undefined : handleBarCodeScanned}
              >
                <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
                  <View style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.55)' }} />

                  {/* Instruction */}
                  <Text style={{ color: 'rgba(255,255,255,0.75)', fontSize: 14, fontWeight: '600', marginBottom: 24, zIndex: 10 }}>
                    {mode === 'VERIFY_DOC' ? 'Align the document QR within the frame' : 'Point camera at a QR code'}
                  </Text>

                  {/* Mode-specific frame */}
                  {mode === 'VERIFY_DOC' ? <DocFrame /> : <ScanFrame />}

                  {/* Contextual hint */}
                  <View style={{
                    marginTop: 20, zIndex: 10, paddingHorizontal: 20,
                    backgroundColor: `${accentColor}12`,
                    borderRadius: 12, borderWidth: 1,
                    borderColor: `${accentColor}30`,
                    paddingVertical: 10, marginHorizontal: 24,
                  }}>
                    <Text style={{ color: accentColor, fontSize: 11, fontWeight: '700', textAlign: 'center', marginBottom: 3 }}>
                      {mode === 'VERIFY_DOC' ? '🏛️ Document Verification Mode' : '📋 Security Scan Mode'}
                    </Text>
                    <Text style={{ color: 'rgba(255,255,255,0.6)', fontSize: 11, textAlign: 'center', lineHeight: 16 }}>
                      {mode === 'VERIFY_DOC'
                        ? 'Supports Aadhaar, DigiLocker, DL, CBSE & more.\nTap 📷 Capture to scan physical cards.'
                        : 'Scans for phishing URLs, UPI scams & threats.\nTap 📷 Capture for best accuracy.'}
                    </Text>
                  </View>

                  {/* Bottom controls: Flash | CAPTURE | Gallery */}
                  <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 32, gap: 20, zIndex: 10 }}>
                    <View style={{ width: 50 }} />

                    {/* Main capture button */}
                    <TouchableOpacity
                      style={{
                        width: 74, height: 74, borderRadius: 37,
                        backgroundColor: accentColor,
                        alignItems: 'center', justifyContent: 'center',
                        shadowColor: accentColor, shadowRadius: 14, shadowOpacity: 0.7, shadowOffset: { width: 0, height: 0 },
                        elevation: 10,
                      }}
                      onPress={handleCapture}
                    >
                      <Ionicons name={mode === 'VERIFY_DOC' ? 'shield-checkmark' : 'camera'} size={30} color="#000" />
                    </TouchableOpacity>

                    {/* Gallery */}
                    <TouchableOpacity
                      style={{ backgroundColor: 'rgba(255,255,255,0.1)', width: 50, height: 50, borderRadius: 25, alignItems: 'center', justifyContent: 'center' }}
                      onPress={handleGalleryPick}
                    >
                      <Ionicons name="images-outline" size={22} color="#fff" />
                    </TouchableOpacity>
                  </View>

                  <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 11, marginTop: 10, zIndex: 10 }}>
                    {mode === 'VERIFY_DOC' ? '🛡️ Capture  ·  🖼️ Gallery' : '📷 Capture  ·  🖼️ Gallery'}
                  </Text>
                </View>
              </CameraView>
            ) : (
              <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
                <Text style={{ color: C.frost4 }}>Camera not available</Text>
              </View>
            )}
          </View>
        </View>
      )}
    </View>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const styles = StyleSheet.create({
  header: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
    paddingHorizontal: 16, paddingBottom: 12,
    borderBottomWidth: 1, borderBottomColor: 'rgba(255,255,255,0.06)',
  },
  backBtn: { flexDirection: 'row', alignItems: 'center', width: 70 },
  livePill: {
    flexDirection: 'row', alignItems: 'center',
    paddingHorizontal: 14, paddingVertical: 6,
    borderRadius: 20, borderWidth: 1, gap: 6,
  },
  liveDot: { width: 6, height: 6, borderRadius: 3, shadowRadius: 4, shadowOpacity: 1 },
  liveText: { fontSize: 11, fontWeight: '700', letterSpacing: 1.5 },
  toggleContainer: {
    flexDirection: 'row', height: 44,
    backgroundColor: 'rgba(255,255,255,0.06)',
    borderRadius: 22, borderWidth: 1, borderColor: 'rgba(255,255,255,0.1)',
    overflow: 'hidden', position: 'relative',
    marginBottom: 8,
  },
  togglePill: {
    position: 'absolute', top: 3, bottom: 3, width: '50%',
    backgroundColor: 'rgba(255,255,255,0.92)',
    borderRadius: 18,
  },
  toggleOption: {
    flex: 1, flexDirection: 'row', alignItems: 'center', justifyContent: 'center',
    zIndex: 1,
  },
  toggleLabel: {
    fontSize: 13, fontWeight: '600', color: 'rgba(255,255,255,0.45)',
  },
  toggleLabelActive: {
    color: '#06080f',
  },
});
