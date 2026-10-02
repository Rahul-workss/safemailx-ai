import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView,
  Animated, Linking, Dimensions, Image, Alert, Platform,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { CameraView, useCameraPermissions, BarcodeScanningResult } from 'expo-camera';
import * as ImagePicker from 'expo-image-picker';
import { scanQrCode, scanUrl, QRScanResult } from '../api';
import { detectGovDocType, type GovDocDetectResult } from '../services/govDocDetector';
import GovDocVerifierScreen from './GovDocVerifierScreen';


const { width: SW, height: SH } = Dimensions.get('window');

const C = {
  bg: '#06080f',
  surface: 'rgba(255,255,255,0.05)',
  border: 'rgba(255,255,255,0.09)',
  cyan: '#00f3ff',
  violet: '#8c52ff',
  rose: '#ff3d71',
  gold: '#ffaa00',
  green: '#34c759',
  frost: '#e8eaf0',
  frost4: '#4a5568',
};

type ScreenState = 'CAMERA' | 'ANALYZING' | 'VERDICT' | 'NO_PERMISSION' | 'GOV_DOC';


// ─── Glassmorphic Card ────────────────────────────────────────────────────────
function GlassCard({ children, style }: { children: React.ReactNode; style?: any }) {
  return <View style={[gs.card, style]}>{children}</View>;
}
const gs = StyleSheet.create({
  card: {
    backgroundColor: 'rgba(255,255,255,0.05)',
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.1)',
    padding: 20,
  },
});

// ─── Animated Scan Frame ──────────────────────────────────────────────────────
function ScanFrame() {
  const pulse = useRef(new Animated.Value(0.4)).current;
  const sweep = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.loop(Animated.sequence([
      Animated.timing(pulse, { toValue: 0.9, duration: 1200, useNativeDriver: true }),
      Animated.timing(pulse, { toValue: 0.4, duration: 1200, useNativeDriver: true }),
    ])).start();
    Animated.loop(
      Animated.timing(sweep, { toValue: 1, duration: 2000, useNativeDriver: true })
    ).start();
  }, []);

  const FRAME = SW * 0.65;
  const CORNER = 30;
  const sweepY = sweep.interpolate({
    inputRange: [0, 1],
    outputRange: [0, FRAME - 4],
  });

  const cornerStyle = (pos: any) => ({
    position: 'absolute' as const,
    width: CORNER,
    height: CORNER,
    ...pos,
  });

  return (
    <View style={{ width: FRAME, height: FRAME, alignSelf: 'center' }}>
      {/* Corners */}
      <Animated.View style={[cornerStyle({ top: 0, left: 0 }), { borderTopWidth: 3, borderLeftWidth: 3, borderColor: C.cyan, borderTopLeftRadius: 12, opacity: pulse }]} />
      <Animated.View style={[cornerStyle({ top: 0, right: 0 }), { borderTopWidth: 3, borderRightWidth: 3, borderColor: C.cyan, borderTopRightRadius: 12, opacity: pulse }]} />
      <Animated.View style={[cornerStyle({ bottom: 0, left: 0 }), { borderBottomWidth: 3, borderLeftWidth: 3, borderColor: C.cyan, borderBottomLeftRadius: 12, opacity: pulse }]} />
      <Animated.View style={[cornerStyle({ bottom: 0, right: 0 }), { borderBottomWidth: 3, borderRightWidth: 3, borderColor: C.cyan, borderBottomRightRadius: 12, opacity: pulse }]} />

      {/* Sweep line */}
      <Animated.View style={{
        position: 'absolute', left: 8, right: 8, height: 2,
        backgroundColor: C.cyan, opacity: 0.7,
        transform: [{ translateY: sweepY }],
        shadowColor: C.cyan, shadowRadius: 10, shadowOpacity: 0.8,
      }} />
    </View>
  );
}

// ─── Analyzing View ───────────────────────────────────────────────────────────
function AnalyzingView() {
  const spin = useRef(new Animated.Value(0)).current;
  const pulse = useRef(new Animated.Value(0.8)).current;

  useEffect(() => {
    Animated.loop(Animated.timing(spin, { toValue: 1, duration: 1800, useNativeDriver: true })).start();
    Animated.loop(Animated.sequence([
      Animated.timing(pulse, { toValue: 1.1, duration: 800, useNativeDriver: true }),
      Animated.timing(pulse, { toValue: 0.8, duration: 800, useNativeDriver: true }),
    ])).start();
  }, []);

  const rotate = spin.interpolate({ inputRange: [0, 1], outputRange: ['0deg', '360deg'] });

  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <Animated.View style={{ transform: [{ rotate }, { scale: pulse }] }}>
        <View style={{ width: 90, height: 90, borderRadius: 45, borderWidth: 2, borderColor: C.cyan, borderTopColor: 'transparent', alignItems: 'center', justifyContent: 'center', shadowColor: C.cyan, shadowRadius: 20, shadowOpacity: 0.6 }}>
          <Ionicons name="qr-code" size={32} color={C.cyan} />
        </View>
      </Animated.View>
      <Text style={{ fontSize: 26, fontWeight: '700', color: '#fff', marginTop: 32, marginBottom: 8, textAlign: 'center' }}>Analyzing QR Code</Text>
      <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 14, textAlign: 'center' }}>Decoding & checking for threats...</Text>
      {['QR Decode', 'URL Extract', 'Phishing Check', 'UPI Scam Detect', 'Verdict'].map((layer, i) => (
        <Text key={i} style={{ color: 'rgba(0,243,255,0.4)', fontSize: 11, marginTop: 6, letterSpacing: 0.8 }}>
          ▶ {layer}
        </Text>
      ))}
    </View>
  );
}

// ─── Verdict View ─────────────────────────────────────────────────────────────
function VerdictView({ result, onRetry, onClose }: { result: QRScanResult; onRetry: () => void; onClose: () => void }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(40)).current;
  const scoreAnim = useRef(new Animated.Value(0)).current;
  const [displayScore, setDisplayScore] = useState(0);

  const isDangerous = result.overall_verdict === 'dangerous';
  const isSuspicious = result.overall_verdict === 'suspicious';
  const isSafe = result.overall_verdict === 'safe';
  const noQr = result.overall_verdict === 'no_qr_found';

  const color = isDangerous ? C.rose : isSuspicious ? C.gold : C.green;
  const label = isDangerous ? '🔴 DANGEROUS'
    : isSuspicious ? '🟡 SUSPICIOUS'
    : noQr ? '⚪ NO QR FOUND'
    : '🟢 SAFE';

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
      {/* Score circle */}
      <View style={{ alignItems: 'center', marginBottom: 28 }}>
        <View style={{ width: 130, height: 130, borderRadius: 65, backgroundColor: `${color}18`, borderWidth: 2, borderColor: color, alignItems: 'center', justifyContent: 'center', shadowColor: color, shadowRadius: 24, shadowOpacity: 0.6, marginBottom: 16 }}>
          <Ionicons name="qr-code" size={28} color={color} style={{ marginBottom: 4 }} />
          <Text style={{ fontSize: 32, fontWeight: '800', color }}>{displayScore}</Text>
          <Text style={{ fontSize: 9, color: 'rgba(255,255,255,0.5)', letterSpacing: 1 }}>RISK SCORE</Text>
        </View>
        <Text style={{ fontSize: 20, fontWeight: '800', color, letterSpacing: 0.5 }}>{label}</Text>
      </View>

      {/* Summary */}
      <GlassCard style={{ marginBottom: 16, borderColor: `${color}40` }}>
        <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
          <Ionicons name="shield-checkmark" size={16} color={color} style={{ marginRight: 8 }} />
          <Text style={{ color, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Verdict</Text>
        </View>
        <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 14, lineHeight: 21 }}>{result.summary}</Text>
      </GlassCard>

      {/* QR codes found */}
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

      {/* UPI Payment Alert */}
      {result.is_upi_payment && result.upi_details && (
        <GlassCard style={{ marginBottom: 16, borderColor: 'rgba(255,170,0,0.4)' }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
            <Text style={{ fontSize: 18, marginRight: 8 }}>💳</Text>
            <Text style={{ color: C.gold, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>UPI Payment QR Detected</Text>
          </View>
          <View style={{ gap: 6 }}>
            {result.upi_details.payee_name && (
              <Text style={{ color: 'rgba(255,255,255,0.8)', fontSize: 13 }}>
                <Text style={{ fontWeight: '700', color: C.frost }}>Payee: </Text>{result.upi_details.payee_name}
              </Text>
            )}
            {result.upi_details.payee_vpa && (
              <Text style={{ color: 'rgba(255,255,255,0.8)', fontSize: 13 }}>
                <Text style={{ fontWeight: '700', color: C.frost }}>UPI ID: </Text>{result.upi_details.payee_vpa}
              </Text>
            )}
            {result.upi_details.amount && (
              <Text style={{ color: C.rose, fontSize: 16, fontWeight: '800', marginTop: 4 }}>
                Amount: ₹{result.upi_details.amount}
              </Text>
            )}
            {result.upi_details.note && (
              <Text style={{ color: 'rgba(255,255,255,0.6)', fontSize: 12, fontStyle: 'italic', marginTop: 2 }}>
                Note: {result.upi_details.note}
              </Text>
            )}
          </View>
          <View style={{ backgroundColor: 'rgba(255,61,113,0.1)', padding: 10, borderRadius: 10, marginTop: 12 }}>
            <Text style={{ color: C.rose, fontSize: 12, fontWeight: '600' }}>
              ⚠️ Never scan & pay QR codes from unknown callers or messages. Scammers use QR codes to steal money.
            </Text>
          </View>
        </GlassCard>
      )}

      {/* URL Verdicts */}
      {result.url_verdicts.length > 0 && (
        <GlassCard style={{ marginBottom: 16 }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 14 }}>
            <Ionicons name="globe-outline" size={16} color={C.violet} style={{ marginRight: 8 }} />
            <Text style={{ color: C.violet, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>URL Analysis</Text>
          </View>
          {result.url_verdicts.filter(v => !v.url.startsWith('upi://')).map((v, i) => {
            const vc = v.verdict === 'phishing' ? C.rose : v.verdict === 'suspicious' ? C.gold : C.green;
            return (
              <View key={i} style={{ marginBottom: 14, paddingLeft: 10, borderLeftWidth: 2, borderLeftColor: vc }}>
                <Text style={{ color: 'rgba(255,255,255,0.8)', fontSize: 12, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' }} numberOfLines={1}>{v.url}</Text>
                <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 6, gap: 8 }}>
                  <View style={{ backgroundColor: `${vc}20`, paddingHorizontal: 8, paddingVertical: 3, borderRadius: 10 }}>
                    <Text style={{ color: vc, fontSize: 10, fontWeight: '700', textTransform: 'uppercase' }}>{v.verdict}</Text>
                  </View>
                  <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: 10 }}>{Math.round(v.risk_score * 100)}% risk</Text>
                </View>
                {v.summary ? (
                  <Text style={{ color: 'rgba(255,255,255,0.6)', fontSize: 12, marginTop: 6, lineHeight: 18 }}>{v.summary}</Text>
                ) : null}
              </View>
            );
          })}
        </GlassCard>
      )}

      {/* CTAs */}
      {isDangerous && (
        <TouchableOpacity style={{ backgroundColor: C.rose, borderRadius: 16, padding: 16, alignItems: 'center', marginBottom: 12 }}>
          <Text style={{ color: '#fff', fontSize: 16, fontWeight: '700' }}>🚫 Do NOT Open This Link</Text>
        </TouchableOpacity>
      )}
      <TouchableOpacity style={{ backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: 16, padding: 16, alignItems: 'center', marginBottom: 12 }} onPress={onRetry}>
        <Text style={{ color: 'rgba(255,255,255,0.7)', fontSize: 15, fontWeight: '600' }}>Scan Another QR</Text>
      </TouchableOpacity>
      <TouchableOpacity style={{ alignItems: 'center', padding: 12 }} onPress={onClose}>
        <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 15 }}>Close</Text>
      </TouchableOpacity>
    </Animated.ScrollView>
  );
}

// ─── Main QR Scanner Screen ──────────────────────────────────────────────────
export default function QRScannerScreen({ onClose }: { onClose: () => void }) {
  const [permission, requestPermission] = useCameraPermissions();
  const [state, setState] = useState<ScreenState>('CAMERA');
  const [result, setResult] = useState<QRScanResult | null>(null);
  const [govDocDetection, setGovDocDetection] = useState<GovDocDetectResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanned, setScanned] = useState(false);
  const [torch, setTorch] = useState(false);


  useEffect(() => {
    if (!permission?.granted) {
      requestPermission();
    }
  }, []);


  const handleBarCodeScanned = useCallback(async (scanResult: BarcodeScanningResult) => {
    if (scanned) return;
    setScanned(true);

    const data = scanResult.data;

    // ── Fast-path: gov doc detection (sync, no ANALYZING flash needed) ────────
    if (!data.toLowerCase().startsWith('upi://pay') &&
        !data.startsWith('http://') &&
        !data.startsWith('https://')) {
      const govDetection = detectGovDocType(data);
      if (govDetection.isGovDoc) {
        setGovDocDetection(govDetection);
        setState('GOV_DOC');
        return;
      }
    }

    setState('ANALYZING');

    try {
      // Quick local check first for UPI
      if (data.toLowerCase().startsWith('upi://pay')) {
        // Parse UPI locally for instant feedback, then confirm with backend
        const params = new URLSearchParams(data.split('?')[1] || '');
        setResult({
          qr_codes_found: 1,
          decoded_payloads: [data],
          urls_found: [],
          non_url_payloads: [],
          url_verdicts: [{
            url: data,
            verdict: 'suspicious',
            risk_score: 0.65,
            summary: `UPI payment QR. Payee: ${params.get('pn') || '?'} (${params.get('pa') || '?'})${params.get('am') ? `, Amount: Rs.${params.get('am')}` : ''}. Verify before paying.`,
          }],
          overall_verdict: 'suspicious',
          overall_risk_score: 0.65,
          summary: 'WARNING: This is a payment QR code. Never pay via QR from unknown sources.',
          is_upi_payment: true,
          upi_details: {
            raw: data,
            payee_name: params.get('pn') || 'Unknown',
            payee_vpa: params.get('pa') || 'Unknown',
            amount: params.get('am'),
            note: params.get('tn'),
          },
        });
        setState('VERDICT');
        return;
      }

      // For URLs, first check if it's a government document URL
      if (data.startsWith('http://') || data.startsWith('https://')) {
        const govCheck = detectGovDocType(data);
        if (govCheck.isGovDoc) {
          setGovDocDetection(govCheck);
          setState('GOV_DOC');
          return;
        }

        // We'll create a simple QR image and send to backend
        // Actually, use the file scan approach — upload a dummy image
        // For now, construct a client-side result and use URL scan if available
        try {
          const urlResult = await scanUrl(data);
          const normScore = urlResult.risk_score / 100;
          const verdict = urlResult.verdict === 'phishing' ? 'dangerous'
            : urlResult.verdict === 'suspicious' ? 'suspicious' : 'safe';
          setResult({
            qr_codes_found: 1,
            decoded_payloads: [data],
            urls_found: [data],
            non_url_payloads: [],
            url_verdicts: [{
              url: data,
              verdict: urlResult.verdict,
              risk_score: normScore,
              summary: urlResult.summary,
            }],
            overall_verdict: verdict,
            overall_risk_score: normScore,
            summary: urlResult.summary,
            is_upi_payment: false,
            upi_details: null,
          });
        } catch {
          // If URL scan fails, still show what we found
          setResult({
            qr_codes_found: 1,
            decoded_payloads: [data],
            urls_found: [data],
            non_url_payloads: [],
            url_verdicts: [{
              url: data,
              verdict: 'unknown',
              risk_score: 0.3,
              summary: 'URL found but could not be analyzed. Proceed with caution.',
            }],
            overall_verdict: 'suspicious',
            overall_risk_score: 0.3,
            summary: 'QR code contains a URL that could not be fully analyzed.',
            is_upi_payment: false,
            upi_details: null,
          });
        }
        setState('VERDICT');
        return;
      }

      // ── Government Document Detection ────────────────────────────────────
      // Runs on any non-URL, non-UPI QR data (Aadhaar, DigiLocker, DL, CBSE etc.)
      // Also runs on .gov.in URLs to provide enhanced verification UI.
      const govDetection = detectGovDocType(data);
      if (govDetection.isGovDoc) {
        setGovDocDetection(govDetection);
        setState('GOV_DOC');
        return;
      }

      // Non-URL, non-UPI, non-gov QR data
      setResult({
        qr_codes_found: 1,
        decoded_payloads: [data],
        urls_found: [],
        non_url_payloads: [data],
        url_verdicts: [],
        overall_verdict: 'safe',
        overall_risk_score: 0,
        summary: `QR code contains text data: "${data.substring(0, 100)}"`,
        is_upi_payment: false,
        upi_details: null,
      });
      setState('VERDICT');
    } catch (e: any) {
      setError(e.message || 'QR analysis failed');
      setState('CAMERA');
      setScanned(false);
    }
  }, [scanned]);

  // ── Capture still photo → backend pyzbar decode ───────────────────────────
  // WHY NOT cameraRef.takePictureAsync():
  //   CameraView (expo-camera v17) is a class component that wires its own
  //   internal _cameraRef. The public class ref doesn't reliably expose
  //   takePictureAsync() in the current Expo SDK 54 build on Android.
  //
  // SOLUTION: ImagePicker.launchCameraAsync() — opens the native Android camera
  //   app at full sensor resolution (12-48 MP). No internal ref needed.
  //   The returned photo URI goes straight to scanQrCode() → backend pyzbar.
  //   This is the same pipeline as gallery — just triggered from the camera.
  const handleCapture = useCallback(async () => {
    try {
      // Request camera permission if not already granted (usually already done)
      const permResult = await ImagePicker.requestCameraPermissionsAsync();
      if (!permResult.granted) {
        setError('Camera permission required to capture a photo.');
        return;
      }

      const pickerResult = await ImagePicker.launchCameraAsync({
        mediaTypes: ['images'],
        quality: 1.0,           // full sensor resolution
        allowsEditing: true,    // ENABLE CROP: drastically improves dense QR detection by removing background
        exif: false,
      });

      if (pickerResult.canceled || !pickerResult.assets?.[0]) return;

      setState('ANALYZING');
      const asset = pickerResult.assets[0];

      const res = await scanQrCode({
        uri: asset.uri,
        name: 'qr_capture.jpg',
        mimeType: asset.mimeType || 'image/jpeg',
      });

      // ── Route through gov doc detector ───────────────────────────────────
      const allPayloads = [
        ...(res.decoded_payloads || []),
        ...(res.non_url_payloads || []),
      ];
      for (const payload of allPayloads) {
        const govDetection = detectGovDocType(payload);
        if (govDetection.isGovDoc) {
          setGovDocDetection(govDetection);
          setState('GOV_DOC');
          return;
        }
      }

      if (res.qr_codes_found === 0) {
        setError('No QR code found. Hold the camera 10–15 cm from the QR, ensure good lighting, then try again.');
        setState('CAMERA');
        return;
      }

      setResult(res);
      setState('VERDICT');
    } catch (e: any) {
      setError(e.message || 'Capture failed. Try the 🖼️ Gallery option instead.');
      setState('CAMERA');
    }
  }, []);

  const handleGalleryPick = useCallback(async () => {
    try {
      const pickerResult = await ImagePicker.launchImageLibraryAsync({
        mediaTypes: ['images'],
        quality: 1.0,           // Max quality — Aadhaar QR is dense, needs full res
        allowsEditing: true,    // ENABLE CROP: allows zooming in on QR code
      });
      if (pickerResult.canceled || !pickerResult.assets?.[0]) return;

      setState('ANALYZING');
      const asset = pickerResult.assets[0];
      const res = await scanQrCode({
        uri: asset.uri,
        name: asset.fileName || 'qr_gallery.jpg',
        mimeType: asset.mimeType || 'image/jpeg',
      });

      // ── Gov doc detection on decoded payloads ────────────────────────────
      // CRITICAL: gallery scans also need to route through the gov doc verifier.
      // Without this, scanning an Aadhaar image from gallery shows generic verdict.
      const allPayloads = [
        ...(res.decoded_payloads || []),
        ...(res.non_url_payloads || []),
      ];
      for (const payload of allPayloads) {
        const govDetection = detectGovDocType(payload);
        if (govDetection.isGovDoc) {
          setGovDocDetection(govDetection);
          setState('GOV_DOC');
          return;
        }
      }

      setResult(res);
      setState('VERDICT');
    } catch (e: any) {
      setError(e.message || 'Gallery QR scan failed');
      setState('CAMERA');
    }
  }, []);


  const handleRetry = useCallback(() => {
    setResult(null);
    setGovDocDetection(null);
    setError(null);
    setScanned(false);
    setState('CAMERA');
  }, []);

  // ── Early returns (all hooks above must fire first) ──────────────────────────

  // Gov doc: full-screen verifier — renders its own header, no QR Scanner chrome needed
  if (state === 'GOV_DOC' && govDocDetection) {
    return (
      <GovDocVerifierScreen
        detection={govDocDetection}
        onClose={onClose}
        onScanAnother={handleRetry}
      />
    );
  }

  // No camera permission

  if (!permission?.granted && state === 'CAMERA') {
    return (
      <View style={{ flex: 1, backgroundColor: C.bg, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
        <Ionicons name="camera-outline" size={64} color={C.frost4} />
        <Text style={{ color: C.frost, fontSize: 18, fontWeight: '700', marginTop: 20, textAlign: 'center' }}>Camera Access Required</Text>
        <Text style={{ color: 'rgba(255,255,255,0.5)', fontSize: 14, textAlign: 'center', marginTop: 10, lineHeight: 20 }}>
          SafeMail X needs camera access to scan QR codes for phishing threats.
        </Text>
        <TouchableOpacity
          style={{ backgroundColor: C.cyan, borderRadius: 16, paddingHorizontal: 32, paddingVertical: 14, marginTop: 24 }}
          onPress={requestPermission}
        >
          <Text style={{ color: '#000', fontSize: 15, fontWeight: '700' }}>Grant Camera Access</Text>
        </TouchableOpacity>
        <TouchableOpacity style={{ marginTop: 16 }} onPress={handleGalleryPick}>
          <Text style={{ color: C.cyan, fontSize: 14 }}>Or pick from gallery instead</Text>
        </TouchableOpacity>
        <TouchableOpacity style={{ marginTop: 20 }} onPress={onClose}>
          <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 14 }}>Close</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      {/* Header */}
      <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 16, paddingBottom: 16, borderBottomWidth: 1, borderBottomColor: 'rgba(255,255,255,0.06)' }}>
        <TouchableOpacity onPress={onClose} style={{ flexDirection: 'row', alignItems: 'center', width: 70 }}>
          <Ionicons name="chevron-back" size={20} color="rgba(255,255,255,0.7)" />
          <Text style={{ color: 'rgba(255,255,255,0.7)', fontSize: 15, marginLeft: 2 }}>Back</Text>
        </TouchableOpacity>
        <View style={{ flexDirection: 'row', alignItems: 'center', backgroundColor: 'rgba(0,243,255,0.1)', paddingHorizontal: 14, paddingVertical: 6, borderRadius: 20, borderWidth: 1, borderColor: 'rgba(0,243,255,0.3)', gap: 8 }}>
          <View style={{ width: 6, height: 6, borderRadius: 3, backgroundColor: C.cyan, shadowColor: C.cyan, shadowRadius: 4, shadowOpacity: 1 }} />
          <Text style={{ color: C.cyan, fontSize: 11, fontWeight: '700', letterSpacing: 1.5 }}>QR SCANNER</Text>
        </View>
        <View style={{ width: 70 }} />
      </View>

      {/* Error banner */}
      {error && (
        <View style={{ backgroundColor: 'rgba(255,61,113,0.15)', paddingHorizontal: 16, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: 'rgba(255,61,113,0.3)' }}>
          <Text style={{ color: C.rose, fontSize: 13 }}>{error}</Text>
        </View>
      )}

      {/* Content */}
      {state === 'ANALYZING' ? (
        <AnalyzingView />
      ) : state === 'VERDICT' && result ? (
        <VerdictView result={result} onRetry={handleRetry} onClose={onClose} />
      ) : (
        <View style={{ flex: 1 }}>
          {/* Camera */}
          <View style={{ flex: 1, overflow: 'hidden', borderRadius: 0 }}>
            {permission?.granted ? (
              <CameraView
                style={{ flex: 1 }}
                facing="back"
                enableTorch={torch}
                barcodeScannerSettings={{
                  barcodeTypes: ['qr'],
                }}
                onBarcodeScanned={scanned ? undefined : handleBarCodeScanned}
              >
                {/* Overlay */}
                <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
                  {/* Dark overlay with cutout */}
                  <View style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.55)' }} />

                  {/* Instruction */}
                  <Text style={{ color: 'rgba(255,255,255,0.7)', fontSize: 14, fontWeight: '600', marginBottom: 24, zIndex: 10 }}>
                    Point camera at a QR code
                  </Text>

                  {/* Scan frame */}
                  <ScanFrame />

                  {/* Aadhaar dense QR tip */}
                  <View style={{
                    marginTop: 20, zIndex: 10, paddingHorizontal: 20,
                    backgroundColor: 'rgba(0,243,255,0.08)',
                    borderRadius: 12, borderWidth: 1,
                    borderColor: 'rgba(0,243,255,0.2)',
                    paddingVertical: 10, marginHorizontal: 24,
                  }}>
                    <Text style={{ color: C.cyan, fontSize: 11, fontWeight: '700', textAlign: 'center', marginBottom: 3 }}>
                      📋 Scanning Aadhaar Card?
                    </Text>
                    <Text style={{ color: 'rgba(255,255,255,0.6)', fontSize: 11, textAlign: 'center', lineHeight: 16 }}>
                      Aadhaar QR is very dense. Hold steady 10–15 cm away.{'\n'}
                      Tap 📷 <Text style={{ color: C.cyan, fontWeight: '700' }}>Capture</Text> for best results — or use 🖼️ Gallery.
                    </Text>
                  </View>

                  {/* Bottom controls — Flash | CAPTURE | Gallery */}
                  <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 32, gap: 20, zIndex: 10 }}>

                    {/* Flash */}
                    <TouchableOpacity
                      style={{ alignItems: 'center', backgroundColor: 'rgba(255,255,255,0.1)', width: 50, height: 50, borderRadius: 25, justifyContent: 'center' }}
                      onPress={() => setTorch(!torch)}
                    >
                      <Ionicons name={torch ? 'flash' : 'flash-outline'} size={22} color={torch ? C.gold : '#fff'} />
                    </TouchableOpacity>

                    {/* CAPTURE — prominent center button */}
                    <TouchableOpacity
                      style={{
                        alignItems: 'center', justifyContent: 'center',
                        width: 70, height: 70, borderRadius: 35,
                        backgroundColor: C.cyan,
                        shadowColor: C.cyan, shadowRadius: 12, shadowOpacity: 0.6, shadowOffset: { width: 0, height: 0 },
                        elevation: 8,
                      }}
                      onPress={handleCapture}
                    >
                      <Ionicons name="camera" size={30} color="#000" />
                    </TouchableOpacity>

                    {/* Gallery */}
                    <TouchableOpacity
                      style={{ alignItems: 'center', backgroundColor: 'rgba(255,255,255,0.1)', width: 50, height: 50, borderRadius: 25, justifyContent: 'center' }}
                      onPress={handleGalleryPick}
                    >
                      <Ionicons name="images-outline" size={22} color="#fff" />
                    </TouchableOpacity>
                  </View>

                  <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 11, marginTop: 10, zIndex: 10 }}>
                    📷 Capture  ·  🖼️ Gallery
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
