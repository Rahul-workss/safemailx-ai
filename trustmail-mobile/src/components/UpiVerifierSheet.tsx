/**
 * SafeMail X — UPI Verifier Sheet (Assistive Touch)
 * Liquid glass theme — matches App.tsx TmCard exactly.
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  Animated, Keyboard, StyleSheet, Text,
  TextInput, TouchableOpacity, View,
} from 'react-native';
import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import { TM } from './LiquidGlass';

const KNOWN_HANDLES: Record<string, string> = {
  oksbi: 'State Bank of India', okhdfcbank: 'HDFC Bank', okaxis: 'Axis Bank',
  okicici: 'ICICI Bank', ybl: 'Yes Bank (PhonePe)', ibl: 'IndusInd Bank',
  axl: 'Axis Bank (PhonePe)', upi: 'BHIM / NPCI', paytm: 'Paytm',
  apl: 'Amazon Pay', kotak: 'Kotak Mahindra', airtel: 'Airtel Payments Bank',
  freecharge: 'Freecharge', jupiteraxis: 'Jupiter (Axis)',
  pnb: 'Punjab National Bank', cnrb: 'Canara Bank',
  barodampay: 'Bank of Baroda', mahb: 'Bank of Maharashtra',
  nsdl: 'NSDL Payments Bank', ikwik: 'iKwik', sliceaxis: 'Slice',
  rajgovhdfcbank: 'Rajasthan Govt (HDFC)',
};

const SCAM_PATTERNS = [
  /support$/i, /helpdesk$/i, /customercare$/i, /refund$/i,
  /prize$/i, /win(ner)?$/i, /lottery$/i, /reward$/i,
  /tax(dept)?$/i, /uidai$/i, /incometax$/i, /pmcare/i,
  /covidrelief$/i, /emi$/i,
];

interface UpiResult {
  valid: boolean; username: string; handle: string;
  bank: string | null; suspicious: boolean; reasons: string[];
  color: string; icon: keyof typeof Ionicons.glyphMap; verdict: string;
}

function analyzeUpi(raw: string): UpiResult {
  const reasons: string[] = [];
  const upi = raw.trim().toLowerCase();
  const parts = upi.split('@');

  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return {
      valid: false, username: '', handle: '', bank: null,
      suspicious: false, reasons: ['Invalid UPI format. Should be username@handle'],
      color: TM.rose, icon: 'close-circle', verdict: 'INVALID FORMAT',
    };
  }

  const [username, handle] = parts;
  const bank = KNOWN_HANDLES[handle] || null;
  if (!bank) reasons.push(`Unknown handle "@${handle}" — not a recognized bank/app`);

  let suspicious = false;
  for (const p of SCAM_PATTERNS) {
    if (p.test(username)) {
      suspicious = true;
      reasons.push(`Username "${username}" matches known scam patterns`);
      break;
    }
  }
  if (username.length < 3) reasons.push('Username is unusually short');
  if (/\d{10,}/.test(username)) reasons.push('Long number in username — common in temporary scam VPAs');

  const color = suspicious ? TM.rose : !bank ? TM.gold : TM.emerald;
  const icon: keyof typeof Ionicons.glyphMap = suspicious ? 'warning' : !bank ? 'help-circle-outline' : 'shield-checkmark';
  const verdict = suspicious ? 'SUSPICIOUS' : !bank ? 'UNVERIFIED HANDLE' : 'LOOKS LEGITIMATE';

  return { valid: true, username, handle, bank, suspicious, reasons, color, icon, verdict };
}

interface Props { visible: boolean; onClose: () => void; initialUpi?: string; }

export default function UpiVerifierSheet({ visible, onClose, initialUpi }: Props) {
  const [upiId, setUpiId] = useState(initialUpi || '');
  const [result, setResult] = useState<UpiResult | null>(null);
  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(24)).current;
  const inputRef = useRef<TextInput>(null);

  useEffect(() => {
    if (visible) {
      setUpiId(initialUpi || ''); setResult(null);
      Animated.parallel([
        Animated.timing(fadeIn, { toValue: 1, duration: 220, useNativeDriver: true }),
        Animated.spring(slideUp, { toValue: 0, tension: 80, friction: 10, useNativeDriver: true }),
      ]).start(() => { if (!initialUpi) inputRef.current?.focus(); });
      if (initialUpi) setResult(analyzeUpi(initialUpi));
    } else {
      Animated.parallel([
        Animated.timing(fadeIn, { toValue: 0, duration: 150, useNativeDriver: true }),
        Animated.timing(slideUp, { toValue: 24, duration: 150, useNativeDriver: true }),
      ]).start();
    }
  }, [visible, initialUpi]);

  if (!visible) return null;

  return (
    <Animated.View style={[S.shell, { opacity: fadeIn, transform: [{ translateY: slideUp }] }]}>
      <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
      <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.40)' }]} />
      <LinearGradient
        colors={['rgba(255,255,255,0.08)','rgba(255,255,255,0.01)','rgba(255,255,255,0.00)','rgba(255,255,255,0.03)']}
        start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
        style={StyleSheet.absoluteFillObject}
      />
      <View style={S.shimmer} />

      <View style={S.header}>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          <View style={[S.iconRing, { borderColor: `${TM.emerald}80`, backgroundColor: 'rgba(111,217,184,0.12)' }]}>
            <Ionicons name="cash-outline" size={13} color={TM.emerald} />
          </View>
          <Text style={[S.title, { color: TM.emerald }]}>UPI VERIFIER</Text>
        </View>
        <TouchableOpacity onPress={onClose} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
          <Ionicons name="close" size={18} color={TM.frost4} />
        </TouchableOpacity>
      </View>

      <LinearGradient
        colors={['transparent', `${TM.emerald}30`, 'transparent']}
        start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }}
        style={{ height: 1, marginBottom: 6 }}
      />
      <Text style={S.subtitle}>Verify a UPI ID before sending money</Text>

      <View style={S.inputRow}>
        <View style={S.inputWrap}>
          <BlurView intensity={18} tint="dark" style={StyleSheet.absoluteFillObject} />
          <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.25)', borderRadius: 14 }]} />
          <View style={S.inputShimmer} />
          <TextInput
            ref={inputRef}
            style={S.input}
            placeholder="name@upi or name@paytm"
            placeholderTextColor="rgba(242,234,253,0.25)"
            value={upiId}
            onChangeText={t => { setUpiId(t); setResult(null); }}
            keyboardType="email-address"
            autoCapitalize="none"
            returnKeyType="done"
            onSubmitEditing={() => { if (upiId.trim()) { Keyboard.dismiss(); setResult(analyzeUpi(upiId.trim())); } }}
          />
        </View>
        <TouchableOpacity
          style={S.checkBtn} activeOpacity={0.82}
          onPress={() => { if (upiId.trim()) { Keyboard.dismiss(); setResult(analyzeUpi(upiId.trim())); } }}
        >
          <LinearGradient colors={[TM.violetSoft, TM.violet, TM.ink3]} style={S.checkBtnGrad}>
            <Ionicons name="checkmark-sharp" size={17} color={TM.frost} />
          </LinearGradient>
        </TouchableOpacity>
      </View>

      {result && (
        <View style={[S.resultCard, { borderColor: `${result.color}40` }]}>
          <BlurView intensity={16} tint="dark" style={StyleSheet.absoluteFillObject} />
          <View style={[StyleSheet.absoluteFillObject, { backgroundColor: `${result.color}10`, borderRadius: 16 }]} />
          <View style={S.resultTop}>
            <Ionicons name={result.icon} size={22} color={result.color} />
            <View style={{ flex: 1 }}>
              <Text style={[S.verdict, { color: result.color }]}>{result.verdict}</Text>
              {result.bank
                ? <Text style={S.bankText}>Bank: {result.bank}</Text>
                : result.valid
                ? <Text style={S.bankText}>Handle "@{result.handle}" not in verified list</Text>
                : null}
            </View>
          </View>
          {result.reasons.map((r, i) => (
            <View key={i} style={S.reasonRow}>
              <Ionicons name="alert-circle-outline" size={11} color={result.color} />
              <Text style={[S.reasonText, { color: result.color }]}>{r}</Text>
            </View>
          ))}
        </View>
      )}

      <Text style={S.hint}>Offline analysis. Does not check bank account balance or ownership.</Text>
    </Animated.View>
  );
}

const S = StyleSheet.create({
  shell: {
    borderRadius: 20, borderWidth: 1,
    borderColor: `${TM.emerald}40`,
    padding: 16, width: 300, overflow: 'hidden',
    shadowColor: '#000', shadowOffset: { width: 0, height: 16 },
    shadowOpacity: 0.8, shadowRadius: 20, elevation: 10,
  },
  shimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1.2, backgroundColor: 'rgba(255,255,255,0.35)' },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 },
  iconRing: { width: 26, height: 26, borderRadius: 13, borderWidth: 1, alignItems: 'center', justifyContent: 'center' },
  title: { fontSize: 11, fontWeight: '700', letterSpacing: 1.5, textTransform: 'uppercase' },
  subtitle: { color: TM.frost4, fontSize: 11, marginBottom: 12 },
  inputRow: { flexDirection: 'row', gap: 8, marginBottom: 14 },
  inputWrap: { flex: 1, borderRadius: 14, borderWidth: 1, borderColor: TM.line2, overflow: 'hidden', height: 44 },
  inputShimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1, backgroundColor: 'rgba(255,255,255,0.18)' },
  input: { flex: 1, color: TM.frost, fontSize: 13, paddingHorizontal: 14, height: 44 },
  checkBtn: { width: 44, height: 44, borderRadius: 14, overflow: 'hidden' },
  checkBtnGrad: { flex: 1, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: 'rgba(242,234,253,0.22)', borderRadius: 14 },
  resultCard: { borderRadius: 16, borderWidth: 1, padding: 14, marginBottom: 12, overflow: 'hidden', gap: 8 },
  resultTop: { flexDirection: 'row', alignItems: 'flex-start', gap: 10 },
  verdict: { fontSize: 14, fontWeight: '800', letterSpacing: 0.5 },
  bankText: { color: TM.frost3, fontSize: 11, marginTop: 2 },
  reasonRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 6 },
  reasonText: { fontSize: 11, lineHeight: 16, flex: 1 },
  hint: { color: TM.frost4, fontSize: 10, lineHeight: 14, textAlign: 'center' },
});
