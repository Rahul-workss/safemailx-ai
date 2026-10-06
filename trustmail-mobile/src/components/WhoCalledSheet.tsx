/**
 * SafeMail X — Who Called? Sheet (Assistive Touch)
 * Liquid glass theme — matches App.tsx TmCard exactly.
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  Animated, Keyboard, Linking, StyleSheet, Text,
  TextInput, TouchableOpacity, View,
} from 'react-native';
import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import { TM } from './LiquidGlass';
import officialNumbers from '../data/official_numbers.json';

const KNOWN_SCAM_PREFIXES = ['+92', '+1 (', '+44', '+880'];

interface LookupResult {
  type: 'official' | 'suspicious' | 'unknown';
  label: string; sublabel: string;
  color: string; icon: keyof typeof Ionicons.glyphMap;
  canAnalyze: boolean;
}

function lookupNumber(raw: string): LookupResult {
  const clean = raw.replace(/[\s\-().+]/g, '');
  const stripped = clean.replace(/^91/, '');
  const db = officialNumbers as Record<string, { name: string; category: string }>;
  const entry = db[clean] || db[stripped];

  if (entry) {
    return {
      type: 'official', label: entry.name,
      sublabel: `Verified ${entry.category} number`,
      color: TM.emerald, icon: 'shield-checkmark', canAnalyze: false,
    };
  }
  if (KNOWN_SCAM_PREFIXES.some(p => raw.startsWith(p))) {
    return {
      type: 'suspicious', label: 'International / Spoofed Number',
      sublabel: 'International calls are common in OTP and tech-support scams.',
      color: TM.rose, icon: 'warning', canAnalyze: true,
    };
  }
  if (/^[6-9]\d{9}$/.test(stripped)) {
    return {
      type: 'unknown', label: 'Unknown Indian Mobile',
      sublabel: 'Not in our verified database. Analyze if caller made suspicious claims.',
      color: TM.gold, icon: 'help-circle-outline', canAnalyze: true,
    };
  }
  return {
    type: 'unknown', label: 'Unknown Number',
    sublabel: 'We have no information on this number.',
    color: 'rgba(0,240,255,1)', icon: 'help-circle-outline', canAnalyze: true,
  };
}

interface Props {
  visible: boolean; onClose: () => void;
  onOpenCallAnalyzer: () => void; initialNumber?: string;
}

export default function WhoCalledSheet({ visible, onClose, onOpenCallAnalyzer, initialNumber }: Props) {
  const [number, setNumber] = useState(initialNumber || '');
  const [result, setResult] = useState<LookupResult | null>(null);
  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(24)).current;
  const inputRef = useRef<TextInput>(null);

  useEffect(() => {
    if (visible) {
      setNumber(initialNumber || ''); setResult(null);
      Animated.parallel([
        Animated.timing(fadeIn, { toValue: 1, duration: 220, useNativeDriver: true }),
        Animated.spring(slideUp, { toValue: 0, tension: 80, friction: 10, useNativeDriver: true }),
      ]).start(() => { if (!initialNumber) inputRef.current?.focus(); });
      if (initialNumber) setResult(lookupNumber(initialNumber));
    } else {
      Animated.parallel([
        Animated.timing(fadeIn, { toValue: 0, duration: 150, useNativeDriver: true }),
        Animated.timing(slideUp, { toValue: 24, duration: 150, useNativeDriver: true }),
      ]).start();
    }
  }, [visible, initialNumber]);

  const handleCheck = () => {
    if (!number.trim()) return;
    Keyboard.dismiss();
    setResult(lookupNumber(number.trim()));
  };

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

      {/* Header */}
      <View style={S.header}>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          <View style={[S.iconRing, { borderColor: 'rgba(0,240,255,0.5)', backgroundColor: TM.cyanDim }]}>
            <Ionicons name="call-outline" size={13} color="rgba(0,240,255,1)" />
          </View>
          <Text style={S.title}>WHO CALLED?</Text>
        </View>
        <TouchableOpacity onPress={onClose} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
          <Ionicons name="close" size={18} color={TM.frost4} />
        </TouchableOpacity>
      </View>

      <LinearGradient
        colors={['transparent', TM.cyanBorder, 'transparent']}
        start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }}
        style={{ height: 1, marginBottom: 14 }}
      />

      {/* Input row */}
      <View style={S.inputRow}>
        <View style={S.inputWrap}>
          <BlurView intensity={18} tint="dark" style={StyleSheet.absoluteFillObject} />
          <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.25)', borderRadius: 14 }]} />
          <View style={S.inputShimmer} />
          <TextInput
            ref={inputRef}
            style={S.input}
            placeholder="+91 98765 43210"
            placeholderTextColor="rgba(242,234,253,0.25)"
            value={number}
            onChangeText={t => { setNumber(t); setResult(null); }}
            keyboardType="phone-pad"
            returnKeyType="search"
            onSubmitEditing={handleCheck}
          />
        </View>
        <TouchableOpacity style={S.checkBtn} onPress={handleCheck} activeOpacity={0.82}>
          <LinearGradient colors={[TM.violetSoft, TM.violet, TM.ink3]} style={S.checkBtnGrad}>
            <Ionicons name="search" size={16} color={TM.frost} />
          </LinearGradient>
        </TouchableOpacity>
      </View>

      {/* Result */}
      {result && (
        <View style={[S.resultCard, { borderColor: `${result.color}40` }]}>
          <BlurView intensity={18} tint="dark" style={StyleSheet.absoluteFillObject} />
          <View style={[StyleSheet.absoluteFillObject, { backgroundColor: `${result.color}10`, borderRadius: 16 }]} />
          <View style={S.resultHeader}>
            <Ionicons name={result.icon} size={20} color={result.color} />
            <View style={{ flex: 1 }}>
              <Text style={[S.resultLabel, { color: result.color }]}>{result.label}</Text>
              <Text style={S.resultSub}>{result.sublabel}</Text>
            </View>
          </View>
          {result.canAnalyze && (
            <TouchableOpacity
              style={S.analyzeBtn}
              onPress={() => { onClose(); onOpenCallAnalyzer(); }}
              activeOpacity={0.82}
            >
              <LinearGradient colors={[TM.violetSoft, TM.violet, TM.ink3]} style={S.analyzeBtnGrad}>
                <Ionicons name="mic-outline" size={14} color={TM.frost} />
                <Text style={S.analyzeBtnText}>Analyze This Call →</Text>
              </LinearGradient>
            </TouchableOpacity>
          )}
          {result.type === 'official' && (
            <TouchableOpacity
              style={[S.analyzeBtn, { marginTop: 8 }]}
              onPress={() => Linking.openURL(`tel:${number.replace(/\s/g, '')}`)}
              activeOpacity={0.82}
            >
              <LinearGradient colors={['#6fd9b8', '#3aaf8c', '#1a5f4a']} style={S.analyzeBtnGrad}>
                <Ionicons name="call" size={14} color="#010104" />
                <Text style={[S.analyzeBtnText, { color: '#010104' }]}>Call Back (Verified)</Text>
              </LinearGradient>
            </TouchableOpacity>
          )}
        </View>
      )}

      <Text style={S.hint}>Checks 35+ official Indian numbers offline. No data sent.</Text>
    </Animated.View>
  );
}

const S = StyleSheet.create({
  shell: {
    borderRadius: 20, borderWidth: 1,
    borderColor: TM.cyanBorder,
    padding: 16, width: 300, overflow: 'hidden',
    shadowColor: '#000', shadowOffset: { width: 0, height: 16 },
    shadowOpacity: 0.8, shadowRadius: 20, elevation: 10,
  },
  shimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1.2, backgroundColor: 'rgba(255,255,255,0.35)' },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 },
  iconRing: { width: 26, height: 26, borderRadius: 13, borderWidth: 1, alignItems: 'center', justifyContent: 'center' },
  title: { color: 'rgba(0,240,255,1)', fontSize: 11, fontWeight: '700', letterSpacing: 1.5, textTransform: 'uppercase' },
  inputRow: { flexDirection: 'row', gap: 8, marginBottom: 14 },
  inputWrap: { flex: 1, borderRadius: 14, borderWidth: 1, borderColor: TM.line2, overflow: 'hidden', height: 44 },
  inputShimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1, backgroundColor: 'rgba(255,255,255,0.18)' },
  input: { flex: 1, color: TM.frost, fontSize: 14, paddingHorizontal: 14, height: 44 },
  checkBtn: { width: 44, height: 44, borderRadius: 14, overflow: 'hidden' },
  checkBtnGrad: { flex: 1, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: 'rgba(242,234,253,0.22)', borderRadius: 14 },
  resultCard: {
    borderRadius: 16, borderWidth: 1, padding: 14, marginBottom: 12, overflow: 'hidden', gap: 10,
  },
  resultHeader: { flexDirection: 'row', alignItems: 'flex-start', gap: 10 },
  resultLabel: { fontSize: 14, fontWeight: '700' },
  resultSub: { color: TM.frost3, fontSize: 11, lineHeight: 16, marginTop: 2 },
  analyzeBtn: { borderRadius: 12, overflow: 'hidden' },
  analyzeBtnGrad: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center',
    gap: 6, paddingVertical: 11, borderWidth: 1, borderColor: 'rgba(242,234,253,0.22)', borderRadius: 12,
  },
  analyzeBtnText: { color: TM.frost, fontSize: 13, fontWeight: '600' },
  hint: { color: TM.frost4, fontSize: 10, lineHeight: 14, textAlign: 'center' },
});
