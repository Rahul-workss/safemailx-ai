/**
 * SafeMail X — Assistive Touch Floating Button
 * Liquid glass theme — matches App.tsx TmCard / Indigo Nocturne design system.
 *
 * A draggable, edge-snapping glass bubble that floats over every in-app screen
 * when the user is signed in. Expands into a 5-action fan menu.
 *
 * Actions:
 *   1. Clipboard Scan   — reads clipboard, auto-routes to correct scanner
 *   2. Quick Link Check — URL text input + instant threat verdict
 *   3. UPI Verifier     — UPI ID format + handle validation (offline)
 *   4. Who Called?      — offline number lookup → open Call Analyzer
 *   5. Quick Note       — floating notepad for jotting during suspicious calls
 */

import React, {
  useCallback, useEffect, useMemo, useRef, useState,
} from 'react';
import {
  Animated, Dimensions, Keyboard, PanResponder,
  Pressable, StyleSheet, Text, TextInput,
  TouchableOpacity, View,
} from 'react-native';
import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { scanSms, scanUrl } from '../api';
import { TM } from './LiquidGlass';
import QuickNotepad from './QuickNotepad';
import WhoCalledSheet from './WhoCalledSheet';
import UpiVerifierSheet from './UpiVerifierSheet';

const { width: SW, height: SH } = Dimensions.get('window');
const BUBBLE = 48;
const EDGE   = 14;
const RADIUS = 86; // fan arc radius
const POS_KEY = 'assistive_touch_position';

// ── Menu items ────────────────────────────────────────────────────────────────
type MenuAction = 'clipboard' | 'link' | 'upi' | 'whocalled' | 'note';

const ITEMS: { id: MenuAction; icon: keyof typeof Ionicons.glyphMap; label: string; color: string; glow: string }[] = [
  { id: 'clipboard', icon: 'clipboard-outline',      label: 'Clipboard',  color: 'rgba(0,240,255,1)',  glow: 'rgba(0,240,255,0.5)' },
  { id: 'link',      icon: 'link-outline',            label: 'Link Check', color: TM.violetGlow,        glow: 'rgba(138,143,240,0.5)' },
  { id: 'upi',       icon: 'cash-outline',            label: 'UPI Check',  color: TM.emerald,           glow: 'rgba(111,217,184,0.5)' },
  { id: 'whocalled', icon: 'call-outline',            label: 'Who Called?',color: TM.gold,              glow: 'rgba(232,168,76,0.5)' },
  { id: 'note',      icon: 'document-text-outline',   label: 'Note',       color: TM.rose,              glow: 'rgba(224,138,174,0.5)' },
];

// ── Clipboard type detection ──────────────────────────────────────────────────
type ClipType = 'url' | 'upi' | 'phone' | 'text';
function detectType(text: string): ClipType {
  const t = text.trim();
  if (/^(https?|www\.)/i.test(t))          return 'url';
  if (/^[\w.\-+]+@[\w]+$/.test(t))         return 'upi';
  if (/^[+]?[\d\s\-(). ]{7,15}$/.test(t)) return 'phone';
  return 'text';
}

interface ScanVerdict { verdict: string; score: number; color: string; detail: string; }

// ── Props ─────────────────────────────────────────────────────────────────────
interface Props {
  onOpenCallAnalyzer: () => void;
  onOpenQRScanner: () => void;
  isVisible: boolean;
}

export default function AssistiveTouch({ onOpenCallAnalyzer, onOpenQRScanner, isVisible }: Props) {
  const insets = useSafeAreaInsets();

  // ── Position refs (not state — avoids re-render on move) ──
  const posX = useRef(SW - BUBBLE - EDGE);
  const posY = useRef(SH * 0.42);
  const pan  = useRef(new Animated.ValueXY({ x: posX.current, y: posY.current })).current;
  const isDragging = useRef(false);

  // ── UI state ──
  const [menuOpen,   setMenuOpen]   = useState(false);
  const [onRight,    setOnRight]    = useState(true);
  const [sheet,      setSheet]      = useState<MenuAction | null>(null);
  const [linkText,   setLinkText]   = useState('');
  const [clipText,   setClipText]   = useState('');  // paste-and-scan input
  const [verdict,    setVerdict]    = useState<ScanVerdict | null>(null);
  const [scanning,   setScanning]   = useState(false);

  // ── Animations ──
  const bubbleScale  = useRef(new Animated.Value(1)).current;
  const bubbleOpacity= useRef(new Animated.Value(0.9)).current;
  const menuOpacity  = useRef(new Animated.Value(0)).current;
  const backdropOp   = useRef(new Animated.Value(0)).current;
  const itemAnims    = useRef(ITEMS.map(() => new Animated.Value(0))).current;
  const pulseAnim    = useRef(new Animated.Value(1)).current;

  // ── Restore position ──
  useEffect(() => {
    AsyncStorage.getItem(POS_KEY).then(raw => {
      if (!raw) return;
      const { x, y } = JSON.parse(raw);
      posX.current = x; posY.current = y;
      pan.setValue({ x, y });
      setOnRight(x > SW / 2);
    });
  }, []);

  // ── Entrance pulse on first show ──
  useEffect(() => {
    if (!isVisible) return;
    const t = setTimeout(() => {
      Animated.sequence([
        Animated.spring(pulseAnim, { toValue: 1.22, friction: 4, useNativeDriver: true }),
        Animated.spring(pulseAnim, { toValue: 1,    friction: 6, useNativeDriver: true }),
      ]).start();
    }, 900);
    return () => clearTimeout(t);
  }, [isVisible]);

  // ── Open fan ──
  const openMenu = useCallback(() => {
    setMenuOpen(true);
    Animated.parallel([
      Animated.timing(menuOpacity,  { toValue: 1, duration: 180, useNativeDriver: true }),
      Animated.timing(backdropOp,   { toValue: 1, duration: 200, useNativeDriver: true }),
      Animated.spring(bubbleScale,  { toValue: 1.12, friction: 5, useNativeDriver: true }),
      ...itemAnims.map((a, i) =>
        Animated.spring(a, { toValue: 1, delay: i * 48, tension: 90, friction: 9, useNativeDriver: true })
      ),
    ]).start();
  }, [itemAnims]);

  // ── Close fan ──
  const closeMenu = useCallback(() => {
    Animated.parallel([
      Animated.timing(menuOpacity, { toValue: 0, duration: 140, useNativeDriver: true }),
      Animated.timing(backdropOp,  { toValue: 0, duration: 140, useNativeDriver: true }),
      Animated.spring(bubbleScale, { toValue: 1, friction: 6,   useNativeDriver: true }),
      ...itemAnims.map(a => Animated.timing(a, { toValue: 0, duration: 110, useNativeDriver: true })),
    ]).start(() => setMenuOpen(false));
    setVerdict(null);
  }, [itemAnims]);

  const dismissAll = useCallback(() => {
    closeMenu();
    setSheet(null);
    setLinkText('');
    setVerdict(null);
  }, [closeMenu]);

  // ── PanResponder ──
  const panResponder = useMemo(() => PanResponder.create({
    onStartShouldSetPanResponder: () => true,
    onMoveShouldSetPanResponder: (_, g) => Math.abs(g.dx) > 5 || Math.abs(g.dy) > 5,

    onPanResponderGrant: () => {
      isDragging.current = false;
      Animated.spring(bubbleOpacity, { toValue: 0.55, useNativeDriver: true }).start();
    },

    onPanResponderMove: (_, g) => {
      if (Math.abs(g.dx) > 6 || Math.abs(g.dy) > 6) {
        if (!isDragging.current) { isDragging.current = true; if (menuOpen) closeMenu(); }
      }
      if (!isDragging.current) return;
      const minY = insets.top + 58;
      const maxY = SH - insets.bottom - BUBBLE - 84;
      pan.setValue({
        x: Math.max(0, Math.min(SW - BUBBLE, posX.current + g.dx)),
        y: Math.max(minY, Math.min(maxY, posY.current + g.dy)),
      });
    },

    onPanResponderRelease: (_, g) => {
      Animated.spring(bubbleOpacity, { toValue: 0.9, useNativeDriver: true }).start();
      if (!isDragging.current) {
        menuOpen ? closeMenu() : openMenu();
        return;
      }
      const minY = insets.top + 58;
      const maxY = SH - insets.bottom - BUBBLE - 84;
      const newY = Math.max(minY, Math.min(maxY, posY.current + g.dy));
      const snapX = (posX.current + g.dx) > SW / 2 ? SW - BUBBLE - EDGE : EDGE;
      Animated.spring(pan, { toValue: { x: snapX, y: newY }, tension: 100, friction: 12, useNativeDriver: false }).start();
      posX.current = snapX; posY.current = newY;
      setOnRight(snapX > SW / 2);
      AsyncStorage.setItem(POS_KEY, JSON.stringify({ x: snapX, y: newY }));
      isDragging.current = false;
    },
  }), [menuOpen, openMenu, closeMenu, insets]);

  // ── Fan item positions (semicircle arc upward) ──
  function itemPos(i: number) {
    const spread = 148;
    const startAngle = onRight ? 180 + (90 - spread / 2) : -(90 - spread / 2);
    const step = spread / (ITEMS.length - 1);
    const rad  = ((startAngle + step * i) * Math.PI) / 180;
    return { x: Math.cos(rad) * RADIUS * (onRight ? 1 : -1), y: -Math.abs(Math.sin(rad) * RADIUS) };
  }

  // ── Clipboard: open paste sheet (no native clipboard module needed) ──
  const handleClipboard = () => {
    closeMenu();
    setClipText('');
    setVerdict(null);
    setSheet('clipboard');
  };

  // ── Clipboard paste scan (called from the sheet's button) ──
  const handleClipScan = async () => {
    if (!clipText.trim()) return;
    Keyboard.dismiss(); setScanning(true); setVerdict(null);
    try {
      const text = clipText.trim();
      const type = detectType(text);
      if (type === 'url') {
        const r = await scanUrl(text);
        const s = r.risk_score ?? 0;
        setVerdict({ verdict: s >= 70 ? 'PHISHING DETECTED' : s >= 40 ? 'SUSPICIOUS' : 'LIKELY SAFE', score: s, color: s >= 70 ? TM.rose : s >= 40 ? TM.gold : TM.emerald, detail: `URL risk: ${s}/100` });
      } else if (type === 'upi') {
        setScanning(false); setSheet('upi'); return;
      } else if (type === 'phone') {
        setScanning(false); setSheet('whocalled'); return;
      } else {
        const r = await scanSms(text);
        const s = r.risk_score ?? 0;
        setVerdict({ verdict: s >= 70 ? 'SCAM TEXT' : s >= 40 ? 'SUSPICIOUS' : 'LOOKS SAFE', score: s, color: s >= 70 ? TM.rose : s >= 40 ? TM.gold : TM.emerald, detail: `Scam likelihood: ${s}/100` });
      }
    } catch { setVerdict({ verdict: 'Scan Failed', score: 0, color: TM.gold, detail: 'Check your connection.' }); }
    setScanning(false);
  };

  // ── Link check ──
  const handleLinkCheck = async () => {
    if (!linkText.trim()) return;
    Keyboard.dismiss(); setScanning(true); setVerdict(null);
    try {
      const r = await scanUrl(linkText.trim());
      const s = r.risk_score ?? 0;
      setVerdict({ verdict: s >= 70 ? 'PHISHING' : s >= 40 ? 'SUSPICIOUS' : 'LIKELY SAFE', score: s, color: s >= 70 ? TM.rose : s >= 40 ? TM.gold : TM.emerald, detail: `Risk: ${s}/100 · ${r.verdict.toUpperCase()}` });
    } catch { setVerdict({ verdict: 'Failed', score: 0, color: TM.gold, detail: 'Network error.' }); }
    setScanning(false);
  };

  const handleAction = (action: MenuAction) => {
    closeMenu();
    if (action === 'clipboard') handleClipboard();
    else setSheet(action);
  };

  if (!isVisible) return null;

  // Position of sheets relative to bubble (always offscreen-safe)
  const sheetTop = Math.max(insets.top + 8, posY.current - 340);
  const sheetRight = onRight ? EDGE : undefined;
  const sheetLeft  = onRight ? undefined : EDGE;

  return (
    <>
      {/* ── Backdrop ── */}
      {(menuOpen || sheet !== null) && (
        <Animated.View
          style={[StyleSheet.absoluteFill, { opacity: backdropOp, backgroundColor: 'rgba(1,1,4,0.55)', zIndex: 8998 }]}
          pointerEvents="auto"
        >
          <Pressable style={StyleSheet.absoluteFill} onPress={dismissAll} />
        </Animated.View>
      )}

      {/* ── Bubble + fan ── */}
      <Animated.View
        style={[S.bubbleWrap, { transform: pan.getTranslateTransform(), zIndex: 9000 }]}
        {...panResponder.panHandlers}
      >
        {/* Fan items */}
        {ITEMS.map((item, i) => {
          const pos = itemPos(i);
          return (
            <Animated.View
              key={item.id}
              style={[S.fanItem, {
                transform: [
                  { translateX: itemAnims[i].interpolate({ inputRange: [0,1], outputRange: [0, pos.x] }) },
                  { translateY: itemAnims[i].interpolate({ inputRange: [0,1], outputRange: [0, pos.y] }) },
                  { scale: itemAnims[i] },
                ],
                opacity: itemAnims[i],
              }]}
              pointerEvents={menuOpen ? 'auto' : 'none'}
            >
              <TouchableOpacity
                style={S.fanBtnWrap}
                onPress={() => handleAction(item.id)}
                activeOpacity={0.82}
              >
                {/* Glass item button */}
                <BlurView intensity={22} tint="dark" style={StyleSheet.absoluteFillObject} />
                <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.35)', borderRadius: 24 }]} />
                <LinearGradient
                  colors={['rgba(255,255,255,0.09)','rgba(255,255,255,0.01)','rgba(255,255,255,0.03)']}
                  start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
                  style={StyleSheet.absoluteFillObject}
                />
                <View style={[S.fanBtnShimmer]} />
                <View style={[S.fanBtnBorder, { borderColor: `${item.color}50` }]}>
                  <Ionicons name={item.icon} size={17} color={item.color} />
                </View>
              </TouchableOpacity>
              <Text style={[S.fanLabel, { color: item.color }]}>{item.label}</Text>
            </Animated.View>
          );
        })}

        {/* Main bubble */}
        <Animated.View style={{ transform: [{ scale: Animated.multiply(bubbleScale, pulseAnim) }], opacity: bubbleOpacity }}>
          <View style={S.bubble}>
            <BlurView intensity={30} tint="dark" style={StyleSheet.absoluteFillObject} />
            <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.40)', borderRadius: BUBBLE / 2 }]} />
            <LinearGradient
              colors={['rgba(90,96,216,0.45)','rgba(59,65,191,0.30)','rgba(0,240,255,0.10)']}
              start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
              style={StyleSheet.absoluteFillObject}
            />
            {/* Crystal top lip */}
            <View style={S.bubbleShimmer} />
            <Ionicons
              name={menuOpen ? 'close' : 'shield-half'}
              size={22}
              color={menuOpen ? TM.frost3 : 'rgba(0,240,255,0.9)'}
            />
          </View>
        </Animated.View>
      </Animated.View>

      {/* ── Inline verdict (clipboard / link) ── */}
      {(verdict || scanning) && sheet === null && (
        <View style={[S.verdictFloat, { top: sheetTop + 260, right: sheetRight, left: sheetLeft, zIndex: 9001 }]}>
          <View style={S.verdictCard}>
            <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
            <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.45)', borderRadius: 18 }]} />
            <LinearGradient
              colors={['rgba(255,255,255,0.08)','rgba(255,255,255,0.00)','rgba(255,255,255,0.03)']}
              start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
              style={StyleSheet.absoluteFillObject}
            />
            <View style={S.verdictShimmer} />
            {scanning ? (
              <Text style={S.scanningText}>Scanning…</Text>
            ) : verdict ? (
              <>
                <Text style={[S.verdictText, { color: verdict.color }]}>{verdict.verdict}</Text>
                <Text style={S.verdictDetail}>{verdict.detail}</Text>
              </>
            ) : null}
            <TouchableOpacity onPress={() => setVerdict(null)} style={S.verdictClose}>
              <Ionicons name="close-circle" size={16} color={TM.frost4} />
            </TouchableOpacity>
          </View>
        </View>
      )}

      {/* ── Quick Link Check sheet ── */}
      {sheet === 'link' && (
        <View style={[S.sheetFloat, { top: sheetTop, right: sheetRight, left: sheetLeft, zIndex: 9001 }]}>
          <View style={S.linkShell}>
            <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
            <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.42)', borderRadius: 20 }]} />
            <LinearGradient
              colors={['rgba(255,255,255,0.08)','rgba(255,255,255,0.01)','rgba(255,255,255,0.00)','rgba(255,255,255,0.03)']}
              start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
              style={StyleSheet.absoluteFillObject}
            />
            <View style={S.linkShimmer} />

            {/* Header */}
            <View style={S.sheetHeader}>
              <View style={[S.iconRing, { borderColor: `${TM.violetGlow}80`, backgroundColor: 'rgba(138,143,240,0.14)' }]}>
                <Ionicons name="link-outline" size={13} color={TM.violetGlow} />
              </View>
              <Text style={[S.sheetTitle, { color: TM.violetGlow }]}>QUICK LINK CHECK</Text>
              <TouchableOpacity onPress={() => { setSheet(null); setVerdict(null); setLinkText(''); }} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
                <Ionicons name="close" size={18} color={TM.frost4} />
              </TouchableOpacity>
            </View>

            <LinearGradient
              colors={['transparent', `${TM.violetGlow}30`, 'transparent']}
              start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }}
              style={{ height: 1, marginBottom: 14 }}
            />

            <View style={S.inputRow}>
              <View style={S.inputWrap}>
                <BlurView intensity={16} tint="dark" style={StyleSheet.absoluteFillObject} />
                <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.28)', borderRadius: 14 }]} />
                <View style={S.inputShimmer} />
                <TextInput
                  style={S.input}
                  placeholder="Paste a URL…"
                  placeholderTextColor="rgba(242,234,253,0.25)"
                  value={linkText}
                  onChangeText={t => { setLinkText(t); setVerdict(null); }}
                  autoCapitalize="none"
                  keyboardType="url"
                  returnKeyType="go"
                  onSubmitEditing={handleLinkCheck}
                  autoFocus
                />
              </View>
              <TouchableOpacity style={S.actionBtn} onPress={handleLinkCheck} activeOpacity={0.82}>
                <LinearGradient colors={[TM.violetSoft, TM.violet, TM.ink3]} style={S.actionBtnGrad}>
                  <Ionicons name={scanning ? 'refresh' : 'search'} size={16} color={TM.frost} />
                </LinearGradient>
              </TouchableOpacity>
            </View>

            {verdict && (
              <View style={[S.inlineResult, { borderColor: `${verdict.color}40`, backgroundColor: `${verdict.color}12` }]}>
                <Text style={[S.inlineVerdict, { color: verdict.color }]}>{verdict.verdict}</Text>
                <Text style={S.inlineDetail}>{verdict.detail}</Text>
              </View>
            )}
          </View>
        </View>
      )}

      {/* ── Clipboard paste-and-scan sheet ── */}
      {sheet === 'clipboard' && (
        <View style={[S.sheetFloat, { top: sheetTop, right: sheetRight, left: sheetLeft, zIndex: 9001 }]}>
          <View style={S.linkShell}>
            <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
            <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.42)', borderRadius: 20 }]} />
            <LinearGradient
              colors={['rgba(255,255,255,0.08)','rgba(255,255,255,0.01)','rgba(255,255,255,0.00)','rgba(255,255,255,0.03)']}
              start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
              style={StyleSheet.absoluteFillObject}
            />
            <View style={S.linkShimmer} />
            <View style={S.sheetHeader}>
              <View style={[S.iconRing, { borderColor: 'rgba(0,240,255,0.5)', backgroundColor: TM.cyanDim }]}>
                <Ionicons name="clipboard-outline" size={13} color="rgba(0,240,255,1)" />
              </View>
              <Text style={[S.sheetTitle, { color: 'rgba(0,240,255,1)' }]}>SCAN ANYTHING</Text>
              <TouchableOpacity onPress={() => { setSheet(null); setVerdict(null); setClipText(''); }} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
                <Ionicons name="close" size={18} color={TM.frost4} />
              </TouchableOpacity>
            </View>
            <LinearGradient
              colors={['transparent', TM.cyanBorder, 'transparent']}
              start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }}
              style={{ height: 1, marginBottom: 8 }}
            />
            <Text style={{ color: TM.frost4, fontSize: 11, marginBottom: 10 }}>
              Paste a link, UPI ID, phone number, or any suspicious text
            </Text>
            <View style={S.inputRow}>
              <View style={S.inputWrap}>
                <BlurView intensity={16} tint="dark" style={StyleSheet.absoluteFillObject} />
                <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.28)', borderRadius: 14 }]} />
                <View style={S.inputShimmer} />
                <TextInput
                  style={S.input}
                  placeholder="Paste here…"
                  placeholderTextColor="rgba(242,234,253,0.25)"
                  value={clipText}
                  onChangeText={t => { setClipText(t); setVerdict(null); }}
                  autoCapitalize="none"
                  multiline={false}
                  returnKeyType="go"
                  onSubmitEditing={handleClipScan}
                  autoFocus
                />
              </View>
              <TouchableOpacity style={S.actionBtn} onPress={handleClipScan} activeOpacity={0.82}>
                <LinearGradient colors={[TM.violetSoft, TM.violet, TM.ink3]} style={S.actionBtnGrad}>
                  <Ionicons name={scanning ? 'refresh' : 'scan'} size={16} color={TM.frost} />
                </LinearGradient>
              </TouchableOpacity>
            </View>
            {verdict && (
              <View style={[S.inlineResult, { borderColor: `${verdict.color}40`, backgroundColor: `${verdict.color}12` }]}>
                <Text style={[S.inlineVerdict, { color: verdict.color }]}>{verdict.verdict}</Text>
                <Text style={S.inlineDetail}>{verdict.detail}</Text>
              </View>
            )}
          </View>
        </View>
      )}

      {/* ── Who Called sheet ── */}
      {sheet === 'whocalled' && (
        <View style={[S.sheetFloat, { top: sheetTop, right: sheetRight, left: sheetLeft, zIndex: 9001 }]}>
          <WhoCalledSheet
            visible={true}
            onClose={() => setSheet(null)}
            onOpenCallAnalyzer={() => { setSheet(null); onOpenCallAnalyzer(); }}
          />
        </View>
      )}

      {/* ── UPI Verifier sheet ── */}
      {sheet === 'upi' && (
        <View style={[S.sheetFloat, { top: sheetTop, right: sheetRight, left: sheetLeft, zIndex: 9001 }]}>
          <UpiVerifierSheet
            visible={true}
            onClose={() => setSheet(null)}
          />
        </View>
      )}

      {/* ── Quick Note sheet ── */}
      {sheet === 'note' && (
        <View style={[S.sheetFloat, { top: sheetTop, right: sheetRight, left: sheetLeft, zIndex: 9001 }]}>
          <QuickNotepad visible={true} onClose={() => setSheet(null)} />
        </View>
      )}
    </>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────
const S = StyleSheet.create({
  // ── Bubble ──
  bubbleWrap: {
    position: 'absolute', width: BUBBLE, height: BUBBLE,
    alignItems: 'center', justifyContent: 'center',
  },
  bubble: {
    width: BUBBLE, height: BUBBLE, borderRadius: BUBBLE / 2,
    alignItems: 'center', justifyContent: 'center',
    overflow: 'hidden',
    borderWidth: 1.5, borderColor: 'rgba(0,240,255,0.45)',
    shadowColor: 'rgba(0,240,255,1)',
    shadowOffset: { width: 0, height: 0 },
    shadowRadius: 16, shadowOpacity: 0.7, elevation: 12,
  },
  bubbleShimmer: {
    position: 'absolute', top: 0, left: 0, right: 0, height: 1.2,
    backgroundColor: 'rgba(255,255,255,0.40)',
  },

  // ── Fan items ──
  fanItem: {
    position: 'absolute', alignItems: 'center', gap: 4,
    width: 52, transform: [{ translateX: -26 + BUBBLE / 2 }],
  },
  fanBtnWrap: {
    width: 46, height: 46, borderRadius: 23, overflow: 'hidden',
    shadowColor: '#000', shadowOffset: { width: 0, height: 4 },
    shadowRadius: 8, shadowOpacity: 0.5, elevation: 8,
  },
  fanBtnBorder: {
    position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
    borderRadius: 23, borderWidth: 1,
    alignItems: 'center', justifyContent: 'center',
  },
  fanBtnShimmer: {
    position: 'absolute', top: 0, left: 0, right: 0, height: 1.2,
    backgroundColor: 'rgba(255,255,255,0.30)',
  },
  fanLabel: {
    fontSize: 9, fontWeight: '700', letterSpacing: 0.3,
    textShadowColor: 'rgba(0,0,0,0.9)',
    textShadowOffset: { width: 0, height: 1 }, textShadowRadius: 4,
  },

  // ── Floating sheets container ──
  sheetFloat: { position: 'absolute' },
  verdictFloat: { position: 'absolute' },

  // ── Inline verdict ──
  verdictCard: {
    borderRadius: 18, borderWidth: 1,
    borderColor: TM.cyanBorder,
    padding: 14, minWidth: 220, maxWidth: 290,
    overflow: 'hidden',
    shadowColor: '#000', shadowOffset: { width: 0, height: 12 },
    shadowOpacity: 0.7, shadowRadius: 16, elevation: 8,
  },
  verdictShimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1.2, backgroundColor: 'rgba(255,255,255,0.35)' },
  scanningText: { color: TM.frost4, fontSize: 13, textAlign: 'center' },
  verdictText: { fontSize: 14, fontWeight: '800', marginBottom: 4 },
  verdictDetail: { color: TM.frost3, fontSize: 11 },
  verdictClose: { position: 'absolute', top: 8, right: 8 },

  // ── Link check sheet ──
  linkShell: {
    borderRadius: 20, borderWidth: 1,
    borderColor: `${TM.violetGlow}40`,
    padding: 16, width: 300, overflow: 'hidden',
    shadowColor: '#000', shadowOffset: { width: 0, height: 16 },
    shadowOpacity: 0.8, shadowRadius: 20, elevation: 10,
  },
  linkShimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1.2, backgroundColor: 'rgba(255,255,255,0.35)' },
  sheetHeader: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 12 },
  iconRing: { width: 26, height: 26, borderRadius: 13, borderWidth: 1, alignItems: 'center', justifyContent: 'center' },
  sheetTitle: { flex: 1, fontSize: 11, fontWeight: '700', letterSpacing: 1.5, textTransform: 'uppercase' },
  inputRow: { flexDirection: 'row', gap: 8 },
  inputWrap: { flex: 1, height: 44, borderRadius: 14, borderWidth: 1, borderColor: TM.line2, overflow: 'hidden' },
  inputShimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1, backgroundColor: 'rgba(255,255,255,0.18)' },
  input: { flex: 1, color: TM.frost, fontSize: 13, paddingHorizontal: 14, height: 44 },
  actionBtn: { width: 44, height: 44, borderRadius: 14, overflow: 'hidden' },
  actionBtnGrad: { flex: 1, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: 'rgba(242,234,253,0.22)', borderRadius: 14 },
  inlineResult: { borderRadius: 12, borderWidth: 1, padding: 10, marginTop: 10 },
  inlineVerdict: { fontSize: 13, fontWeight: '800', marginBottom: 2 },
  inlineDetail: { color: TM.frost3, fontSize: 11 },
});
