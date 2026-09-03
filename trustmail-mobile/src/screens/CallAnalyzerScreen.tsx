import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView,
  Animated, BackHandler, Linking, Dimensions, Platform,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { Audio } from 'expo-av';
import * as FileSystem from 'expo-file-system';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { analyzeCall, CallAnalysisResult } from '../api';

const { height: SCREEN_HEIGHT, width: SCREEN_WIDTH } = Dimensions.get('window');

type ScreenState = 'CHOOSING' | 'RECORDING' | 'STRUCTURED' | 'ANALYZING' | 'VERDICT' | 'ERROR';

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

// ─── Glassmorphic Card ────────────────────────────────────────────────────────
function GlassCard({ children, style }: { children: React.ReactNode; style?: any }) {
  return (
    <View style={[glassStyles.card, style]}>
      {children}
    </View>
  );
}

const glassStyles = StyleSheet.create({
  card: {
    backgroundColor: 'rgba(255,255,255,0.05)',
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.1)',
    padding: 20,
  },
});

// ─── Animated Chip ────────────────────────────────────────────────────────────
function AnimatedChip({
  label, active, color, onPress,
}: {
  label: string; active: boolean; color: string; onPress: () => void;
}) {
  const scale = useRef(new Animated.Value(1)).current;
  const glow = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.spring(scale, { toValue: active ? 1.04 : 1, useNativeDriver: true }),
      Animated.timing(glow, { toValue: active ? 1 : 0, duration: 200, useNativeDriver: false }),
    ]).start();
  }, [active]);

  const bgColor = glow.interpolate({ inputRange: [0, 1], outputRange: ['rgba(255,255,255,0.05)', `${color}20`] });
  const borderColor = glow.interpolate({ inputRange: [0, 1], outputRange: ['rgba(255,255,255,0.09)', color] });

  return (
    <TouchableOpacity onPress={onPress} activeOpacity={0.8}>
      <Animated.View style={[
        chipStyles.chip,
        { transform: [{ scale }], backgroundColor: bgColor, borderColor },
      ]}>
        <Text style={[chipStyles.text, active && { color, fontWeight: '700' }]}>{label}</Text>
      </Animated.View>
    </TouchableOpacity>
  );
}

const chipStyles = StyleSheet.create({
  chip: { paddingVertical: 10, paddingHorizontal: 16, borderRadius: 24, borderWidth: 1, margin: 4 },
  text: { color: 'rgba(255,255,255,0.55)', fontSize: 14, fontWeight: '500' },
});

// ─── Pulsing Mic Button ───────────────────────────────────────────────────────
function PulsingMic({ onStop }: { onStop: () => void }) {
  const ring1 = useRef(new Animated.Value(1)).current;
  const ring2 = useRef(new Animated.Value(1)).current;
  const ring3 = useRef(new Animated.Value(1)).current;
  const ring1Opacity = useRef(new Animated.Value(0.6)).current;
  const ring2Opacity = useRef(new Animated.Value(0.4)).current;
  const ring3Opacity = useRef(new Animated.Value(0.2)).current;

  useEffect(() => {
    const pulse = (anim: Animated.Value, opAnim: Animated.Value, delay: number) =>
      Animated.loop(
        Animated.sequence([
          Animated.delay(delay),
          Animated.parallel([
            Animated.timing(anim, { toValue: 1.8, duration: 1200, useNativeDriver: true }),
            Animated.timing(opAnim, { toValue: 0, duration: 1200, useNativeDriver: true }),
          ]),
          Animated.parallel([
            Animated.timing(anim, { toValue: 1, duration: 0, useNativeDriver: true }),
            Animated.timing(opAnim, { toValue: 0.5, duration: 0, useNativeDriver: true }),
          ]),
        ])
      );
    const a1 = pulse(ring1, ring1Opacity, 0);
    const a2 = pulse(ring2, ring2Opacity, 400);
    const a3 = pulse(ring3, ring3Opacity, 800);
    a1.start(); a2.start(); a3.start();
    return () => { a1.stop(); a2.stop(); a3.stop(); };
  }, []);

  return (
    <View style={{ alignItems: 'center', justifyContent: 'center', height: 200 }}>
      {/* Ripple rings */}
      {[ring1, ring2, ring3].map((r, i) => (
        <Animated.View key={i} style={{
          position: 'absolute',
          width: 120, height: 120, borderRadius: 60,
          borderWidth: 2, borderColor: C.rose,
          transform: [{ scale: r }],
          opacity: [ring1Opacity, ring2Opacity, ring3Opacity][i],
        }} />
      ))}
      {/* Core mic button */}
      <TouchableOpacity onPress={onStop} activeOpacity={0.85}>
        <View style={{
          width: 100, height: 100, borderRadius: 50,
          backgroundColor: 'rgba(255,61,113,0.2)',
          borderWidth: 2, borderColor: C.rose,
          alignItems: 'center', justifyContent: 'center',
          shadowColor: C.rose, shadowRadius: 20, shadowOpacity: 0.8,
          elevation: 12,
        }}>
          <Ionicons name="mic" size={40} color={C.rose} />
        </View>
      </TouchableOpacity>
    </View>
  );
}

// ─── Main Screen ──────────────────────────────────────────────────────────────
export default function CallAnalyzerScreen({ onClose }: { onClose: () => void }) {
  const insets = useSafeAreaInsets();
  const [screenState, setScreenState] = useState<ScreenState>('CHOOSING');

  // Animations
  const slideAnim = useRef(new Animated.Value(SCREEN_HEIGHT)).current;
  const overlayOpacity = useRef(new Animated.Value(0)).current;

  // Path A — Voice
  const recordingRef = useRef<Audio.Recording | null>(null);
  const [timeLeft, setTimeLeft] = useState(20);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timeLeftRef = useRef(20);

  // Path B — Structured
  const [orgClaimed, setOrgClaimed] = useState('');
  const [actions, setActions] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);

  // Results
  const [result, setResult] = useState<CallAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [analyzing, setAnalyzing] = useState(false);

  // ── Entrance animation ──────────────────────────────────────────────────────
  useEffect(() => {
    Animated.parallel([
      Animated.timing(overlayOpacity, { toValue: 1, duration: 300, useNativeDriver: true }),
      Animated.spring(slideAnim, { toValue: 0, tension: 65, friction: 11, useNativeDriver: true }),
    ]).start();
  }, []);

  // ── Android back button ─────────────────────────────────────────────────────
  useEffect(() => {
    const handler = BackHandler.addEventListener('hardwareBackPress', () => {
      handleBack();
      return true;
    });
    return () => handler.remove();
  }, [screenState]);

  const handleClose = useCallback(() => {
    Animated.parallel([
      Animated.timing(overlayOpacity, { toValue: 0, duration: 250, useNativeDriver: true }),
      Animated.timing(slideAnim, { toValue: SCREEN_HEIGHT, duration: 280, useNativeDriver: true }),
    ]).start(() => onClose());
  }, []);

  const handleBack = useCallback(() => {
    if (screenState === 'CHOOSING') {
      handleClose();
    } else if (screenState === 'STRUCTURED' || screenState === 'RECORDING') {
      stopRecordingIfNeeded();
      setScreenState('CHOOSING');
    } else if (screenState === 'VERDICT' || screenState === 'ERROR') {
      setScreenState('CHOOSING');
      setResult(null);
      setErrorMsg('');
    }
  }, [screenState]);

  // ── Cleanup on unmount ──────────────────────────────────────────────────────
  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (recordingRef.current) {
        recordingRef.current.stopAndUnloadAsync().catch(() => {});
      }
    };
  }, []);

  const stopRecordingIfNeeded = async () => {
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    if (recordingRef.current) {
      try { await recordingRef.current.stopAndUnloadAsync(); } catch (_) {}
      recordingRef.current = null;
    }
  };

  // ── Path A: Voice Recording ─────────────────────────────────────────────────
  const startRecording = async () => {
    try {
      const { status } = await Audio.requestPermissionsAsync();
      if (status !== 'granted') {
        setScreenState('STRUCTURED');
        return;
      }
      await Audio.setAudioModeAsync({ allowsRecordingIOS: true, playsInSilentModeIOS: true });
      const { recording } = await Audio.Recording.createAsync(Audio.RecordingOptionsPresets.HIGH_QUALITY);
      recordingRef.current = recording;
      timeLeftRef.current = 20;
      setTimeLeft(20);
      setScreenState('RECORDING');

      timerRef.current = setInterval(() => {
        timeLeftRef.current -= 1;
        setTimeLeft(timeLeftRef.current);
        if (timeLeftRef.current <= 0) {
          finishRecording();
        }
      }, 1000);
    } catch (err) {
      setScreenState('STRUCTURED');
    }
  };

  const finishRecording = async () => {
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    const rec = recordingRef.current;
    if (!rec) return;
    try {
      await rec.stopAndUnloadAsync();
      const uri = rec.getURI();
      recordingRef.current = null;
      if (!uri) { setScreenState('STRUCTURED'); return; }
      const info = await FileSystem.getInfoAsync(uri);
      if (info.exists && (info as any).size < 1000) {
        setScreenState('STRUCTURED');
        return;
      }
      submitVoice(uri);
    } catch (_) {
      setScreenState('STRUCTURED');
    }
  };

  const submitVoice = async (uri: string) => {
    setAnalyzing(true);
    setScreenState('ANALYZING');
    try {
      const res = await analyzeCall({ inputMode: 'voice', audioUri: uri });
      setResult(res);
      setScreenState('VERDICT');
    } catch (e: any) {
      setErrorMsg(e.message || 'Analysis failed');
      setScreenState('ERROR');
    } finally {
      setAnalyzing(false);
    }
  };

  // ── Path B: Structured ──────────────────────────────────────────────────────
  const submitStructured = async () => {
    setAnalyzing(true);
    setScreenState('ANALYZING');
    try {
      const res = await analyzeCall({ inputMode: 'structured', orgClaimed, actionsRequested: actions, warningPhrases: warnings });
      setResult(res);
      setScreenState('VERDICT');
    } catch (e: any) {
      setErrorMsg(e.message || 'Analysis failed');
      setScreenState('ERROR');
    } finally {
      setAnalyzing(false);
    }
  };

  const toggleItem = (list: string[], setList: (l: string[]) => void, item: string) => {
    setList(list.includes(item) ? list.filter(i => i !== item) : [...list, item]);
  };

  const canSubmit = orgClaimed.length > 0 || actions.length > 0 || warnings.length > 0;

  // ── Render content per state ────────────────────────────────────────────────
  const renderContent = () => {
    switch (screenState) {
      case 'CHOOSING': return <ChoosingView onSpeak={startRecording} onTap={() => setScreenState('STRUCTURED')} />;
      case 'RECORDING': return (
        <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
          <Text style={S.sectionLabel}>Recording your description…</Text>
          <PulsingMic onStop={finishRecording} />
          <Text style={S.timerText}>00:{timeLeft.toString().padStart(2, '0')}</Text>
          <Text style={[S.mutedText, { marginTop: 8, textAlign: 'center' }]}>
            Describe the call briefly. Be specific.{'\n'}Tap the mic to stop early.
          </Text>
          <TouchableOpacity style={[S.stopBtn, { marginTop: 32 }]} onPress={finishRecording}>
            <Text style={S.btnText}>Stop & Analyze Now</Text>
          </TouchableOpacity>
        </View>
      );
      case 'STRUCTURED': return (
        <ScrollView contentContainerStyle={{ padding: 24, paddingBottom: 120 }} showsVerticalScrollIndicator={false}>
          <StructuredForm
            orgClaimed={orgClaimed} setOrgClaimed={setOrgClaimed}
            actions={actions} setActions={setActions}
            warnings={warnings} setWarnings={setWarnings}
            onToggle={toggleItem}
          />
          <TouchableOpacity
            style={[S.primaryBtn, { opacity: canSubmit ? 1 : 0.4, marginTop: 24 }]}
            disabled={!canSubmit}
            onPress={submitStructured}
          >
            <Text style={S.btnText}>Analyze Now →</Text>
          </TouchableOpacity>
        </ScrollView>
      );
      case 'ANALYZING': return <AnalyzingView />;
      case 'VERDICT': return result ? (
        <VerdictView result={result} onClose={handleClose} onRetry={() => { setResult(null); setScreenState('CHOOSING'); }} />
      ) : null;
      case 'ERROR': return (
        <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
          <Ionicons name="alert-circle" size={56} color={C.rose} />
          <Text style={[S.title, { marginTop: 16 }]}>Analysis Failed</Text>
          <Text style={[S.mutedText, { marginTop: 8, textAlign: 'center' }]}>{errorMsg}</Text>
          <TouchableOpacity style={[S.primaryBtn, { marginTop: 32 }]} onPress={() => { setErrorMsg(''); setScreenState('CHOOSING'); }}>
            <Text style={S.btnText}>Try Again</Text>
          </TouchableOpacity>
        </View>
      );
    }
  };

  return (
    <Animated.View style={[StyleSheet.absoluteFill, { opacity: overlayOpacity, zIndex: 9999, elevation: 9999 }]}>
      {/* Dark blurred backdrop */}
      <View style={[StyleSheet.absoluteFill, { backgroundColor: 'rgba(6,8,15,0.96)' }]} />

      {/* Sheet */}
      <Animated.View style={[S.sheet, { transform: [{ translateY: slideAnim }], paddingTop: insets.top + 16, paddingBottom: insets.bottom }]}>
        {/* Header bar */}
        <View style={S.headerBar}>
          <TouchableOpacity onPress={handleBack} style={S.backBtn} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
            <Ionicons name="chevron-back" size={24} color={C.frost} />
            <Text style={S.backLabel}>
              {screenState === 'CHOOSING' ? 'Close' : 'Back'}
            </Text>
          </TouchableOpacity>
          <View style={S.headerPill}>
            <View style={S.liveIndicator} />
            <Text style={S.headerPillText}>CALL ANALYZER</Text>
          </View>
          <View style={{ width: 70 }} />
        </View>

        {/* Content */}
        <View style={{ flex: 1 }}>
          {renderContent()}
        </View>
      </Animated.View>
    </Animated.View>
  );
}

// ─── Sub-views ─────────────────────────────────────────────────────────────────

function ChoosingView({ onSpeak, onTap }: { onSpeak: () => void; onTap: () => void }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(30)).current;
  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn, { toValue: 1, duration: 400, useNativeDriver: true }),
      Animated.spring(slideUp, { toValue: 0, tension: 80, friction: 10, useNativeDriver: true }),
    ]).start();
  }, []);

  return (
    <Animated.View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24, opacity: fadeIn, transform: [{ translateY: slideUp }] }}>
      {/* Icon */}
      <View style={{ width: 80, height: 80, borderRadius: 40, backgroundColor: 'rgba(0,243,255,0.12)', borderWidth: 1, borderColor: 'rgba(0,243,255,0.3)', alignItems: 'center', justifyContent: 'center', marginBottom: 28, shadowColor: C.cyan, shadowRadius: 20, shadowOpacity: 0.5 }}>
        <Ionicons name="shield-checkmark" size={36} color={C.cyan} />
      </View>

      <Text style={[S.title, { textAlign: 'center', marginBottom: 8 }]}>Suspicious Call?</Text>
      <Text style={[S.mutedText, { textAlign: 'center', marginBottom: 40, lineHeight: 22 }]}>
        Tell SafeMail X what is happening{'\n'}to get an instant scam analysis.
      </Text>

      {/* Path A */}
      <ChoiceCard
        icon="mic"
        iconColor={C.cyan}
        title="Speak It"
        subtitle="Record a 20-second voice description"
        onPress={onSpeak}
        glowColor={C.cyan}
      />

      <View style={{ height: 14 }} />

      {/* Path B */}
      <ChoiceCard
        icon="list"
        iconColor={C.violet}
        title="Tap to Describe"
        subtitle="Use quick-tap checkboxes"
        onPress={onTap}
        glowColor={C.violet}
      />
    </Animated.View>
  );
}

function ChoiceCard({ icon, iconColor, title, subtitle, onPress, glowColor }: {
  icon: any; iconColor: string; title: string; subtitle: string; onPress: () => void; glowColor: string;
}) {
  const scale = useRef(new Animated.Value(1)).current;
  return (
    <TouchableOpacity
      onPressIn={() => Animated.spring(scale, { toValue: 0.97, useNativeDriver: true }).start()}
      onPressOut={() => Animated.spring(scale, { toValue: 1, useNativeDriver: true }).start()}
      onPress={onPress}
      activeOpacity={1}
      style={{ width: '100%' }}
    >
      <Animated.View style={[{
        flexDirection: 'row', alignItems: 'center',
        backgroundColor: 'rgba(255,255,255,0.05)',
        borderRadius: 20, borderWidth: 1, borderColor: 'rgba(255,255,255,0.1)',
        padding: 20, transform: [{ scale }],
        shadowColor: glowColor, shadowRadius: 12, shadowOpacity: 0.15,
      }]}>
        <View style={{ width: 52, height: 52, borderRadius: 26, backgroundColor: `${iconColor}18`, borderWidth: 1, borderColor: `${iconColor}40`, alignItems: 'center', justifyContent: 'center' }}>
          <Ionicons name={icon} size={26} color={iconColor} />
        </View>
        <View style={{ marginLeft: 18, flex: 1 }}>
          <Text style={{ fontSize: 18, fontWeight: '700', color: '#fff', marginBottom: 4 }}>{title}</Text>
          <Text style={{ fontSize: 13, color: 'rgba(255,255,255,0.45)' }}>{subtitle}</Text>
        </View>
        <Ionicons name="chevron-forward" size={20} color="rgba(255,255,255,0.3)" />
      </Animated.View>
    </TouchableOpacity>
  );
}

function StructuredForm({ orgClaimed, setOrgClaimed, actions, setActions, warnings, setWarnings, onToggle }: any) {
  const ORGS = ['SBI Bank', 'HDFC', 'ICICI', 'UIDAI', 'Police/CBI', 'Customs', 'Income Tax'];
  const ACTIONS = ['OTP or PIN', 'Card details / CVV', 'Aadhaar number', 'Transfer money', 'Install an app', 'Share screen'];
  const WARNINGS = ['Account will be blocked', 'Arrest warrant / FIR', "Don't tell anyone", 'Stay on the line'];

  return (
    <View>
      <SectionHeader label="Who do they claim to be?" color={C.cyan} icon="business" />
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 8 }}>
        {ORGS.map(org => (
          <AnimatedChip key={org} label={org} active={orgClaimed === org} color={C.cyan}
            onPress={() => setOrgClaimed(org === orgClaimed ? '' : org)} />
        ))}
      </View>

      <SectionHeader label="What did they ask for?" color={C.rose} icon="alert-circle" />
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 8 }}>
        {ACTIONS.map(act => (
          <AnimatedChip key={act} label={act} active={actions.includes(act)} color={C.rose}
            onPress={() => onToggle(actions, setActions, act)} />
        ))}
      </View>

      <SectionHeader label="Did they say any of these?" color={C.gold} icon="warning" />
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 8 }}>
        {WARNINGS.map(w => (
          <AnimatedChip key={w} label={w} active={warnings.includes(w)} color={C.gold}
            onPress={() => onToggle(warnings, setWarnings, w)} />
        ))}
      </View>
    </View>
  );
}

function SectionHeader({ label, color, icon }: { label: string; color: string; icon: any }) {
  return (
    <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 28, marginBottom: 12 }}>
      <Ionicons name={icon} size={16} color={color} style={{ marginRight: 8 }} />
      <Text style={{ fontSize: 11, color, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1.2 }}>{label}</Text>
    </View>
  );
}

function AnalyzingView() {
  const spin = useRef(new Animated.Value(0)).current;
  const pulse = useRef(new Animated.Value(0.8)).current;
  const dot1 = useRef(new Animated.Value(0)).current;
  const dot2 = useRef(new Animated.Value(0)).current;
  const dot3 = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.loop(Animated.timing(spin, { toValue: 1, duration: 1800, useNativeDriver: true })).start();
    Animated.loop(Animated.sequence([
      Animated.timing(pulse, { toValue: 1.1, duration: 800, useNativeDriver: true }),
      Animated.timing(pulse, { toValue: 0.8, duration: 800, useNativeDriver: true }),
    ])).start();
    const dotAnim = (d: Animated.Value, delay: number) => Animated.loop(Animated.sequence([
      Animated.delay(delay),
      Animated.timing(d, { toValue: 1, duration: 300, useNativeDriver: true }),
      Animated.timing(d, { toValue: 0, duration: 300, useNativeDriver: true }),
      Animated.delay(600),
    ]));
    dotAnim(dot1, 0).start(); dotAnim(dot2, 300).start(); dotAnim(dot3, 600).start();
  }, []);

  const rotate = spin.interpolate({ inputRange: [0, 1], outputRange: ['0deg', '360deg'] });

  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <Animated.View style={{ transform: [{ rotate }, { scale: pulse }] }}>
        <View style={{ width: 90, height: 90, borderRadius: 45, borderWidth: 2, borderColor: C.cyan, borderTopColor: 'transparent', alignItems: 'center', justifyContent: 'center', shadowColor: C.cyan, shadowRadius: 20, shadowOpacity: 0.6 }}>
          <Ionicons name="shield-checkmark" size={32} color={C.cyan} />
        </View>
      </Animated.View>
      <Text style={[S.title, { marginTop: 32, marginBottom: 8, textAlign: 'center' }]}>Analyzing Call</Text>
      <Text style={[S.mutedText, { textAlign: 'center' }]}>7-layer Scam Intelligence Engine</Text>
      <View style={{ flexDirection: 'row', marginTop: 24, gap: 8 }}>
        {[dot1, dot2, dot3].map((d, i) => (
          <Animated.View key={i} style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: C.cyan, opacity: d }} />
        ))}
      </View>
      {['Policy Check', 'Manipulation Detect', 'Script Match', 'Isolation Signal'].map((layer, i) => (
        <Text key={i} style={{ color: 'rgba(0,243,255,0.4)', fontSize: 11, marginTop: 6, letterSpacing: 0.8 }}>
          ▶ {layer}
        </Text>
      ))}
    </View>
  );
}

function VerdictView({ result, onClose, onRetry }: { result: CallAnalysisResult; onClose: () => void; onRetry: () => void }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(40)).current;
  const scoreAnim = useRef(new Animated.Value(0)).current;
  const [displayScore, setDisplayScore] = useState(0);

  const isCritical = result.risk_band === 'CRITICAL';
  const isSafe = result.risk_band === 'SAFE';
  const color = isCritical ? C.rose : (isSafe ? C.green : C.gold);
  const label = isCritical ? '🔴 CRITICAL — SCAM' : (isSafe ? '🟢 SAFE' : '🟡 SUSPICIOUS');

  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn, { toValue: 1, duration: 500, useNativeDriver: true }),
      Animated.spring(slideUp, { toValue: 0, tension: 70, friction: 10, useNativeDriver: true }),
    ]).start();
    scoreAnim.addListener(({ value }) => setDisplayScore(Math.round(value)));
    Animated.timing(scoreAnim, { toValue: result.score_display, duration: 1200, useNativeDriver: false }).start();
    return () => scoreAnim.removeAllListeners();
  }, []);

  return (
    <Animated.ScrollView
      contentContainerStyle={{ padding: 24, paddingBottom: 120 }}
      showsVerticalScrollIndicator={false}
      style={{ opacity: fadeIn, transform: [{ translateY: slideUp }] }}
    >
      {/* Score card */}
      <View style={{ alignItems: 'center', marginBottom: 28 }}>
        <View style={{ width: 130, height: 130, borderRadius: 65, backgroundColor: `${color}18`, borderWidth: 2, borderColor: color, alignItems: 'center', justifyContent: 'center', shadowColor: color, shadowRadius: 24, shadowOpacity: 0.6, marginBottom: 16 }}>
          <Text style={{ fontSize: 36, fontWeight: '800', color }}>{displayScore}</Text>
          <Text style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)', letterSpacing: 1 }}>RISK SCORE</Text>
        </View>
        <Text style={{ fontSize: 20, fontWeight: '800', color, letterSpacing: 0.5 }}>{label}</Text>
      </View>

      {/* Flags */}
      {result.why_flagged.length > 0 && (
        <View style={[glassStyles.card, { marginBottom: 16, borderColor: `${color}40` }]}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 14 }}>
            <Ionicons name="alert-circle" size={16} color={color} style={{ marginRight: 8 }} />
            <Text style={{ color, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Why Flagged</Text>
          </View>
          {result.why_flagged.map((f, i) => (
            <View key={i} style={{ flexDirection: 'row', marginBottom: 12, paddingLeft: 8, borderLeftWidth: 2, borderLeftColor: color }}>
              <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 13, lineHeight: 20, flex: 1, fontStyle: 'italic' }}>{f}</Text>
            </View>
          ))}
        </View>
      )}

      {/* Recommended action */}
      {result.recommended_action ? (
        <View style={[glassStyles.card, { marginBottom: 16 }]}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
            <Ionicons name="checkmark-circle" size={16} color={C.cyan} style={{ marginRight: 8 }} />
            <Text style={{ color: C.cyan, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Recommended Action</Text>
          </View>
          <Text style={{ color: '#fff', fontSize: 14, lineHeight: 21 }}>{result.recommended_action}</Text>
        </View>
      ) : null}

      {/* Official number */}
      {result.official_callback_number ? (
        <View style={[glassStyles.card, { marginBottom: 24 }]}>
          <Text style={{ color: 'rgba(255,255,255,0.5)', fontSize: 11, marginBottom: 6, letterSpacing: 1, textTransform: 'uppercase' }}>Official Helpline</Text>
          <Text style={{ color: C.cyan, fontSize: 18, fontWeight: '700' }}>{result.official_callback_number}</Text>
          <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: 12, marginTop: 4 }}>Call this number to verify — not the number they gave you.</Text>
        </View>
      ) : null}

      {/* CTAs */}
      {isCritical && (
        <TouchableOpacity style={[S.primaryBtn, { backgroundColor: C.rose, marginBottom: 12 }]} onPress={() => Linking.openURL('tel:')}>
          <Text style={S.btnText}>📵  Hang Up Now</Text>
        </TouchableOpacity>
      )}
      <TouchableOpacity style={[S.primaryBtn, { backgroundColor: 'rgba(255,255,255,0.08)', marginBottom: 12 }]} onPress={onRetry}>
        <Text style={[S.btnText, { color: 'rgba(255,255,255,0.7)' }]}>Analyze Another Call</Text>
      </TouchableOpacity>
      <TouchableOpacity style={S.closeBtn} onPress={onClose}>
        <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 15 }}>Close</Text>
      </TouchableOpacity>
    </Animated.ScrollView>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const S = StyleSheet.create({
  sheet: {
    flex: 1,
    backgroundColor: 'rgba(6,8,15,0.98)',
    borderTopLeftRadius: 28,
    borderTopRightRadius: 28,
    overflow: 'hidden',
  },
  headerBar: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255,255,255,0.06)',
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
    gap: 8,
  },
  headerPillText: {
    color: '#00f3ff',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 1.5,
  },
  liveIndicator: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: '#00f3ff',
    shadowColor: '#00f3ff',
    shadowRadius: 4,
    shadowOpacity: 1,
  },
  title: {
    fontSize: 26,
    fontWeight: '700',
    color: '#fff',
    letterSpacing: -0.3,
  },
  mutedText: {
    color: 'rgba(255,255,255,0.45)',
    fontSize: 14,
    lineHeight: 20,
  },
  sectionLabel: {
    fontSize: 13,
    color: 'rgba(255,255,255,0.5)',
    letterSpacing: 1,
    textTransform: 'uppercase',
    marginBottom: 16,
    textAlign: 'center',
  },
  timerText: {
    fontSize: 64,
    fontWeight: '200',
    color: '#fff',
    letterSpacing: 4,
    marginTop: 8,
    // fontVariant: ['tabular-nums'],  // removed — causes crash on some RN versions
  },
  primaryBtn: {
    backgroundColor: '#00f3ff',
    padding: 18,
    borderRadius: 16,
    width: '100%',
    alignItems: 'center',
    shadowColor: '#00f3ff',
    shadowRadius: 10,
    shadowOpacity: 0.3,
    elevation: 6,
  },
  stopBtn: {
    backgroundColor: 'rgba(255,61,113,0.15)',
    padding: 18,
    borderRadius: 16,
    width: '100%',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#ff3d71',
    shadowColor: '#ff3d71',
    shadowRadius: 8,
    shadowOpacity: 0.3,
  },
  btnText: {
    color: '#06080f',
    fontSize: 16,
    fontWeight: '700',
    letterSpacing: 0.3,
  },
  closeBtn: {
    alignItems: 'center',
    padding: 12,
  },
});
