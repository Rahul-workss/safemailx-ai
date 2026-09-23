import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView,
  Animated, BackHandler, Linking, Dimensions, Platform, Image,
  TextInput, KeyboardAvoidingView,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import Svg, { Path, Defs, LinearGradient as SvgLinearGradient, Stop, RadialGradient } from 'react-native-svg';

import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import {
  ExpoSpeechRecognitionModule,
  useSpeechRecognitionEvent,
  type ExpoSpeechRecognitionOptions,
} from 'expo-speech-recognition';
import { analyzeCall, CallAnalysisResult } from '../api';

const { height: SCREEN_HEIGHT, width: SCREEN_WIDTH } = Dimensions.get('window');

type ScreenState = 'CHOOSING' | 'RECORDING' | 'REVIEW' | 'STRUCTURED' | 'ANALYZING' | 'VERDICT' | 'ERROR';

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
    // Keep native driver (scale) and JS driver (glow) SEPARATE — never mix on same node
    Animated.spring(scale, { toValue: active ? 1.04 : 1, useNativeDriver: true }).start();
    Animated.timing(glow, { toValue: active ? 1 : 0, duration: 200, useNativeDriver: false }).start();
  }, [active]);

  const bgColor = glow.interpolate({ inputRange: [0, 1], outputRange: ['rgba(255,255,255,0.05)', `${color}20`] });
  const borderColor = glow.interpolate({ inputRange: [0, 1], outputRange: ['rgba(255,255,255,0.09)', color] });

  return (
    <TouchableOpacity onPress={onPress} activeOpacity={0.8}>
      {/* Outer: JS-driven colors (useNativeDriver: false) */}
      <Animated.View style={[chipStyles.chip, { backgroundColor: bgColor, borderColor }]}>
        {/* Inner: native-driven transform (useNativeDriver: true) — separate node */}
        <Animated.View style={{ transform: [{ scale }] }}>
          <Text style={[chipStyles.text, active && { color, fontWeight: '700' }]}>{label}</Text>
        </Animated.View>
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

  // ── Path A — Live Transcription (expo-speech-recognition) ──────────────────
  const [timeLeft, setTimeLeft] = useState(20);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timeLeftRef = useRef(20);

  // Transcript state: finalTranscript = confirmed sentences, partialTranscript = live current word stream
  const [finalTranscript, setFinalTranscript] = useState('');
  const [partialTranscript, setPartialTranscript] = useState('');
  const [reviewTranscript, setReviewTranscript] = useState(''); // editable in REVIEW state
  const isRecognizingRef = useRef(false);
  const finalTranscriptRef = useRef(''); // ref so speech event handlers always see latest value

  // Waveform bar animations (5 bars)
  const bar1 = useRef(new Animated.Value(4)).current;
  const bar2 = useRef(new Animated.Value(8)).current;
  const bar3 = useRef(new Animated.Value(14)).current;
  const bar4 = useRef(new Animated.Value(8)).current;
  const bar5 = useRef(new Animated.Value(4)).current;
  const waveAniRef = useRef<Animated.CompositeAnimation | null>(null);

  // Recording dot pulse
  const recDotOpacity = useRef(new Animated.Value(1)).current;
  const recDotAniRef = useRef<Animated.CompositeAnimation | null>(null);

  // ── Speech recognition event hooks ─────────────────────────────────────────
  useSpeechRecognitionEvent('result', (event) => {
    if (event.isFinal) {
      // A sentence was finalized — append to running transcript
      const newText = event.results?.[0]?.transcript ?? '';
      if (newText.trim()) {
        const updated = finalTranscriptRef.current
          ? finalTranscriptRef.current + ' ' + newText.trim()
          : newText.trim();
        finalTranscriptRef.current = updated;
        setFinalTranscript(updated);
      }
      setPartialTranscript('');
      // Restart immediately if still within recording window (restart-on-pause trick)
      if (isRecognizingRef.current && timeLeftRef.current > 1) {
        restartRecognizer();
      }
    } else {
      // Live partial result — display as they speak
      const partial = event.results?.[0]?.transcript ?? '';
      setPartialTranscript(partial);
    }
  });

  useSpeechRecognitionEvent('error', (event) => {
    // "no-speech" is expected when user pauses — just restart quietly
    if (event.error === 'no-speech' && isRecognizingRef.current && timeLeftRef.current > 1) {
      restartRecognizer();
    }
    // Other errors: stop silently, keep whatever transcript we have
    setPartialTranscript('');
  });

  useSpeechRecognitionEvent('end', (_event) => {
    // Recognizer stopped — restart if still in recording window
    if (isRecognizingRef.current && timeLeftRef.current > 1) {
      restartRecognizer();
    }
  });

  const restartRecognizer = () => {
    try {
      ExpoSpeechRecognitionModule.start({
        lang: 'en-IN',
        interimResults: true,
        continuous: false, // auto-segments sentences naturally
        addsPunctuation: true,
        contextualStrings: [
          'OTP', 'KYC', 'Aadhaar', 'UIDAI', 'UPI', 'IFSC', 'CVV', 'PIN', 'PAN',
          'AnyDesk', 'TeamViewer', 'SBI', 'HDFC', 'ICICI', 'TRAI', 'RBI',
          'digital arrest', 'customs', 'CBI', 'scam', 'fraud', 'phishing',
        ],
      });
    } catch (_) { /* ignore if start fails mid-session */ }
  };

  const startWaveAnimation = () => {
    const makeWave = (bar: Animated.Value, min: number, max: number, dur: number) =>
      Animated.loop(Animated.sequence([
        Animated.timing(bar, { toValue: max, duration: dur, useNativeDriver: false }),
        Animated.timing(bar, { toValue: min, duration: dur, useNativeDriver: false }),
      ]));
    waveAniRef.current = Animated.parallel([
      makeWave(bar1, 4, 18, 280),
      makeWave(bar2, 6, 26, 340),
      makeWave(bar3, 8, 32, 260),
      makeWave(bar4, 6, 22, 380),
      makeWave(bar5, 4, 16, 310),
    ]);
    waveAniRef.current.start();
  };

  const stopWaveAnimation = () => {
    waveAniRef.current?.stop();
    [bar1, bar2, bar3, bar4, bar5].forEach(b => b.setValue(4));
  };

  const startRecDotPulse = () => {
    recDotAniRef.current = Animated.loop(Animated.sequence([
      Animated.timing(recDotOpacity, { toValue: 0.2, duration: 500, useNativeDriver: true }),
      Animated.timing(recDotOpacity, { toValue: 1.0, duration: 500, useNativeDriver: true }),
    ]));
    recDotAniRef.current.start();
  };

  const stopRecDotPulse = () => {
    recDotAniRef.current?.stop();
    recDotOpacity.setValue(1);
  };

  // ── Start live transcription ────────────────────────────────────────────────
  const startRecording = async () => {
    try {
      const result = await ExpoSpeechRecognitionModule.requestPermissionsAsync();
      if (!result.granted) {
        // Fallback to form mode if mic denied
        setScreenState('STRUCTURED');
        return;
      }

      // Reset all transcript state
      finalTranscriptRef.current = '';
      setFinalTranscript('');
      setPartialTranscript('');
      setReviewTranscript('');
      timeLeftRef.current = 20;
      setTimeLeft(20);
      isRecognizingRef.current = true;

      setScreenState('RECORDING');
      startWaveAnimation();
      startRecDotPulse();

      // Start the recognizer
      ExpoSpeechRecognitionModule.start({
        lang: 'en-IN',
        interimResults: true,
        continuous: false,
        addsPunctuation: true,
        contextualStrings: [
          'OTP', 'KYC', 'Aadhaar', 'UIDAI', 'UPI', 'IFSC', 'CVV', 'PIN', 'PAN',
          'AnyDesk', 'TeamViewer', 'SBI', 'HDFC', 'ICICI', 'TRAI', 'RBI',
          'digital arrest', 'customs', 'CBI', 'scam', 'fraud', 'phishing',
        ],
      });

      // 20-second countdown timer
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

  // ── Stop recording and move to REVIEW ──────────────────────────────────────
  const finishRecording = () => {
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    isRecognizingRef.current = false;
    try { ExpoSpeechRecognitionModule.stop(); } catch (_) {}
    stopWaveAnimation();
    stopRecDotPulse();

    // Small delay to let final 'result' event fire and append last sentence
    setTimeout(() => {
      const captured = finalTranscriptRef.current.trim();
      if (!captured || captured.split(' ').length < 5) {
        // Nothing captured — stay on RECORDING and reset, let user try again
        setFinalTranscript('');
        setPartialTranscript('');
        setTimeLeft(20);
        timeLeftRef.current = 20;
        isRecognizingRef.current = true;
        startRecDotPulse();
        ExpoSpeechRecognitionModule.start({
          lang: 'en-IN', interimResults: true, continuous: false,
          addsPunctuation: true,
        });
        timerRef.current = setInterval(() => {
          timeLeftRef.current -= 1;
          setTimeLeft(timeLeftRef.current);
          if (timeLeftRef.current <= 0) finishRecording();
        }, 1000);
        return;
      }
      // Move to REVIEW with the captured transcript
      setReviewTranscript(captured);
      setScreenState('REVIEW');
    }, 600);
  };

  // ── Submit transcript for analysis ─────────────────────────────────────────
  const submitTranscript = async (text: string) => {
    const cleaned = text.trim();
    if (!cleaned) return;
    setAnalyzing(true);
    setScreenState('ANALYZING');
    try {
      const res = await analyzeCall({ inputMode: 'transcript', transcript: cleaned });
      setResult(res);
      setScreenState('VERDICT');
    } catch (e: any) {
      setErrorMsg(e.message || 'Analysis failed');
      setScreenState('ERROR');
    } finally {
      setAnalyzing(false);
    }
  };

  // ── Cleanup on unmount ──────────────────────────────────────────────────────
  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      isRecognizingRef.current = false;
      try { ExpoSpeechRecognitionModule.stop(); } catch (_) {}
      stopWaveAnimation();
      stopRecDotPulse();
    };
  }, []);

  const stopRecordingIfNeeded = () => {
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    isRecognizingRef.current = false;
    try { ExpoSpeechRecognitionModule.stop(); } catch (_) {}
    stopWaveAnimation();
    stopRecDotPulse();
  };

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
    } else if (screenState === 'REVIEW') {
      // From review, go back to re-record
      finalTranscriptRef.current = '';
      setFinalTranscript('');
      setPartialTranscript('');
      setReviewTranscript('');
      startRecording();
    } else if (screenState === 'VERDICT' || screenState === 'ERROR') {
      setScreenState('CHOOSING');
      setResult(null);
      setErrorMsg('');
    }
  }, [screenState]);

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

      // ── RECORDING: Live transcript with waveform ──────────────────────────
      case 'RECORDING': {
        const displayText = finalTranscript
          ? (partialTranscript ? finalTranscript + ' ' + partialTranscript : finalTranscript)
          : partialTranscript;
        const isEmpty = !displayText.trim();

        return (
          <View style={{ flex: 1, padding: 20, paddingTop: 12 }}>

            {/* ── Timer row ── */}
            <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                <Animated.View style={{
                  width: 10, height: 10, borderRadius: 5,
                  backgroundColor: C.rose, opacity: recDotOpacity,
                  shadowColor: C.rose, shadowRadius: 6, shadowOpacity: 0.8,
                }} />
                <Text style={{ color: C.rose, fontSize: 12, fontWeight: '700', letterSpacing: 1 }}>LISTENING</Text>
              </View>
              <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: 11 }}>
                  {timeLeft <= 5 ? '⚠️' : '⏱'}
                </Text>
                <Text style={{
                  fontSize: 28, fontWeight: '200', color: timeLeft <= 5 ? C.rose : '#fff',
                  letterSpacing: 2,
                }}>{timeLeft.toString().padStart(2, '0')}s</Text>
              </View>
            </View>

            {/* ── Progress bar ── */}
            <View style={{ height: 2, backgroundColor: 'rgba(255,255,255,0.06)', borderRadius: 1, marginBottom: 20 }}>
              <View style={{
                height: 2, borderRadius: 1, backgroundColor: C.cyan,
                width: `${((20 - timeLeft) / 20) * 100}%`,
              }} />
            </View>

            {/* ── Live Transcript Card ── */}
            <View style={{ flex: 1 }}>
              <View style={{
                flex: 1,
                borderRadius: 20, borderWidth: 1,
                borderColor: isEmpty ? 'rgba(255,255,255,0.08)' : `${C.cyan}40`,
                overflow: 'hidden',
                minHeight: 180,
              }}>
                <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
                <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.4)' }]} />
                <LinearGradient
                  colors={['rgba(255,255,255,0.06)', 'rgba(255,255,255,0.0)']}
                  start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
                  style={StyleSheet.absoluteFillObject}
                />
                <View style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, backgroundColor: 'rgba(255,255,255,0.12)' }} />

                <View style={{ flex: 1, padding: 18, justifyContent: 'flex-end' }}>
                  {isEmpty ? (
                    <Text style={{ color: 'rgba(255,255,255,0.2)', fontSize: 15, textAlign: 'center', lineHeight: 24 }}>
                      {"Speak clearly...\n\nTell us who called and\nwhat they asked for"}
                    </Text>
                  ) : (
                    <Text style={{ color: '#fff', fontSize: 16, lineHeight: 26, letterSpacing: 0.2 }}>
                      {/* Final (confirmed) text in full white */}
                      {finalTranscript ? (
                        <Text style={{ color: '#ffffff' }}>{finalTranscript}</Text>
                      ) : null}
                      {/* Partial (live) text in dimmer white */}
                      {partialTranscript ? (
                        <Text style={{ color: 'rgba(255,255,255,0.5)' }}>
                          {finalTranscript ? ' ' : ''}{partialTranscript}
                        </Text>
                      ) : null}
                      {/* Blinking cursor */}
                      <Text style={{ color: C.cyan }}>▌</Text>
                    </Text>
                  )}
                </View>
              </View>
            </View>

            {/* ── Waveform bars ── */}
            <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 5, marginTop: 20, height: 36 }}>
              {[bar1, bar2, bar3, bar4, bar5].map((bar, i) => (
                <Animated.View key={i} style={{
                  width: 4, height: bar, borderRadius: 2,
                  backgroundColor: C.cyan, opacity: 0.7,
                }} />
              ))}
            </View>

            {/* ── Hint + Stop button ── */}
            <Text style={{ color: 'rgba(255,255,255,0.3)', fontSize: 12, textAlign: 'center', marginTop: 14 }}>
              Speak clearly · English or Hinglish both work
            </Text>
            <TouchableOpacity
              style={[S.stopBtn, { marginTop: 14 }]}
              onPress={finishRecording}
            >
              <Text style={[S.btnText, { color: C.rose }]}>Stop & Review →</Text>
            </TouchableOpacity>
          </View>
        );
      }

      // ── REVIEW: Editable transcript before analysis ───────────────────────
      case 'REVIEW': {
        const wordCount = reviewTranscript.trim().split(/\s+/).filter(Boolean).length;
        const canAnalyze = wordCount >= 5;

        return (
          <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
            <ScrollView
              contentContainerStyle={{ padding: 20, paddingBottom: 40 }}
              keyboardShouldPersistTaps="handled"
              showsVerticalScrollIndicator={false}
            >
              {/* ── Header ── */}
              <View style={{ alignItems: 'center', marginBottom: 20 }}>
                <View style={{
                  width: 56, height: 56, borderRadius: 28,
                  backgroundColor: `${C.green}20`, alignItems: 'center', justifyContent: 'center',
                  borderWidth: 1, borderColor: `${C.green}50`, marginBottom: 12,
                }}>
                  <Ionicons name="checkmark-circle" size={28} color={C.green} />
                </View>
                <Text style={{ color: '#fff', fontSize: 20, fontWeight: '700' }}>Got it!</Text>
                <Text style={{ color: 'rgba(255,255,255,0.5)', fontSize: 13, marginTop: 4, textAlign: 'center' }}>
                  Review what we heard. Tap the text to fix any errors.
                </Text>
              </View>

              {/* ── Editable transcript card ── */}
              <View style={{
                borderRadius: 20, borderWidth: 1,
                borderColor: `${C.cyan}40`, overflow: 'hidden', marginBottom: 16,
              }}>
                <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
                <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.4)' }]} />
                <LinearGradient
                  colors={['rgba(255,255,255,0.06)', 'rgba(255,255,255,0.0)']}
                  start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
                  style={StyleSheet.absoluteFillObject}
                />
                <View style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, backgroundColor: 'rgba(255,255,255,0.12)' }} />

                <View style={{ padding: 16 }}>
                  <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
                    <Ionicons name="mic" size={14} color={C.cyan} style={{ marginRight: 6 }} />
                    <Text style={{ color: C.cyan, fontSize: 10, fontWeight: '700', letterSpacing: 1, textTransform: 'uppercase' }}>
                      Transcribed · Tap to edit
                    </Text>
                  </View>
                  <TextInput
                    value={reviewTranscript}
                    onChangeText={setReviewTranscript}
                    multiline
                    style={{
                      color: '#fff', fontSize: 15, lineHeight: 24,
                      textAlignVertical: 'top', minHeight: 100,
                    }}
                    placeholderTextColor="rgba(255,255,255,0.3)"
                    placeholder="Your description will appear here..."
                  />
                </View>
              </View>

              {/* ── Word count hint ── */}
              {!canAnalyze && (
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6, marginBottom: 12 }}>
                  <Ionicons name="warning" size={14} color={C.gold} />
                  <Text style={{ color: C.gold, fontSize: 12 }}>
                    Add a few more words to get an accurate analysis.
                  </Text>
                </View>
              )}

              {/* ── Analyze button ── */}
              <TouchableOpacity
                style={[S.primaryBtn, { opacity: canAnalyze ? 1 : 0.4, marginBottom: 12 }]}
                disabled={!canAnalyze}
                onPress={() => submitTranscript(reviewTranscript)}
              >
                <Text style={S.btnText}>🔍 Analyze This Call →</Text>
              </TouchableOpacity>

              {/* ── Re-record button ── */}
              <TouchableOpacity
                style={{ padding: 14, alignItems: 'center' }}
                onPress={() => {
                  finalTranscriptRef.current = '';
                  setFinalTranscript('');
                  setPartialTranscript('');
                  setReviewTranscript('');
                  startRecording();
                }}
              >
                <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: 14 }}>🔄  Re-record</Text>
              </TouchableOpacity>
            </ScrollView>
          </KeyboardAvoidingView>
        );
      }

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
      {/* ── Dashboard-style Base Background ── */}
      <View style={[StyleSheet.absoluteFill, { backgroundColor: '#000000' }]} />
      
      {/* Centered Logo Watermark (matches TmBg) */}
      <View style={{ ...StyleSheet.absoluteFillObject, justifyContent: "center", alignItems: "center" }} pointerEvents="none">
        <Image
          source={require('../../assets/new-logo.png')}
          style={{ width: SCREEN_WIDTH * 0.85, height: SCREEN_WIDTH * 0.85, resizeMode: "contain", opacity: 0.18 }}
        />
      </View>

      {/* Sheet (now transparent so background shows through, or solid black if preferred. Let's make it transparent) */}
      <Animated.View style={[S.sheet, { backgroundColor: 'transparent', transform: [{ translateY: slideAnim }], paddingTop: insets.top + 16, paddingBottom: insets.bottom }]}>
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
  // Entrance animations
  const fadeIn  = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(50)).current;
  const card1Y  = useRef(new Animated.Value(40)).current;
  const card2Y  = useRef(new Animated.Value(40)).current;
  const card1Op = useRef(new Animated.Value(0)).current;
  const card2Op = useRef(new Animated.Value(0)).current;

  // Shield animations
  const floatY      = useRef(new Animated.Value(0)).current;
  const shieldGlow  = useRef(new Animated.Value(0.5)).current;
  const shieldScale = useRef(new Animated.Value(1)).current;

  // Phone vibration (quick horizontal shake)
  const phoneShake  = useRef(new Animated.Value(0)).current;

  // 3 vibration arcs below shield (each pulses out from center)
  const arc1Scale   = useRef(new Animated.Value(0.3)).current;
  const arc2Scale   = useRef(new Animated.Value(0.3)).current;
  const arc3Scale   = useRef(new Animated.Value(0.3)).current;
  const arc1Op      = useRef(new Animated.Value(0.8)).current;
  const arc2Op      = useRef(new Animated.Value(0.6)).current;
  const arc3Op      = useRef(new Animated.Value(0.4)).current;

  // Bottom glow ring
  const ringScale   = useRef(new Animated.Value(0.8)).current;
  const ringOp      = useRef(new Animated.Value(0.4)).current;

  useEffect(() => {
    // Staggered entrance
    Animated.sequence([
      Animated.parallel([
        Animated.timing(fadeIn,  { toValue: 1, duration: 500, useNativeDriver: true }),
        Animated.spring(slideUp, { toValue: 0, tension: 60, friction: 10, useNativeDriver: true }),
      ]),
      Animated.parallel([
        Animated.spring(card1Y,  { toValue: 0, tension: 70, friction: 11, useNativeDriver: true }),
        Animated.timing(card1Op, { toValue: 1, duration: 300, useNativeDriver: true }),
      ]),
      Animated.parallel([
        Animated.spring(card2Y,  { toValue: 0, tension: 70, friction: 11, useNativeDriver: true }),
        Animated.timing(card2Op, { toValue: 1, duration: 300, useNativeDriver: true }),
      ]),
    ]).start();

    // Shield gentle float
    Animated.loop(Animated.sequence([
      Animated.timing(floatY, { toValue: -8, duration: 2200, useNativeDriver: true }),
      Animated.timing(floatY, { toValue:  0, duration: 2200, useNativeDriver: true }),
    ])).start();

    // Shield glow pulse
    Animated.loop(Animated.sequence([
      Animated.timing(shieldGlow, { toValue: 1.0, duration: 1600, useNativeDriver: true }),
      Animated.timing(shieldGlow, { toValue: 0.5, duration: 1600, useNativeDriver: true }),
    ])).start();

    // Shield subtle scale pulse
    Animated.loop(Animated.sequence([
      Animated.timing(shieldScale, { toValue: 1.04, duration: 1600, useNativeDriver: true }),
      Animated.timing(shieldScale, { toValue: 1.00, duration: 1600, useNativeDriver: true }),
    ])).start();

    // Phone vibration — rapid left-right jiggle looping
    const vibrate = () =>
      Animated.loop(Animated.sequence([
        Animated.timing(phoneShake, { toValue:  4, duration: 60, useNativeDriver: true }),
        Animated.timing(phoneShake, { toValue: -4, duration: 60, useNativeDriver: true }),
        Animated.timing(phoneShake, { toValue:  3, duration: 60, useNativeDriver: true }),
        Animated.timing(phoneShake, { toValue: -3, duration: 60, useNativeDriver: true }),
        Animated.timing(phoneShake, { toValue:  0, duration: 60, useNativeDriver: true }),
        Animated.delay(1400), // pause between vibrations
      ]));
    vibrate().start();

    // Vibration arcs — staggered outward pulses
    const arc = (scale: Animated.Value, opacity: Animated.Value, delay: number) =>
      Animated.loop(Animated.sequence([
        Animated.delay(delay),
        Animated.parallel([
          Animated.timing(scale,   { toValue: 1.0, duration: 700, useNativeDriver: true }),
          Animated.timing(opacity, { toValue: 0,   duration: 700, useNativeDriver: true }),
        ]),
        Animated.parallel([
          Animated.timing(scale,   { toValue: 0.3, duration: 0, useNativeDriver: true }),
          Animated.timing(opacity, { toValue: 0.8, duration: 0, useNativeDriver: true }),
        ]),
        Animated.delay(1700 - delay), // keep total loop = 1700ms
      ]));
    arc(arc1Scale, arc1Op, 0).start();
    arc(arc2Scale, arc2Op, 250).start();
    arc(arc3Scale, arc3Op, 500).start();

    // Bottom glow ring breathe
    Animated.loop(Animated.sequence([
      Animated.timing(ringScale, { toValue: 1.1, duration: 1800, useNativeDriver: true }),
      Animated.timing(ringScale, { toValue: 0.8, duration: 1800, useNativeDriver: true }),
    ])).start();
    Animated.loop(Animated.sequence([
      Animated.timing(ringOp, { toValue: 0.7, duration: 1800, useNativeDriver: true }),
      Animated.timing(ringOp, { toValue: 0.2, duration: 1800, useNativeDriver: true }),
    ])).start();
  }, []);



  return (
    <Animated.View style={{ flex: 1, opacity: fadeIn }}>
      <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 24 }}>

        {/* ── Shield + Vibration ── */}
        <Animated.View style={{ transform: [{ translateY: slideUp }], alignItems: 'center', marginBottom: 36 }}>
          <Animated.View style={{ transform: [{ translateY: floatY }], alignItems: 'center' }}>

            {/* ── True Liquid Glass SVG Shield ── */}
            <Animated.View style={{
              width: 140, height: 160,
              alignItems: 'center', justifyContent: 'center',
              transform: [{ scale: shieldScale }],
            }}>
              {/* Outer glow halo */}
              <Animated.View style={{
                position: 'absolute',
                width: 140, height: 160,
                opacity: shieldGlow,
                shadowColor: C.cyan, shadowRadius: 50, shadowOpacity: 1,
              }}>
                 <Svg viewBox="0 0 24 24" width="140" height="160">
                   <Path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" fill="rgba(0,200,255,0.18)" />
                 </Svg>
              </Animated.View>

              {/* Shield Liquid Glass Layers */}
              <View style={{ position: 'absolute' }}>
                 <Svg viewBox="0 0 24 24" width="140" height="160">
                   <Defs>
                     {/* Liquid glass specular gradient (white diagonal sheen) */}
                     <SvgLinearGradient id="glassGradient" x1="0" y1="0" x2="1" y2="1">
                       <Stop offset="0" stopColor="rgba(255,255,255,0.45)" />
                       <Stop offset="0.25" stopColor="rgba(255,255,255,0.05)" />
                       <Stop offset="0.6" stopColor="rgba(0,180,255,0.02)" />
                       <Stop offset="1" stopColor="rgba(0,200,255,0.15)" />
                     </SvgLinearGradient>
                     
                     {/* Border glowing metallic edge */}
                     <SvgLinearGradient id="borderGradient" x1="0" y1="0" x2="0" y2="1">
                       <Stop offset="0" stopColor="rgba(200,255,255,0.95)" />
                       <Stop offset="0.4" stopColor="rgba(0,220,255,0.6)" />
                       <Stop offset="1" stopColor="rgba(0,100,255,0.9)" />
                     </SvgLinearGradient>
                     
                     {/* Deep blue core glow */}
                     <RadialGradient id="glow" cx="0.5" cy="0.3" r="0.7">
                       <Stop offset="0" stopColor="rgba(0,230,255,0.35)" />
                       <Stop offset="1" stopColor="rgba(0,20,80,0.4)" />
                     </RadialGradient>
                   </Defs>
                   
                   {/* Shield Deep Body */}
                   <Path 
                     d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" 
                     fill="url(#glow)" 
                   />
                   
                   {/* Specular Highlight layer */}
                   <Path 
                     d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" 
                     fill="url(#glassGradient)" 
                   />
                   
                   {/* Thick Glass Border */}
                   <Path 
                     d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" 
                     fill="none" 
                     stroke="url(#borderGradient)" 
                     strokeWidth="0.8" 
                     strokeLinejoin="round"
                   />
                 </Svg>
              </View>

              {/* Phone icon centered on shield, with vibration */}
              <Animated.View style={{ transform: [{ translateX: phoneShake }], marginTop: -15 }}>
                <Ionicons name="call" size={48} color="#fff" style={{ shadowColor: '#fff', shadowRadius: 10, shadowOpacity: 0.8 }} />
              </Animated.View>
            </Animated.View>

            {/* ── Vibration arcs below shield ── */}
            {/* These are stacked ellipse arcs, bottom-half only, like the reference */}
            <View style={{ alignItems: 'center', marginTop: -4 }}>
              {/* Arc 3 (outermost) */}
              <Animated.View style={{
                width: 120, height: 60, borderRadius: 60,
                borderWidth: 1.5, borderColor: 'rgba(0,200,255,0.6)',
                borderTopWidth: 0,
                transform: [{ scaleX: arc3Scale }, { scaleY: arc3Scale }],
                opacity: arc3Op,
                shadowColor: C.cyan, shadowRadius: 6, shadowOpacity: 0.5,
              }} />
              {/* Arc 2 */}
              <Animated.View style={{
                position: 'absolute',
                width: 80, height: 40, borderRadius: 40,
                borderWidth: 1.5, borderColor: 'rgba(0,220,255,0.75)',
                borderTopWidth: 0,
                transform: [{ scaleX: arc2Scale }, { scaleY: arc2Scale }],
                opacity: arc2Op,
                shadowColor: C.cyan, shadowRadius: 4, shadowOpacity: 0.6,
              }} />
              {/* Arc 1 (innermost) */}
              <Animated.View style={{
                position: 'absolute',
                width: 44, height: 22, borderRadius: 22,
                borderWidth: 1.5, borderColor: 'rgba(100,240,255,0.9)',
                borderTopWidth: 0,
                transform: [{ scaleX: arc1Scale }, { scaleY: arc1Scale }],
                opacity: arc1Op,
                shadowColor: '#fff', shadowRadius: 3, shadowOpacity: 0.8,
              }} />
            </View>

            {/* ── Bottom glow ring (platform) ── */}
            <Animated.View style={{
              width: 160, height: 20, borderRadius: 80,
              backgroundColor: 'transparent',
              borderWidth: 1, borderColor: 'rgba(0,200,255,0.35)',
              marginTop: 8,
              transform: [{ scaleX: ringScale }],
              opacity: ringOp,
              shadowColor: C.cyan, shadowRadius: 10, shadowOpacity: 0.7,
            }} />
          </Animated.View>
        </Animated.View>

        {/* ── Title ── */}
        <Animated.View style={{ transform: [{ translateY: slideUp }], alignItems: 'center', marginBottom: 36 }}>
          <Text style={{ fontSize: 30, fontWeight: '800', color: '#fff', textAlign: 'center', letterSpacing: -0.5 }}>
            Suspicious Call?
          </Text>
          <Text style={{ fontSize: 15, color: 'rgba(255,255,255,0.45)', textAlign: 'center', marginTop: 10, lineHeight: 22 }}>
            Tell SafeMail X what happened{'\n'}and get an instant scam verdict.
          </Text>
        </Animated.View>

        {/* ── Choice Cards ── */}
        <Animated.View style={{ width: '100%', opacity: card1Op, transform: [{ translateY: card1Y }] }}>
          <ChoiceCard
            icon="mic"
            iconColor={C.cyan}
            title="Speak It"
            subtitle="Record a 20-second voice description"
            badge="AI POWERED"
            badgeColor={C.cyan}
            onPress={onSpeak}
            glowColor={C.cyan}
          />
        </Animated.View>

        <View style={{ height: 14 }} />

        <Animated.View style={{ width: '100%', opacity: card2Op, transform: [{ translateY: card2Y }] }}>
          <ChoiceCard
            icon="list"
            iconColor={C.violet}
            title="Tap to Describe"
            subtitle="Use quick-tap checkboxes"
            badge="INSTANT"
            badgeColor={C.violet}
            onPress={onTap}
            glowColor={C.violet}
          />
        </Animated.View>

        {/* ── Bottom hint ── */}
        <Text style={{ color: 'rgba(255,255,255,0.2)', fontSize: 12, marginTop: 32, textAlign: 'center', letterSpacing: 0.5 }}>
          Powered by On-Device Speech · Qwen3 · Tavily
        </Text>
      </View>
    </Animated.View>
  );
}

function ChoiceCard({ icon, iconColor, title, subtitle, badge, badgeColor, onPress, glowColor }: {
  icon: any; iconColor: string; title: string; subtitle: string;
  badge?: string; badgeColor?: string; onPress: () => void; glowColor: string;
}) {
  const scale   = useRef(new Animated.Value(1)).current;
  const borderG = useRef(new Animated.Value(0)).current;

  const borderColor = borderG.interpolate({
    inputRange: [0, 1],
    outputRange: ['rgba(255,255,255,0.1)', glowColor + '80'],
  });
  const bgColor = borderG.interpolate({
    inputRange: [0, 1],
    outputRange: ['rgba(255,255,255,0.05)', glowColor + '12'],
  });

  return (
    <TouchableOpacity
      onPressIn={() => Animated.spring(scale, { toValue: 0.97, useNativeDriver: true }).start()}
      onPressOut={() => Animated.spring(scale, { toValue: 1, useNativeDriver: true }).start()}
      onPress={onPress}
      activeOpacity={1}
    >
      <Animated.View style={{
        borderRadius: 20,
        borderWidth: 1,
        borderColor: `${glowColor}60`, // 40-60% opacity like dashboard
        backgroundColor: `${glowColor}15`, // ~10% opacity like dashboard
        overflow: 'hidden',
        padding: 16, // matched dashboard padding
        transform: [{ scale }],
        // Exact dashboard shadows
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 16 },
        shadowOpacity: 0.8,
        shadowRadius: 20,
        elevation: 8,
      }}>
        {/* Frosted glass blur */}
        <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
        
        {/* Liquid glass deep color fill */}
        <View style={[StyleSheet.absoluteFillObject, { backgroundColor: "rgba(0, 0, 0, 0.35)" }]} />
        
        {/* Diagonal specular glossy sheen */}
        <LinearGradient
          colors={["rgba(255, 255, 255, 0.08)", "rgba(255, 255, 255, 0.01)", "rgba(255, 255, 255, 0.0)", "rgba(255, 255, 255, 0.03)"]}
          start={{ x: 0.1, y: 0 }}
          end={{ x: 0.9, y: 1 }}
          style={StyleSheet.absoluteFillObject}
        />

        {/* Polish crystal top lip highlight */}
        <View style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1.2, backgroundColor: "rgba(255, 255, 255, 0.15)" }} />

        {/* Content */}
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 12 }}>
          {/* Icon orb (Dashboard style: 44x44, radius 22, 20% opacity bg) */}
          <View style={{
            width: 44, height: 44, borderRadius: 22,
            backgroundColor: `${iconColor}33`, // 20% opacity
            alignItems: 'center', justifyContent: 'center'
          }}>
            <Ionicons name={icon} size={20} color={iconColor} />
          </View>

          {/* Text block */}
          <View style={{ flex: 1 }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 2 }}>
              <Text style={{ color: '#fff', fontSize: 16, fontWeight: '700' }}>{title}</Text>
              {badge && (
                <View style={{ backgroundColor: `${badgeColor}20`, paddingHorizontal: 6, paddingVertical: 2, borderRadius: 6, borderWidth: 1, borderColor: `${badgeColor}50` }}>
                  <Text style={{ color: badgeColor, fontSize: 9, fontWeight: '800', letterSpacing: 0.5 }}>{badge}</Text>
                </View>
              )}
            </View>
            <Text style={{ color: 'rgba(255,255,255,0.7)', fontSize: 12 }}>{subtitle}</Text>
          </View>

          <Ionicons name="chevron-forward" size={20} color="rgba(255,255,255,0.5)" />
        </View>
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
      {['Policy Check', 'Manipulation Detect', 'Script Match', 'Isolation Signal', 'Qwen3 Thinking', 'Live Web Search'].map((layer, i) => (
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
    <Animated.View style={{ flex: 1, opacity: fadeIn, transform: [{ translateY: slideUp }] }}>
      <ScrollView
        contentContainerStyle={{ padding: 24, paddingBottom: 120 }}
        showsVerticalScrollIndicator={false}
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

      {/* ── Qwen3 AI Explanation ─────────────────────────────── */}
      {result.plain_english ? (
        <View style={[glassStyles.card, { marginBottom: 16, borderColor: 'rgba(140,82,255,0.35)' }]}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
            <Ionicons name="hardware-chip" size={15} color={C.violet} style={{ marginRight: 8 }} />
            <Text style={{ color: C.violet, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>AI Analysis</Text>
            {result.qwen_available && (
              <View style={{ marginLeft: 8, backgroundColor: 'rgba(140,82,255,0.15)', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 10 }}>
                <Text style={{ color: C.violet, fontSize: 9, fontWeight: '700' }}>QWEN3 THINKING</Text>
              </View>
            )}
          </View>
          <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 13, lineHeight: 21 }}>{result.plain_english}</Text>
          {result.tactics_detected && result.tactics_detected.length > 0 && (
            <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginTop: 12, gap: 6 }}>
              {result.tactics_detected.filter(t => t !== 'none_detected').map((tactic, i) => (
                <View key={i} style={{ backgroundColor: 'rgba(255,61,113,0.12)', paddingHorizontal: 10, paddingVertical: 4, borderRadius: 12, borderWidth: 1, borderColor: 'rgba(255,61,113,0.3)' }}>
                  <Text style={{ color: C.rose, fontSize: 10, fontWeight: '600', textTransform: 'capitalize' }}>
                    {tactic.replace(/_/g, ' ')}
                  </Text>
                </View>
              ))}
            </View>
          )}
        </View>
      ) : null}

      {/* ── Live Policy Fact-Check ────────────────────────────── */}
      {result.live_policy_check?.checked && (
        <View style={[glassStyles.card, {
          marginBottom: 16,
          borderColor: result.live_policy_check.policy_allows === false
            ? 'rgba(255,61,113,0.4)'
            : result.live_policy_check.policy_allows === true
            ? 'rgba(52,199,89,0.4)'
            : 'rgba(255,170,0,0.3)',
        }]}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
            <Ionicons name="globe-outline" size={15} color={C.cyan} style={{ marginRight: 8 }} />
            <Text style={{ color: C.cyan, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Live Web Verification</Text>
            <View style={{ marginLeft: 'auto', backgroundColor: 'rgba(0,243,255,0.1)', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 10 }}>
              <Text style={{ color: C.cyan, fontSize: 9, fontWeight: '700' }}>TAVILY AI</Text>
            </View>
          </View>

          {/* Verdict pill */}
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
            <View style={{
              paddingHorizontal: 10, paddingVertical: 4, borderRadius: 12,
              backgroundColor: result.live_policy_check.policy_allows === false
                ? 'rgba(255,61,113,0.15)' : result.live_policy_check.policy_allows === true
                ? 'rgba(52,199,89,0.15)' : 'rgba(255,170,0,0.15)',
            }}>
              <Text style={{
                fontSize: 11, fontWeight: '700',
                color: result.live_policy_check.policy_allows === false ? C.rose
                  : result.live_policy_check.policy_allows === true ? C.green : C.gold,
              }}>
                {result.live_policy_check.policy_allows === false ? '⛔ POLICY PROHIBITS THIS'
                  : result.live_policy_check.policy_allows === true ? '✅ POLICY ALLOWS THIS'
                  : '⚠️ POLICY UNCLEAR'}
              </Text>
            </View>
            <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 10, marginLeft: 8 }}>
              {Math.round((result.live_policy_check.confidence || 0) * 100)}% conf
            </Text>
          </View>

          {/* Web answer text */}
          {result.live_policy_check.verdict_text ? (
            <Text style={{ color: 'rgba(255,255,255,0.8)', fontSize: 13, lineHeight: 20, marginBottom: 10 }}>
              {result.live_policy_check.verdict_text}
            </Text>
          ) : null}

          {/* Source link */}
          {result.live_policy_check.source_url ? (
            <TouchableOpacity
              style={{ flexDirection: 'row', alignItems: 'center', marginTop: 4 }}
              onPress={() => Linking.openURL(result.live_policy_check!.source_url!)}
            >
              <Ionicons name="link-outline" size={13} color={C.cyan} style={{ marginRight: 5 }} />
              <Text style={{ color: C.cyan, fontSize: 12, textDecorationLine: 'underline', flex: 1 }} numberOfLines={1}>
                {result.live_policy_check.source_label || result.live_policy_check.source_url}
              </Text>
              <Ionicons name="open-outline" size={13} color={C.cyan} style={{ marginLeft: 4 }} />
            </TouchableOpacity>
          ) : null}
        </View>
      )}

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
      </ScrollView>
    </Animated.View>
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
