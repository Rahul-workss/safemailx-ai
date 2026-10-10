import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView,
  Animated, BackHandler, Linking, Dimensions, Platform, Image,
  TextInput, KeyboardAvoidingView, PermissionsAndroid, Alert, ActivityIndicator, Modal,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';

import { LinearGradient } from 'expo-linear-gradient';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import Voice, { SpeechResultsEvent, SpeechErrorEvent } from '@react-native-voice/voice';
import { analyzeCall, CallAnalysisResult, translateText } from '../api';

const { height: SCREEN_HEIGHT, width: SCREEN_WIDTH } = Dimensions.get('window');

type ScreenState = 'CHOOSING' | 'RECORDING' | 'REVIEW' | 'STRUCTURED' | 'ANALYZING' | 'VERDICT' | 'ERROR';

const C = {
  bg: '#06080f',
  surface: 'rgba(255,255,255,0.05)',
  border: 'rgba(255,255,255,0.09)',
  cyan: '#00d4ff',
  violet: '#8c52ff',
  rose: '#ff3d71',
  gold: '#ffaa00',
  green: '#34c759',
  frost: '#e8eaf0',
  frost4: '#4a5568',
};

// ─── Animated Chip (tap-to-describe chips) ───────────────────────────────────
function AnimatedChip({ label, active, color, onPress }: {
  label: string; active: boolean; color: string; onPress: () => void;
}) {
  const scale = useRef(new Animated.Value(1)).current;
  const glow = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.spring(scale, { toValue: active ? 1.04 : 1, useNativeDriver: true }).start();
    Animated.timing(glow, { toValue: active ? 1 : 0, duration: 200, useNativeDriver: false }).start();
  }, [active]);

  const bgColor = glow.interpolate({ inputRange: [0, 1], outputRange: ['rgba(255,255,255,0.06)', `${color}25`] });
  const borderColor = glow.interpolate({ inputRange: [0, 1], outputRange: ['rgba(255,255,255,0.12)', color] });

  return (
    <TouchableOpacity onPress={onPress} activeOpacity={0.8}>
      <Animated.View style={[chipStyles.chip, { backgroundColor: bgColor, borderColor }]}>
        <Animated.View style={{ transform: [{ scale }] }}>
          <Text style={[chipStyles.text, active && { color, fontWeight: '700' }]}>{label}</Text>
        </Animated.View>
      </Animated.View>
    </TouchableOpacity>
  );
}

const chipStyles = StyleSheet.create({
  chip: {
    paddingVertical: 10, paddingHorizontal: 16, borderRadius: 24,
    borderWidth: 1, margin: 4,
  },
  text: { color: 'rgba(255,255,255,0.6)', fontSize: 14, fontWeight: '500' },
});

// ─── Shared Glass Card ────────────────────────────────────────────────────────
function GlassCard({ children, style, accentColor }: {
  children: React.ReactNode; style?: any; accentColor?: string;
}) {
  return (
    <View style={[{
      borderRadius: 20, borderWidth: 1,
      borderColor: accentColor ? `${accentColor}45` : 'rgba(255,255,255,0.12)',
      backgroundColor: accentColor ? `${accentColor}0f` : 'rgba(255,255,255,0.07)',
      overflow: 'hidden',
    }, style]}>
      <LinearGradient
        colors={['rgba(255,255,255,0.11)', 'rgba(255,255,255,0.03)', 'rgba(255,255,255,0.0)']}
        start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
        style={StyleSheet.absoluteFillObject}
      />
      <View style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1.2, backgroundColor: 'rgba(255,255,255,0.18)' }} />
      {accentColor && (
        <View style={{ position: 'absolute', top: 0, left: 0, bottom: 0, width: 3, backgroundColor: accentColor, opacity: 0.85 }} />
      )}
      <View style={{ padding: 20 }}>
        {children}
      </View>
    </View>
  );
}

// ─── Main Screen ──────────────────────────────────────────────────────────────
export default function CallAnalyzerScreen({ onClose }: { onClose: () => void }) {
  const insets = useSafeAreaInsets();
  const [screenState, setScreenState] = useState<ScreenState>('CHOOSING');

  // Entrance animation
  const slideAnim = useRef(new Animated.Value(SCREEN_HEIGHT)).current;
  const overlayOpacity = useRef(new Animated.Value(0)).current;

  // ── Path A — Live Transcription ────────────────────────────────────────────
  const [timeLeft, setTimeLeft] = useState(20);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timeLeftRef = useRef(20);
  const timerStartRef = useRef<number>(0);
  const timerDurationRef = useRef<number>(20000);

  // Transcript state
  const [finalTranscript, setFinalTranscript] = useState('');
  const [partialTranscript, setPartialTranscript] = useState('');
  const partialTranscriptRef = useRef('');
  const [reviewTranscript, setReviewTranscript] = useState('');
  const isRecognizingRef = useRef(false);
  const finalTranscriptRef = useRef('');
  const partialDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isFinishingRef = useRef(false);
  const extensionCountRef = useRef(0);
  const restartFailCountRef = useRef(0);

  // Waveform bar animations
  const bar1 = useRef(new Animated.Value(4)).current;
  const bar2 = useRef(new Animated.Value(8)).current;
  const bar3 = useRef(new Animated.Value(14)).current;
  const bar4 = useRef(new Animated.Value(8)).current;
  const bar5 = useRef(new Animated.Value(4)).current;
  const waveAniRef = useRef<Animated.CompositeAnimation | null>(null);

  // Recording dot pulse
  const recDotOpacity = useRef(new Animated.Value(1)).current;
  const recDotAniRef = useRef<Animated.CompositeAnimation | null>(null);

  // ── Voice event handlers ───────────────────────────────────────────────────
  useEffect(() => {
    const commitPartialTranscript = () => {
      const partial = partialTranscriptRef.current.trim();
      if (partial) {
        const updated = finalTranscriptRef.current
          ? finalTranscriptRef.current + ' ' + partial
          : partial;
        finalTranscriptRef.current = updated;
        setFinalTranscript(updated);
      }
      partialTranscriptRef.current = '';
      setPartialTranscript('');
    };

    Voice.onSpeechResults = (e: SpeechResultsEvent) => {
      const newText = e.value?.[0] ?? '';
      if (newText.trim()) {
        const updated = finalTranscriptRef.current
          ? finalTranscriptRef.current + ' ' + newText.trim()
          : newText.trim();
        finalTranscriptRef.current = updated;
        setFinalTranscript(updated);
        restartFailCountRef.current = 0;
      }
      if (partialDebounceRef.current) clearTimeout(partialDebounceRef.current);
      partialTranscriptRef.current = '';
      setPartialTranscript('');

      // If we're in the drain phase (user pressed Stop / timer expired),
      // fire the finalize callback now that we have the last words.
      if (finalizeCallbackRef.current) {
        finalizeCallbackRef.current();
        return;
      }
    };

    Voice.onSpeechPartialResults = (e: SpeechResultsEvent) => {
      const partial = e.value?.[0] ?? '';
      partialTranscriptRef.current = partial;
      if (partialDebounceRef.current) clearTimeout(partialDebounceRef.current);
      partialDebounceRef.current = setTimeout(() => {
        setPartialTranscript(partial);
      }, 100);
    };

    Voice.onSpeechError = (_e: SpeechErrorEvent) => {
      if (partialDebounceRef.current) clearTimeout(partialDebounceRef.current);
      commitPartialTranscript();

      // If draining for finalize, fire callback even on error.
      if (finalizeCallbackRef.current) {
        finalizeCallbackRef.current();
        return;
      }

      if (isRecognizingRef.current && timeLeftRef.current > 1) {
        restartRecognizer();
      }
    };

    Voice.onSpeechEnd = () => {
      commitPartialTranscript();

      // If draining for finalize, fire callback — engine has finished speaking.
      if (finalizeCallbackRef.current) {
        finalizeCallbackRef.current();
        return;
      }

      if (isRecognizingRef.current && timeLeftRef.current > 1) {
        restartRecognizer();
      }
    };

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (partialDebounceRef.current) clearTimeout(partialDebounceRef.current);
      isRecognizingRef.current = false;
      Voice.destroy().then(() => Voice.removeAllListeners()).catch(() => {});
      stopWaveAnimation();
      stopRecDotPulse();
    };
  }, []);

  const restartRecognizer = () => {
    if (!isRecognizingRef.current) return;
    Voice.start('en-IN').catch(() => {
      if (!isRecognizingRef.current) return;
      Voice.start('en-US').catch(() => {
        if (!isRecognizingRef.current) return;
        restartFailCountRef.current += 1;
        if (restartFailCountRef.current >= 3) {
          isRecognizingRef.current = false;
          if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
          stopWaveAnimation();
          stopRecDotPulse();
          const captured = finalTranscriptRef.current.trim();
          if (captured.split(/\s+/).filter(Boolean).length >= 1) {
            setReviewTranscript(captured);
            setScreenState('REVIEW');
          } else {
            Alert.alert('Speech Engine Stopped', 'The speech recognizer stopped responding.\n\nUse "Type It" to describe the call manually.', [
              { text: 'Try Again', onPress: () => startRecording() },
              { text: 'Type It Instead', onPress: () => setScreenState('STRUCTURED') },
            ]);
          }
        }
      });
    });
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

  // ── Shared countdown timer ─────────────────────────────────────────────────
  const startCountdownTimer = () => {
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    timerStartRef.current = Date.now();
    timerDurationRef.current = 20000;
    timeLeftRef.current = 20;
    setTimeLeft(20);
    timerRef.current = setInterval(() => {
      const elapsed = Date.now() - timerStartRef.current;
      const remaining = Math.max(0, Math.ceil((timerDurationRef.current - elapsed) / 1000));
      if (remaining !== timeLeftRef.current) {
        timeLeftRef.current = remaining;
        setTimeLeft(remaining);
      }
      if (elapsed >= timerDurationRef.current) {
        finishRecording();
      }
    }, 250);
  };

  const startRecording = async () => {
    try {
      if (Platform.OS === 'android') {
        const granted = await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.RECORD_AUDIO,
          {
            title: 'Microphone Permission Required',
            message: 'SafeMail X needs microphone access to transcribe your call description in real time.\n\nPlease tap "Allow" to use Speak It.',
            buttonPositive: 'Allow',
            buttonNegative: 'Cancel',
          }
        );
        if (granted !== PermissionsAndroid.RESULTS.GRANTED) {
          Alert.alert(
            'Microphone Permission Denied',
            'Without microphone access, Speak It cannot transcribe your voice.\n\nYou can:\n• Tap "Speak It" again and allow the permission\n• Use "Type It" to describe the call manually\n\nTo fix: Phone Settings → Apps → SafeMail X → Permissions → Microphone → Allow',
            [{ text: 'OK' }]
          );
          return;
        }
      }

      // Reset all transcript state for a fresh recording
      finalTranscriptRef.current = '';
      setFinalTranscript('');
      partialTranscriptRef.current = '';
      setPartialTranscript('');
      setReviewTranscript('');
      // Reset guard flags
      isFinishingRef.current = false;
      extensionCountRef.current = 0;
      restartFailCountRef.current = 0;
      isRecognizingRef.current = true;

      try {
        await Voice.start('en-IN');
      } catch (_) {
        await Voice.start('en-US');
      }

      setScreenState('RECORDING');
      startWaveAnimation();
      startRecDotPulse();
      startCountdownTimer();
    } catch (err: any) {
      console.warn('[CallAnalyzer] startRecording failed:', err);
      isRecognizingRef.current = false;
      if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
      try { Voice.stop(); } catch (_) {}
      stopWaveAnimation();
      stopRecDotPulse();
      setScreenState('CHOOSING');
      Alert.alert(
        'Could Not Start Microphone',
        'The speech recognizer failed to start.\n\nThis can happen if:\n• Another app is using the microphone\n• The device speech engine is unavailable\n\nTry again, or use "Type It" to describe the call manually.',
        [
          { text: 'Try Again', onPress: () => startRecording() },
          { text: 'Type It Instead', onPress: () => setScreenState('STRUCTURED') },
        ]
      );
    }
  };

  // Ref to hold the one-shot "finalize" callback so onSpeechResults/onSpeechEnd
  // can trigger it as soon as the engine delivers the last words.
  const finalizeCallbackRef = useRef<(() => void) | null>(null);

  const finishRecording = () => {
    if (isFinishingRef.current) return;
    isFinishingRef.current = true;

    // Stop timer immediately — user has committed to stopping.
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    stopWaveAnimation();
    stopRecDotPulse();

    // --- Phase 1: Graceful drain ---
    // Signal recognizer to stop but DO NOT set isRecognizingRef=false yet.
    // The engine may still deliver a final onSpeechResults with the last words.
    // We wait up to 1800ms for that event before forcibly finalizing.
    try { Voice.stop(); } catch (_) {}

    // Safety net: commit + advance after 1800ms even if engine stays silent.
    const safetyTimer = setTimeout(() => {
      finalizeCallbackRef.current = null;
      _doFinalize();
    }, 1800);

    // Register callback so onSpeechResults / onSpeechEnd can trigger early finalize.
    finalizeCallbackRef.current = () => {
      clearTimeout(safetyTimer);
      finalizeCallbackRef.current = null;
      // Short extra wait so React state from onSpeechResults has settled.
      setTimeout(_doFinalize, 150);
    };
  };

  const _doFinalize = () => {
    isRecognizingRef.current = false;
    isFinishingRef.current = false;

    // Commit any in-flight partial text.
    if (partialDebounceRef.current) { clearTimeout(partialDebounceRef.current); partialDebounceRef.current = null; }
    if (partialTranscriptRef.current.trim()) {
      const updated = finalTranscriptRef.current
        ? finalTranscriptRef.current + ' ' + partialTranscriptRef.current.trim()
        : partialTranscriptRef.current.trim();
      finalTranscriptRef.current = updated;
      setFinalTranscript(updated);
    }
    partialTranscriptRef.current = '';
    setPartialTranscript('');

    const captured = finalTranscriptRef.current.trim();
    const wordCount = captured ? captured.split(/\s+/).filter(Boolean).length : 0;
    const atCap = extensionCountRef.current >= 2;

    if (wordCount >= 5) {
      setReviewTranscript(captured);
      setScreenState('REVIEW');
      return;
    }

    if (atCap) {
      if (wordCount > 0) {
        setReviewTranscript(captured);
        setScreenState('REVIEW');
      } else {
        Alert.alert(
          "We Didn't Hear You",
          "We couldn't capture any speech in 60 seconds.\n\nTry speaking louder and closer to the mic, or use \"Type It\" to describe the call manually.",
          [
            { text: 'Try Again', onPress: () => startRecording() },
            { text: 'Type It Instead', onPress: () => { stopRecordingIfNeeded(); setScreenState('STRUCTURED'); } },
          ]
        );
      }
      return;
    }

    if (wordCount === 0) {
      Alert.alert(
        "We Didn't Hear You",
        `No speech was detected.\n\nSpeak clearly towards the mic and tap Try Again for another 20 seconds.\n(${2 - extensionCountRef.current} attempt${2 - extensionCountRef.current === 1 ? '' : 's'} remaining)`,
        [
          { text: 'Try Again', onPress: () => extendRecording() },
          { text: 'Type It Instead', onPress: () => { stopRecordingIfNeeded(); setScreenState('STRUCTURED'); } },
        ]
      );
      return;
    }

    extendRecording();
  };

  const extendRecording = () => {
    extensionCountRef.current += 1;
    restartFailCountRef.current = 0;

    if (partialDebounceRef.current) { clearTimeout(partialDebounceRef.current); partialDebounceRef.current = null; }
    partialTranscriptRef.current = '';
    setPartialTranscript('');

    isRecognizingRef.current = true;
    startWaveAnimation();
    startRecDotPulse();

    Voice.start('en-IN').catch(() => {
      Voice.start('en-US').catch(() => {
        isRecognizingRef.current = false;
        stopWaveAnimation();
        stopRecDotPulse();
        const captured = finalTranscriptRef.current.trim();
        if (captured.split(/\s+/).filter(Boolean).length >= 1) {
          setReviewTranscript(captured);
          setScreenState('REVIEW');
        } else {
          Alert.alert('Microphone Error', 'Could not restart recording.', [
            { text: 'Type It Instead', onPress: () => setScreenState('STRUCTURED') },
          ]);
        }
      });
    });

    startCountdownTimer();
  };

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

  const stopRecordingIfNeeded = () => {
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    if (partialDebounceRef.current) { clearTimeout(partialDebounceRef.current); partialDebounceRef.current = null; }
    partialTranscriptRef.current = '';
    setPartialTranscript('');
    isRecognizingRef.current = false;
    isFinishingRef.current = false;
    extensionCountRef.current = 0;
    try { Voice.stop(); } catch (_) {}
    stopWaveAnimation();
    stopRecDotPulse();
  };

  // Path B — Structured
  const [orgClaimed, setOrgClaimed] = useState('');
  const [customOrg, setCustomOrg]   = useState('');   // free-text "other" org
  const [actions, setActions] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);

  // Results
  const [result, setResult] = useState<CallAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [analyzing, setAnalyzing] = useState(false);

  // Entrance animation
  useEffect(() => {
    Animated.parallel([
      Animated.timing(overlayOpacity, { toValue: 1, duration: 300, useNativeDriver: true }),
      Animated.spring(slideAnim, { toValue: 0, tension: 65, friction: 11, useNativeDriver: true }),
    ]).start();
  }, []);

  // Android back button
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

  const submitStructured = async () => {
    setAnalyzing(true);
    setScreenState('ANALYZING');
    // Merge chip selection + free-text — custom takes over if no chip selected,
    // or gets appended to chip label so the engine sees the full context.
    const effectiveOrg = orgClaimed
      ? (customOrg.trim() ? `${orgClaimed} (${customOrg.trim()})` : orgClaimed)
      : customOrg.trim();
    try {
      const res = await analyzeCall({ inputMode: 'structured', orgClaimed: effectiveOrg, actionsRequested: actions, warningPhrases: warnings });
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

  const canSubmit = orgClaimed.length > 0 || customOrg.trim().length > 0 || actions.length > 0 || warnings.length > 0;

  // ── Render content per state ───────────────────────────────────────────────
  const renderContent = () => {
    switch (screenState) {
      case 'CHOOSING':
        return <ChoosingView onSpeak={startRecording} onTap={() => setScreenState('STRUCTURED')} />;

      // ── RECORDING ─────────────────────────────────────────────────────────
      case 'RECORDING': {
        const displayText = finalTranscript
          ? (partialTranscript ? finalTranscript + ' ' + partialTranscript : finalTranscript)
          : partialTranscript;
        const isEmpty = !displayText.trim();
        const progress = ((20 - timeLeft) / 20) * 100;

        return (
          <View style={{ flex: 1 }}>

            <ScrollView
              contentContainerStyle={{ padding: 20, paddingBottom: 40 }}
              showsVerticalScrollIndicator={false}
              keyboardShouldPersistTaps="handled"
            >
              {/* Header label */}
              <View style={{ alignItems: 'center', marginBottom: 24 }}>
                <View style={{
                  backgroundColor: 'rgba(0,212,255,0.12)', borderWidth: 1,
                  borderColor: 'rgba(0,212,255,0.35)', borderRadius: 20,
                  paddingHorizontal: 14, paddingVertical: 6,
                  flexDirection: 'row', alignItems: 'center', gap: 8,
                }}>
                  <View style={{ width: 6, height: 6, borderRadius: 3, backgroundColor: C.cyan }} />
                  <Text style={{ color: C.cyan, fontSize: 11, fontWeight: '700', letterSpacing: 1.5 }}>SPEAK IT</Text>
                </View>
                <Text style={{ color: '#fff', fontSize: 22, fontWeight: '800', marginTop: 12, textAlign: 'center' }}>
                  We're Listening...
                </Text>
                <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 13, marginTop: 4, textAlign: 'center' }}>
                  Describe what happened on the call
                </Text>
              </View>

              <View style={{ alignItems: 'center', marginBottom: 24 }}>
                <View style={{
                  width: 110, height: 110, borderRadius: 55,
                  borderWidth: 3, borderColor: timeLeft <= 5 ? C.rose : C.cyan,
                  alignItems: 'center', justifyContent: 'center',
                  backgroundColor: 'rgba(0,212,255,0.06)',
                }}>
                  <Text style={{ fontSize: 34, fontWeight: '200', color: timeLeft <= 5 ? C.rose : '#fff', letterSpacing: 2 }}>
                    {timeLeft.toString().padStart(2, '0')}
                  </Text>
                  <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: 10, letterSpacing: 1 }}>SEC</Text>
                </View>
                {/* Progress bar */}
                <View style={{ width: 160, height: 3, backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: 2, marginTop: 12 }}>
                  <View style={{ height: 3, borderRadius: 2, backgroundColor: timeLeft <= 5 ? C.rose : C.cyan, width: `${progress}%` }} />
                </View>
              </View>

              {/* LISTENING pill + waveform */}
              <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 12, marginBottom: 16 }}>
                <Animated.View style={{
                  width: 8, height: 8, borderRadius: 4,
                  backgroundColor: C.rose, opacity: recDotOpacity,
                  shadowColor: C.rose, shadowRadius: 6, shadowOpacity: 0.9,
                }} />
                <Text style={{ color: C.rose, fontSize: 11, fontWeight: '700', letterSpacing: 2 }}>LISTENING</Text>
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 3, height: 24 }}>
                  {[bar1, bar2, bar3, bar4, bar5].map((bar, i) => (
                    <Animated.View key={i} style={{
                      width: 3, height: bar, borderRadius: 2,
                      backgroundColor: C.cyan, opacity: 0.8,
                    }} />
                  ))}
                </View>
              </View>

              {/* Live Transcript Card */}
              <View style={{
                borderRadius: 20, borderWidth: 1,
                borderColor: isEmpty ? 'rgba(255,255,255,0.10)' : `${C.cyan}50`,
                backgroundColor: isEmpty ? 'rgba(255,255,255,0.05)' : 'rgba(0,212,255,0.07)',
                marginBottom: 20, minHeight: 160, overflow: 'hidden',
              }}>
                <LinearGradient
                  colors={['rgba(255,255,255,0.09)', 'rgba(255,255,255,0.01)', 'rgba(255,255,255,0.0)']}
                  start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
                  style={StyleSheet.absoluteFillObject}
                />
                <View style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, backgroundColor: 'rgba(255,255,255,0.18)' }} />
                {!isEmpty && <View style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 3, backgroundColor: C.cyan, opacity: 0.85 }} />}

                <View style={{ padding: 18, minHeight: 160, justifyContent: 'flex-end' }}>
                  <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
                    <Ionicons name="mic" size={12} color={C.cyan} style={{ marginRight: 6 }} />
                    <Text style={{ color: C.cyan, fontSize: 9, fontWeight: '700', letterSpacing: 1.5, textTransform: 'uppercase' }}>
                      Live Transcript
                    </Text>
                  </View>
                  {isEmpty ? (
                    <Text style={{ color: 'rgba(255,255,255,0.22)', fontSize: 15, lineHeight: 24, fontStyle: 'italic' }}>
                      {"Speak clearly...\n\nTell us who called and\nwhat they asked for"}
                    </Text>
                  ) : (
                    <Text style={{ color: '#fff', fontSize: 16, lineHeight: 26, letterSpacing: 0.2 }}>
                      {finalTranscript ? (
                        <Text style={{ color: '#ffffff' }}>{finalTranscript}</Text>
                      ) : null}
                      {partialTranscript ? (
                        <Text style={{ color: 'rgba(255,255,255,0.5)' }}>
                          {finalTranscript ? ' ' : ''}{partialTranscript}
                        </Text>
                      ) : null}
                      <Text style={{ color: C.cyan }}>▌</Text>
                    </Text>
                  )}
                </View>
              </View>

              {/* Hint */}
              <Text style={{ color: 'rgba(255,255,255,0.3)', fontSize: 12, textAlign: 'center', marginBottom: 16 }}>
                Speak clearly · English or Hinglish both work
              </Text>

              {/* Stop & Review button — no elevation (creates black surface on Android) */}
              <TouchableOpacity
                onPress={finishRecording}
                style={{
                  borderRadius: 16, borderWidth: 1.5, borderColor: C.rose,
                  backgroundColor: 'rgba(255,61,113,0.18)', padding: 18,
                  alignItems: 'center',
                }}
              >
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                  <Ionicons name="stop-circle" size={18} color={C.rose} />
                  <Text style={{ color: C.rose, fontSize: 16, fontWeight: '700', letterSpacing: 0.3 }}>
                    Stop &amp; Review →
                  </Text>
                </View>
              </TouchableOpacity>
            </ScrollView>
          </View>
        );
      }

      // ── REVIEW ────────────────────────────────────────────────────────────
      case 'REVIEW': {
        const wordCount = reviewTranscript.trim().split(/\s+/).filter(Boolean).length;
        const canAnalyze = wordCount >= 5;

        return (
          <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
              <ScrollView
                contentContainerStyle={{ padding: 20, paddingBottom: 60 }}
                keyboardShouldPersistTaps="handled"
                showsVerticalScrollIndicator={false}
              >
                {/* Header */}
                <View style={{ alignItems: 'center', marginBottom: 24 }}>
                  <View style={{
                    width: 64, height: 64, borderRadius: 32,
                    backgroundColor: `${C.green}18`, alignItems: 'center', justifyContent: 'center',
                    borderWidth: 2, borderColor: `${C.green}50`, marginBottom: 14,
                    shadowColor: C.green, shadowRadius: 16, shadowOpacity: 0.4,
                  }}>
                    <Ionicons name="checkmark-circle" size={32} color={C.green} />
                  </View>
                  <Text style={{ color: '#fff', fontSize: 24, fontWeight: '800' }}>Got it!</Text>
                  <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 13, marginTop: 6, textAlign: 'center', lineHeight: 20 }}>
                    Review what we heard.{'\n'}Tap the text to fix any errors before analyzing.
                  </Text>
                </View>

                {/* Editable transcript card */}
                <GlassCard accentColor={C.cyan} style={{ marginBottom: 16 }}>
                  <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
                    <Ionicons name="mic" size={13} color={C.cyan} style={{ marginRight: 6 }} />
                    <Text style={{ color: C.cyan, fontSize: 9, fontWeight: '700', letterSpacing: 1.5, textTransform: 'uppercase' }}>
                      Transcribed · Tap to edit
                    </Text>
                  </View>
                  <TextInput
                    value={reviewTranscript}
                    onChangeText={setReviewTranscript}
                    multiline
                    style={{
                      color: '#fff', fontSize: 15, lineHeight: 24,
                      textAlignVertical: 'top', minHeight: 120,
                    }}
                    placeholderTextColor="rgba(255,255,255,0.3)"
                    placeholder="Your description will appear here..."
                  />
                  <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 10, gap: 6 }}>
                    <Ionicons name="document-text" size={12} color="rgba(255,255,255,0.35)" />
                    <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 11 }}>
                      {wordCount} words {canAnalyze ? '✓' : `(need ${5 - wordCount} more)`}
                    </Text>
                  </View>
                </GlassCard>

                {/* Warning if too short */}
                {!canAnalyze && (
                  <View style={{
                    flexDirection: 'row', alignItems: 'center', gap: 8,
                    backgroundColor: `${C.gold}15`, borderWidth: 1, borderColor: `${C.gold}40`,
                    borderRadius: 12, padding: 12, marginBottom: 16,
                  }}>
                    <Ionicons name="warning" size={16} color={C.gold} />
                    <Text style={{ color: C.gold, fontSize: 13, flex: 1 }}>
                      Add a few more words to get an accurate analysis.
                    </Text>
                  </View>
                )}

                {/* Analyze button */}
                <TouchableOpacity
                  style={[S.primaryBtn, { opacity: canAnalyze ? 1 : 0.4, marginBottom: 12 }]}
                  disabled={!canAnalyze}
                  onPress={() => submitTranscript(reviewTranscript)}
                >
                  <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                    <Ionicons name="shield-checkmark" size={18} color="#06080f" />
                    <Text style={S.btnText}>Analyze This Call →</Text>
                  </View>
                </TouchableOpacity>

                {/* Re-record button */}
                <TouchableOpacity
                  style={{
                    padding: 14, alignItems: 'center',
                    borderRadius: 16, borderWidth: 1, borderColor: 'rgba(255,255,255,0.1)',
                    backgroundColor: 'rgba(255,255,255,0.05)',
                  }}
                  onPress={() => {
                    finalTranscriptRef.current = '';
                    setFinalTranscript('');
                    setPartialTranscript('');
                    setReviewTranscript('');
                    startRecording();
                  }}
                >
                  <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                    <Ionicons name="mic" size={16} color="rgba(255,255,255,0.5)" />
                    <Text style={{ color: 'rgba(255,255,255,0.5)', fontSize: 14 }}>Re-record</Text>
                  </View>
                </TouchableOpacity>
              </ScrollView>
            </KeyboardAvoidingView>
          );
        }

      // ── STRUCTURED ────────────────────────────────────────────────────────
      case 'STRUCTURED':
        return (
          <ScrollView contentContainerStyle={{ padding: 24, paddingBottom: 120 }} showsVerticalScrollIndicator={false}>
              {/* Page header */}
              <View style={{ alignItems: 'center', marginBottom: 28 }}>
                <View style={{
                  width: 64, height: 64, borderRadius: 32,
                  backgroundColor: `${C.violet}20`, alignItems: 'center', justifyContent: 'center',
                  borderWidth: 2, borderColor: `${C.violet}50`, marginBottom: 14,
                  shadowColor: C.violet, shadowRadius: 16, shadowOpacity: 0.4,
                }}>
                  <Ionicons name="list" size={28} color={C.violet} />
                </View>
                <Text style={{ color: '#fff', fontSize: 22, fontWeight: '800' }}>Tap to Describe</Text>
                <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 13, marginTop: 6, textAlign: 'center' }}>
                  Select everything that matches your call
                </Text>
              </View>

              <StructuredForm
                orgClaimed={orgClaimed} setOrgClaimed={(v: string) => { setOrgClaimed(v); if (v) setCustomOrg(''); }}
                customOrg={customOrg}   setCustomOrg={(v: string) => { setCustomOrg(v); if (v) setOrgClaimed(''); }}
                actions={actions} setActions={setActions}
                warnings={warnings} setWarnings={setWarnings}
                onToggle={toggleItem}
              />
              <TouchableOpacity
                style={[S.primaryBtn, { opacity: canSubmit ? 1 : 0.4, marginTop: 28 }]}
                disabled={!canSubmit}
                onPress={submitStructured}
              >
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                  <Ionicons name="shield-checkmark" size={18} color="#06080f" />
                  <Text style={S.btnText}>Analyze Now →</Text>
                </View>
              </TouchableOpacity>
            </ScrollView>
          );

      case 'ANALYZING':
        return <AnalyzingView />;

      case 'VERDICT':
        return result ? (
          <VerdictView result={result} onClose={handleClose} onRetry={() => { setResult(null); setScreenState('CHOOSING'); }} />
        ) : null;

      case 'ERROR':
        return (
          <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 }}>
            <View style={{ width: 80, height: 80, borderRadius: 40, backgroundColor: `${C.rose}18`, alignItems: 'center', justifyContent: 'center', borderWidth: 2, borderColor: `${C.rose}50`, marginBottom: 16 }}>
              <Ionicons name="alert-circle" size={40} color={C.rose} />
            </View>
            <Text style={[S.title, { marginTop: 4 }]}>Analysis Failed</Text>
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
      {/* Full-bleed background image */}
      <Image
        source={require('../../assets/call-analyzer-bg.png')}
        style={{ position: 'absolute', width: '100%', height: '100%' }}
        resizeMode="cover"
      />
      {/* Dark overlay so text is readable */}
      <View style={[StyleSheet.absoluteFill, { backgroundColor: 'rgba(6,8,15,0.62)' }]} />

      {/* Sheet */}
      <Animated.View style={[S.sheet, { transform: [{ translateY: slideAnim }], paddingTop: insets.top + 16, paddingBottom: insets.bottom }]}>

        {/* Header bar */}
        <View style={S.headerBar}>
          <TouchableOpacity onPress={handleBack} style={S.backBtn} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
            <Ionicons name="chevron-back" size={20} color={C.frost} />
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

// ─── CHOOSING Sub-view ────────────────────────────────────────────────────────
function ChoosingView({ onSpeak, onTap }: { onSpeak: () => void; onTap: () => void }) {
  const fadeIn  = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(40)).current;
  const card1Y  = useRef(new Animated.Value(40)).current;
  const card2Y  = useRef(new Animated.Value(40)).current;
  const card1Op = useRef(new Animated.Value(0)).current;
  const card2Op = useRef(new Animated.Value(0)).current;

  const floatY      = useRef(new Animated.Value(0)).current;
  const shieldGlow  = useRef(new Animated.Value(0.6)).current;
  const shieldScale = useRef(new Animated.Value(1)).current;

  useEffect(() => {
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

    Animated.loop(Animated.sequence([
      Animated.timing(floatY, { toValue: -10, duration: 2400, useNativeDriver: true }),
      Animated.timing(floatY, { toValue:   0, duration: 2400, useNativeDriver: true }),
    ])).start();

    Animated.loop(Animated.sequence([
      Animated.timing(shieldGlow, { toValue: 1.0, duration: 1800, useNativeDriver: true }),
      Animated.timing(shieldGlow, { toValue: 0.5, duration: 1800, useNativeDriver: true }),
    ])).start();

    Animated.loop(Animated.sequence([
      Animated.timing(shieldScale, { toValue: 1.05, duration: 1800, useNativeDriver: true }),
      Animated.timing(shieldScale, { toValue: 1.00, duration: 1800, useNativeDriver: true }),
    ])).start();
  }, []);

  return (
    <Animated.View style={{ flex: 1, opacity: fadeIn }}>
      <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 24 }}>

        {/* ── Shield Hero ── */}
        <Animated.View style={{ transform: [{ translateY: slideUp }], alignItems: 'center', marginBottom: 32 }}>
          <Animated.View style={{ transform: [{ translateY: floatY }, { scale: shieldScale }], alignItems: 'center' }}>
            {/* Shield image — built-in blue glow, no extra dark circles needed */}
            <Image
              source={require('../../assets/shield-call.png')}
              style={{ width: 200, height: 200 }}
              resizeMode="contain"
            />
          </Animated.View>
        </Animated.View>

        {/* ── Title ── */}
        <Animated.View style={{ transform: [{ translateY: slideUp }], alignItems: 'center', marginBottom: 32 }}>
          <Text style={{ fontSize: 32, fontWeight: '800', textAlign: 'center', letterSpacing: -0.5, lineHeight: 40 }}>
            <Text style={{ color: '#fff' }}>Suspicious </Text>
            <Text style={{ color: C.cyan }}>Call?</Text>
          </Text>
          <Text style={{ fontSize: 14, color: 'rgba(255,255,255,0.45)', textAlign: 'center', marginTop: 10, lineHeight: 22 }}>
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
            badgeColor={C.green}
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

        {/* Footer */}
        <Text style={{ color: 'rgba(255,255,255,0.2)', fontSize: 11, marginTop: 32, textAlign: 'center', letterSpacing: 0.5 }}>
          Powered by On-Device Speech · Qwen3 · Tavily
        </Text>
      </View>
    </Animated.View>
  );
}

// ─── Choice Card ──────────────────────────────────────────────────────────────
function ChoiceCard({ icon, iconColor, title, subtitle, badge, badgeColor, onPress, glowColor }: {
  icon: any; iconColor: string; title: string; subtitle: string;
  badge?: string; badgeColor?: string; onPress: () => void; glowColor: string;
}) {
  const scale = useRef(new Animated.Value(1)).current;

  return (
    <TouchableOpacity
      onPressIn={() => Animated.spring(scale, { toValue: 0.97, useNativeDriver: true }).start()}
      onPressOut={() => Animated.spring(scale, { toValue: 1.0, useNativeDriver: true }).start()}
      onPress={onPress}
      activeOpacity={1}
    >
      <Animated.View style={{
        borderRadius: 20, borderWidth: 1,
        borderColor: `${glowColor}55`,
        backgroundColor: `${glowColor}12`,
        overflow: 'hidden',
        padding: 18,
        transform: [{ scale }],
      }}>
        {/* Specular sheen — no BlurView, no dark fill (they create opaque black on Android) */}
        <LinearGradient
          colors={['rgba(255,255,255,0.10)', 'rgba(255,255,255,0.02)', 'rgba(255,255,255,0.0)']}
          start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
          style={StyleSheet.absoluteFillObject}
        />
        {/* Top lip highlight */}
        <View style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1.2, backgroundColor: 'rgba(255,255,255,0.16)' }} />
        {/* Left color accent */}
        <View style={{ position: 'absolute', top: 0, left: 0, bottom: 0, width: 3, backgroundColor: glowColor, opacity: 0.75 }} />

        {/* Content row */}
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 14 }}>
          {/* Icon orb */}
          <View style={{
            width: 52, height: 52, borderRadius: 26,
            backgroundColor: `${iconColor}28`,
            alignItems: 'center', justifyContent: 'center',
            borderWidth: 1, borderColor: `${iconColor}40`,
            shadowColor: iconColor, shadowRadius: 12, shadowOpacity: 0.5,
          }}>
            <Ionicons name={icon} size={22} color={iconColor} />
          </View>

          {/* Text block */}
          <View style={{ flex: 1 }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <Text style={{ color: '#fff', fontSize: 17, fontWeight: '700' }}>{title}</Text>
              {badge && (
                <View style={{
                  backgroundColor: `${badgeColor}22`, paddingHorizontal: 8, paddingVertical: 3,
                  borderRadius: 8, borderWidth: 1, borderColor: `${badgeColor}55`,
                }}>
                  <Text style={{ color: badgeColor, fontSize: 9, fontWeight: '800', letterSpacing: 0.8 }}>{badge}</Text>
                </View>
              )}
            </View>
            <Text style={{ color: 'rgba(255,255,255,0.55)', fontSize: 13 }}>{subtitle}</Text>
          </View>

          <Ionicons name="chevron-forward" size={20} color="rgba(255,255,255,0.4)" />
        </View>
      </Animated.View>
    </TouchableOpacity>
  );
}

// ─── Structured Form ──────────────────────────────────────────────────────────
function StructuredForm({ orgClaimed, setOrgClaimed, customOrg, setCustomOrg, actions, setActions, warnings, setWarnings, onToggle }: any) {
  const ORGS = ['SBI Bank', 'HDFC', 'ICICI', 'Axis Bank', 'UIDAI', 'Police/CBI', 'Customs', 'Income Tax', 'TRAI', 'RBI'];
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

      {/* ── Custom "other" org free-text input ── */}
      <View style={{
        flexDirection: 'row', alignItems: 'center',
        marginBottom: 4, marginTop: 2,
      }}>
        <View style={{
          flex: 1,
          borderRadius: 14,
          borderWidth: 1,
          borderColor: customOrg.trim().length > 0
            ? `${C.cyan}80`
            : 'rgba(255,255,255,0.10)',
          backgroundColor: customOrg.trim().length > 0
            ? 'rgba(0,212,255,0.07)'
            : 'rgba(255,255,255,0.04)',
          flexDirection: 'row',
          alignItems: 'center',
          paddingHorizontal: 12,
          paddingVertical: 9,
        }}>
          <Ionicons
            name="create-outline"
            size={14}
            color={customOrg.trim().length > 0 ? C.cyan : 'rgba(255,255,255,0.30)'}
            style={{ marginRight: 8 }}
          />
          <TextInput
            style={{
              flex: 1,
              color: C.frost,
              fontSize: 13,
              fontWeight: '500',
              padding: 0,
            }}
            placeholder="Other organisation… (e.g. Axis Bank, Amazon, IRCTC)"
            placeholderTextColor="rgba(242,234,253,0.28)"
            value={customOrg}
            onChangeText={setCustomOrg}
            autoCapitalize="words"
            returnKeyType="done"
            maxLength={80}
          />
          {customOrg.trim().length > 0 && (
            <TouchableOpacity onPress={() => setCustomOrg('')} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
              <Ionicons name="close-circle" size={16} color="rgba(255,255,255,0.35)" />
            </TouchableOpacity>
          )}
        </View>
      </View>
      <Text style={{ color: 'rgba(255,255,255,0.25)', fontSize: 10, marginBottom: 12, marginLeft: 4 }}>
        Tap a chip above  or  type below — only one applies
      </Text>

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
    <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 24, marginBottom: 10 }}>
      <View style={{
        width: 28, height: 28, borderRadius: 14,
        backgroundColor: `${color}20`, alignItems: 'center', justifyContent: 'center',
        borderWidth: 1, borderColor: `${color}40`, marginRight: 10,
      }}>
        <Ionicons name={icon} size={14} color={color} />
      </View>
      <Text style={{ fontSize: 11, color, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1.2 }}>{label}</Text>
    </View>
  );
}

// ─── Analyzing View ───────────────────────────────────────────────────────────
function AnalyzingView() {
  const spin  = useRef(new Animated.Value(0)).current;
  const pulse = useRef(new Animated.Value(0.9)).current;
  const dot1  = useRef(new Animated.Value(0)).current;
  const dot2  = useRef(new Animated.Value(0)).current;
  const dot3  = useRef(new Animated.Value(0)).current;
  const shieldScale = useRef(new Animated.Value(0.8)).current;
  const shieldOp    = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(shieldOp, { toValue: 1, duration: 500, useNativeDriver: true }),
      Animated.spring(shieldScale, { toValue: 1, tension: 60, friction: 10, useNativeDriver: true }),
    ]).start();
    Animated.loop(Animated.timing(spin, { toValue: 1, duration: 2000, useNativeDriver: true })).start();
    Animated.loop(Animated.sequence([
      Animated.timing(pulse, { toValue: 1.08, duration: 900, useNativeDriver: true }),
      Animated.timing(pulse, { toValue: 0.90, duration: 900, useNativeDriver: true }),
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
      {/* Shield + spinner */}
      <Animated.View style={{
        transform: [{ scale: shieldScale }], opacity: shieldOp,
        alignItems: 'center', justifyContent: 'center',
        width: 130, height: 130, marginBottom: 32
      }}>
        <Animated.View style={{
          position: 'absolute', width: 130, height: 130, borderRadius: 65,
          borderWidth: 2, borderColor: C.cyan, borderTopColor: 'transparent',
          transform: [{ rotate }, { scale: pulse }],
          shadowColor: C.cyan, shadowRadius: 24, shadowOpacity: 0.6,
        }} />
        <Image
          source={require('../../assets/shield-call.png')}
          style={{ width: 90, height: 90 }}
          resizeMode="contain"
        />
      </Animated.View>

      <Text style={[S.title, { textAlign: 'center', marginBottom: 8 }]}>Analyzing Call</Text>
      <Text style={[S.mutedText, { textAlign: 'center', marginBottom: 20 }]}>
        7-layer Scam Intelligence Engine
      </Text>

      {/* Dots */}
      <View style={{ flexDirection: 'row', gap: 8, marginBottom: 28 }}>
        {[dot1, dot2, dot3].map((d, i) => (
          <Animated.View key={i} style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: C.cyan, opacity: d }} />
        ))}
      </View>

      {/* Layer labels */}
      {['Policy Check', 'Manipulation Detect', 'Script Match', 'Isolation Signal', 'Qwen3 Thinking', 'Live Web Search'].map((layer, i) => (
        <Text key={i} style={{ color: 'rgba(0,212,255,0.4)', fontSize: 11, marginTop: 5, letterSpacing: 0.8 }}>
          ▶ {layer}
        </Text>
      ))}
    </View>
  );
}

// ─── Verdict View ─────────────────────────────────────────────────────────────
function VerdictView({ result, onClose, onRetry }: { result: CallAnalysisResult; onClose: () => void; onRetry: () => void }) {
  const fadeIn   = useRef(new Animated.Value(0)).current;
  const slideUp  = useRef(new Animated.Value(40)).current;
  const scoreAnim = useRef(new Animated.Value(0)).current;
  const [displayScore, setDisplayScore] = useState(0);
  
  // Minimal UI & Translation state
  const [showMoreDetails, setShowMoreDetails] = useState(false);
  const [showLangSheet, setShowLangSheet] = useState(false);
  const [translatedMeans, setTranslatedMeans] = useState<string | null>(null);
  const [isTranslating, setIsTranslating] = useState(false);

  const SUPPORTED_LANGS = [
    { code: 'en', name: 'English' },
    { code: 'hi', name: 'Hindi' },
    { code: 'bn', name: 'Bengali' },
    { code: 'te', name: 'Telugu' },
    { code: 'mr', name: 'Marathi' },
    { code: 'ta', name: 'Tamil' },
    { code: 'ur', name: 'Urdu' },
    { code: 'gu', name: 'Gujarati' },
    { code: 'kn', name: 'Kannada' },
    { code: 'ml', name: 'Malayalam' },
    { code: 'pa', name: 'Punjabi' },
    { code: 'or', name: 'Odia' }
  ];

  const handleTranslate = async (langCode: string) => {
    setShowLangSheet(false);
    if (langCode === 'en') {
      setTranslatedMeans(null); // revert to original
      return;
    }
    if (!result.means_for_you) return;
    
    setIsTranslating(true);
    try {
      const translated = await translateText(result.means_for_you, langCode);
      setTranslatedMeans(translated);
    } catch (e) {
      console.error(e);
      Alert.alert('Translation failed', 'Could not translate text.');
    } finally {
      setIsTranslating(false);
    }
  };

  const isHighRisk = result.risk_band === 'HIGH RISK';
  const isCritical = result.risk_band === 'CRITICAL';
  const isSafe     = result.risk_band === 'SAFE';
  const ORANGE     = '#FF6B00';
  const color      = isCritical ? C.rose : isHighRisk ? ORANGE : isSafe ? C.green : C.gold;
  const label      = isCritical ? '🔴 CRITICAL — SCAM' : isHighRisk ? '🟠 HIGH RISK' : isSafe ? '🟢 SAFE' : '🟡 SUSPICIOUS';

  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn,  { toValue: 1, duration: 500, useNativeDriver: true }),
      Animated.spring(slideUp, { toValue: 0, tension: 70, friction: 10, useNativeDriver: true }),
    ]).start();
    scoreAnim.addListener(({ value }) => setDisplayScore(Math.round(value)));
    Animated.timing(scoreAnim, { toValue: result.score_display, duration: 1200, useNativeDriver: false }).start();
    return () => scoreAnim.removeAllListeners();
  }, []);

  return (
    <Animated.View style={{ flex: 1, opacity: fadeIn, transform: [{ translateY: slideUp }] }}>
      <ScrollView contentContainerStyle={{ padding: 24, paddingBottom: 120 }} showsVerticalScrollIndicator={false}>

        {/* Score ring + confidence bar */}
        <View style={{ alignItems: 'center', marginBottom: 28 }}>
          <View style={{
            width: 130, height: 130, borderRadius: 65,
            backgroundColor: `${color}18`, borderWidth: 2.5, borderColor: color,
            alignItems: 'center', justifyContent: 'center',
            shadowColor: color, shadowRadius: 28, shadowOpacity: 0.6, marginBottom: 14,
          }}>
            <Text style={{ fontSize: 42, fontWeight: '900', color }}>{displayScore}</Text>
            <Text style={{ fontSize: 10, color: 'rgba(255,255,255,0.45)', letterSpacing: 1.5 }}>RISK SCORE</Text>
          </View>
          <Text style={{ fontSize: 20, fontWeight: '800', color, letterSpacing: 0.5, marginBottom: 14 }}>{label}</Text>
          {/* Confidence bar */}
          <View style={{ flexDirection: 'row', alignItems: 'center', width: '82%', gap: 10 }}>
            <Text style={{ color: 'rgba(255,255,255,0.38)', fontSize: 11, width: 74 }}>Confidence</Text>
            <View style={{ flex: 1, height: 5, backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: 3 }}>
              <View style={{
                width: `${Math.round((result.confidence_score || 0) * 100)}%` as any,
                height: 5, backgroundColor: color, borderRadius: 3,
              }} />
            </View>
            <Text style={{ color, fontSize: 12, fontWeight: '700', width: 36, textAlign: 'right' }}>
              {Math.round((result.confidence_score || 0) * 100)}%
            </Text>
          </View>
        </View>


        {/* Analysis Summary — always shown (Qwen3-enhanced when live, deterministic fallback otherwise) */}
        {(result.plain_english || result.deterministic_explanation) ? (
          <GlassCard accentColor={C.violet} style={{ marginBottom: 16 }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
              <Ionicons name="hardware-chip" size={15} color={C.violet} style={{ marginRight: 8 }} />
              <Text style={{ color: C.violet, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Analysis Summary</Text>
              {result.qwen_available && (
                <View style={{ marginLeft: 8, backgroundColor: 'rgba(140,82,255,0.15)', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 10 }}>
                  <Text style={{ color: C.violet, fontSize: 9, fontWeight: '700' }}>AI ENHANCED</Text>
                </View>
              )}
            </View>
            <Text style={{ color: 'rgba(255,255,255,0.88)', fontSize: 13, lineHeight: 21 }}>
              {result.plain_english || result.deterministic_explanation}
            </Text>
            {result.tactics_detected && result.tactics_detected.filter(t => t !== 'none_detected').length > 0 && (
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
          </GlassCard>
        ) : null}

        {/* What This Means For You */}
        {result.means_for_you ? (
          <GlassCard accentColor={color} style={{ marginBottom: 16 }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10, justifyContent: 'space-between' }}>
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <Ionicons name="person" size={15} color={color} style={{ marginRight: 8 }} />
                <Text style={{ color, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>What This Means For You</Text>
              </View>
              <TouchableOpacity onPress={() => setShowLangSheet(true)} style={{ padding: 4, backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: 12 }}>
                <Ionicons name="language" size={16} color="#fff" />
              </TouchableOpacity>
            </View>
            {isTranslating ? (
              <ActivityIndicator size="small" color={color} style={{ marginVertical: 10 }} />
            ) : (
              <Text style={{ color: '#fff', fontSize: 14, lineHeight: 22 }}>
                {translatedMeans || result.means_for_you}
              </Text>
            )}
          </GlassCard>
        ) : null}

        {/* How To Verify Safely */}
        {result.how_to_verify && result.how_to_verify.length > 0 && (
          <GlassCard accentColor={C.green} style={{ marginBottom: 16 }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
              <Ionicons name="shield-checkmark" size={15} color={C.green} style={{ marginRight: 8 }} />
              <Text style={{ color: C.green, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>How To Verify Safely</Text>
            </View>
            {result.how_to_verify.map((step, i) => (
              <View key={i} style={{ flexDirection: 'row', marginBottom: 8, alignItems: 'flex-start' }}>
                <Text style={{ color: C.green, marginRight: 8, fontWeight: '700', fontSize: 14, minWidth: 18 }}>{i + 1}.</Text>
                <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 13, lineHeight: 20, flex: 1 }}>{step}</Text>
              </View>
            ))}
          </GlassCard>
        )}

        <TouchableOpacity 
          onPress={() => setShowMoreDetails(!showMoreDetails)}
          style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'center', paddingVertical: 12, backgroundColor: 'rgba(255,255,255,0.04)', borderRadius: 12, marginBottom: 16 }}
        >
          <Text style={{ color: 'rgba(255,255,255,0.6)', fontSize: 13, fontWeight: '600', marginRight: 6 }}>
            {showMoreDetails ? 'Hide Details' : 'More Details'}
          </Text>
          <Ionicons name={showMoreDetails ? 'chevron-up' : 'chevron-down'} size={14} color="rgba(255,255,255,0.6)" />
        </TouchableOpacity>

        {showMoreDetails && (
          <View>
            {/* Why flagged */}
            {result.why_flagged.length > 0 && (
              <GlassCard accentColor={color} style={{ marginBottom: 16 }}>
                <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 14 }}>
                  <Ionicons name="alert-circle" size={15} color={color} style={{ marginRight: 8 }} />
                  <Text style={{ color, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Why Flagged</Text>
                </View>
                {result.why_flagged.map((f, i) => (
                  <View key={i} style={{ flexDirection: 'row', marginBottom: 10, paddingLeft: 10, borderLeftWidth: 2, borderLeftColor: color }}>
                    <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 13, lineHeight: 20, flex: 1, fontStyle: 'italic' }}>{f}</Text>
                  </View>
                ))}
              </GlassCard>
            )}

            {/* What They Might Do Next */}
            {result.next_tactics && result.next_tactics.length > 0 && (
              <GlassCard accentColor={C.rose} style={{ marginBottom: 16 }}>
                <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
                  <Ionicons name="trending-up" size={15} color={C.rose} style={{ marginRight: 8 }} />
                  <Text style={{ color: C.rose, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>What They Might Do Next</Text>
                </View>
                {result.next_tactics.map((tactic, i) => (
                  <View key={i} style={{ flexDirection: 'row', marginBottom: 8, alignItems: 'flex-start' }}>
                    <Text style={{ color: C.rose, marginRight: 8, fontSize: 14, marginTop: 1 }}>!</Text>
                    <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 13, lineHeight: 20, flex: 1 }}>{tactic}</Text>
                  </View>
                ))}
              </GlassCard>
            )}

            {/* Recommended action */}
            {result.recommended_action ? (
              <GlassCard accentColor={C.cyan} style={{ marginBottom: 16 }}>
                <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
                  <Ionicons name="checkmark-circle" size={15} color={C.cyan} style={{ marginRight: 8 }} />
                  <Text style={{ color: C.cyan, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Recommended Action</Text>
                </View>
                <Text style={{ color: '#fff', fontSize: 14, lineHeight: 21 }}>{result.recommended_action}</Text>
              </GlassCard>
            ) : null}

            {/* Live Policy Fact-Check */}
            {result.live_policy_check?.checked && (
              <GlassCard
                accentColor={result.live_policy_check.policy_allows === false ? C.rose : result.live_policy_check.policy_allows === true ? C.green : C.gold}
                style={{ marginBottom: 16 }}
              >
                <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
                  <Ionicons name="globe-outline" size={15} color={C.cyan} style={{ marginRight: 8 }} />
                  <Text style={{ color: C.cyan, fontSize: 11, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 1 }}>Live Web Verification</Text>
                  <View style={{ marginLeft: 'auto', backgroundColor: 'rgba(0,212,255,0.1)', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 10 }}>
                    <Text style={{ color: C.cyan, fontSize: 9, fontWeight: '700' }}>TAVILY AI</Text>
                  </View>
                </View>
                <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
                  <View style={{
                    paddingHorizontal: 10, paddingVertical: 4, borderRadius: 12,
                    backgroundColor: result.live_policy_check.policy_allows === false ? 'rgba(255,61,113,0.15)' : result.live_policy_check.policy_allows === true ? 'rgba(52,199,89,0.15)' : 'rgba(255,170,0,0.15)',
                  }}>
                    <Text style={{ fontSize: 11, fontWeight: '700', color: result.live_policy_check.policy_allows === false ? C.rose : result.live_policy_check.policy_allows === true ? C.green : C.gold }}>
                      {result.live_policy_check.policy_allows === false ? '⛔ POLICY PROHIBITS THIS' : result.live_policy_check.policy_allows === true ? '✅ POLICY ALLOWS THIS' : '⚠️ POLICY UNCLEAR'}
                    </Text>
                  </View>
                  <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 10, marginLeft: 8 }}>
                    {Math.round((result.live_policy_check.confidence || 0) * 100)}% conf
                  </Text>
                </View>
                {result.live_policy_check.verdict_text ? (
                  <Text style={{ color: 'rgba(255,255,255,0.8)', fontSize: 13, lineHeight: 20, marginBottom: 10 }}>{result.live_policy_check.verdict_text}</Text>
                ) : null}
                {result.live_policy_check.source_url ? (
                  <TouchableOpacity style={{ flexDirection: 'row', alignItems: 'center', marginTop: 4 }} onPress={() => Linking.openURL(result.live_policy_check!.source_url!)}>
                    <Ionicons name="link-outline" size={13} color={C.cyan} style={{ marginRight: 5 }} />
                    <Text style={{ color: C.cyan, fontSize: 12, textDecorationLine: 'underline', flex: 1 }} numberOfLines={1}>
                      {result.live_policy_check.source_label || result.live_policy_check.source_url}
                    </Text>
                    <Ionicons name="open-outline" size={13} color={C.cyan} style={{ marginLeft: 4 }} />
                  </TouchableOpacity>
                ) : null}
              </GlassCard>
            )}

            {/* Official callback */}
            {result.official_callback_number ? (
              <GlassCard accentColor={C.cyan} style={{ marginBottom: 24 }}>
                <Text style={{ color: 'rgba(255,255,255,0.5)', fontSize: 11, marginBottom: 6, letterSpacing: 1, textTransform: 'uppercase' }}>Official Helpline</Text>
                <Text style={{ color: C.cyan, fontSize: 20, fontWeight: '700' }}>{result.official_callback_number}</Text>
                <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: 12, marginTop: 4 }}>Call this number to verify — not the number they gave you.</Text>
              </GlassCard>
            ) : null}
          </View>
        )}

        {/* CTAs */}
        {isCritical && (
          <TouchableOpacity style={[S.primaryBtn, { backgroundColor: C.rose, marginBottom: 12 }]} onPress={() => Linking.openURL('tel:')}>
            <Text style={[S.btnText, { color: '#fff' }]}>📵  Hang Up Now</Text>
          </TouchableOpacity>
        )}
        <TouchableOpacity style={[S.primaryBtn, { backgroundColor: 'rgba(255,255,255,0.08)', marginBottom: 12 }]} onPress={onRetry}>
          <Text style={[S.btnText, { color: 'rgba(255,255,255,0.75)' }]}>Analyze Another Call</Text>
        </TouchableOpacity>
        <TouchableOpacity style={S.closeBtn} onPress={onClose}>
          <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 15 }}>Close</Text>
        </TouchableOpacity>
      </ScrollView>

      {/* Language Picker Modal */}
      <Modal visible={showLangSheet} transparent animationType="slide">
        <View style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.6)', justifyContent: 'flex-end' }}>
          <View style={{ backgroundColor: '#1a1d26', borderTopLeftRadius: 24, borderTopRightRadius: 24, padding: 24, maxHeight: SCREEN_HEIGHT * 0.7 }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <Text style={{ color: '#fff', fontSize: 18, fontWeight: '700' }}>Select Language</Text>
              <TouchableOpacity onPress={() => setShowLangSheet(false)}>
                <Ionicons name="close" size={24} color="rgba(255,255,255,0.5)" />
              </TouchableOpacity>
            </View>
            <ScrollView showsVerticalScrollIndicator={false}>
              {SUPPORTED_LANGS.map((lang) => (
                <TouchableOpacity
                  key={lang.code}
                  onPress={() => handleTranslate(lang.code)}
                  style={{ paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: 'rgba(255,255,255,0.05)' }}
                >
                  <Text style={{ color: '#fff', fontSize: 16 }}>{lang.name}</Text>
                </TouchableOpacity>
              ))}
            </ScrollView>
          </View>
        </View>
      </Modal>

    </Animated.View>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const S = StyleSheet.create({
  sheet: {
    flex: 1,
    backgroundColor: 'transparent',
  },
  headerBar: {
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
    color: 'rgba(255,255,255,0.75)',
    fontSize: 15,
    marginLeft: 2,
  },
  headerPill: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(0,212,255,0.12)',
    paddingHorizontal: 14,
    paddingVertical: 7,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(0,212,255,0.35)',
    gap: 8,
  },
  headerPillText: {
    color: '#00d4ff',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 1.5,
  },
  liveIndicator: {
    width: 6, height: 6, borderRadius: 3,
    backgroundColor: '#00d4ff',
    shadowColor: '#00d4ff', shadowRadius: 4, shadowOpacity: 1,
  },
  title: {
    fontSize: 26, fontWeight: '700', color: '#fff', letterSpacing: -0.3,
  },
  mutedText: {
    color: 'rgba(255,255,255,0.45)', fontSize: 14, lineHeight: 20,
  },
  primaryBtn: {
    backgroundColor: '#00d4ff',
    padding: 18, borderRadius: 16,
    width: '100%', alignItems: 'center',
    shadowColor: '#00d4ff', shadowRadius: 12, shadowOpacity: 0.35,
  },
  btnText: {
    color: '#06080f', fontSize: 16, fontWeight: '700', letterSpacing: 0.3,
  },
  closeBtn: {
    alignItems: 'center', padding: 12,
  },
});
