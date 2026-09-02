import React, { useState, useEffect, useRef } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, ScrollView,
  Alert, ActivityIndicator, Linking
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { Audio } from 'expo-av';
import * as FileSystem from 'expo-file-system';
import { analyzeCall, CallAnalysisResult } from '../api';

type ScreenState = 'CHOOSING' | 'RECORDING' | 'STRUCTURED' | 'ANALYZING' | 'VERDICT' | 'ERROR';

export default function CallAnalyzerScreen({ onClose }: { onClose: () => void }) {
  const [screenState, setScreenState] = useState<ScreenState>('CHOOSING');
  
  // Path A - Voice
  const [recording, setRecording] = useState<Audio.Recording | null>(null);
  const [timeLeft, setTimeLeft] = useState(20);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Path B - Structured
  const [orgClaimed, setOrgClaimed] = useState<string>('');
  const [actions, setActions] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  
  // Results
  const [result, setResult] = useState<CallAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState('');

  // Clean up recording if unmounted
  useEffect(() => {
    return () => {
      if (recording) {
        recording.stopAndUnloadAsync().catch(() => {});
      }
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [recording]);

  const toggleItem = (list: string[], setList: (l: string[]) => void, item: string) => {
    if (list.includes(item)) {
      setList(list.filter(i => i !== item));
    } else {
      setList([...list, item]);
    }
  };

  const startRecording = async () => {
    try {
      const { status } = await Audio.requestPermissionsAsync();
      if (status !== 'granted') {
        Alert.alert('Mic Access Denied', 'Falling back to the tap form.');
        setScreenState('STRUCTURED');
        return;
      }

      await Audio.setAudioModeAsync({
        allowsRecordingIOS: true,
        playsInSilentModeIOS: true,
      });

      const { recording: newRecording } = await Audio.Recording.createAsync(
        Audio.RecordingOptionsPresets.HIGH_QUALITY
      );

      setRecording(newRecording);
      setScreenState('RECORDING');
      setTimeLeft(20);

      timerRef.current = setInterval(() => {
        setTimeLeft(prev => {
          if (prev <= 1) {
            stopRecording(newRecording);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    } catch (err) {
      console.warn('Mic blocked or busy', err);
      Alert.alert('Mic Unavailable', 'Your microphone is in use by the call. Please use the tap form instead.');
      setScreenState('STRUCTURED');
    }
  };

  const stopRecording = async (recToStop = recording) => {
    if (!recToStop) return;
    
    if (timerRef.current) clearInterval(timerRef.current);
    
    try {
      await recToStop.stopAndUnloadAsync();
      const uri = recToStop.getURI();
      
      if (!uri) throw new Error("No URI");
      
      const fileInfo = await FileSystem.getInfoAsync(uri);
      
      // If file is tiny, it means the mic was blocked by the OS during the call
      if (fileInfo.exists && fileInfo.size < 1000) {
        Alert.alert('Mic Blocked', 'The phone call blocked microphone access. Please use the tap form instead.');
        setScreenState('STRUCTURED');
        return;
      }
      
      submitVoiceAnalysis(uri);
    } catch (err) {
      console.warn('Stop recording failed', err);
      setScreenState('STRUCTURED');
    }
    setRecording(null);
  };

  const submitVoiceAnalysis = async (uri: string) => {
    setScreenState('ANALYZING');
    try {
      const res = await analyzeCall({
        inputMode: 'voice',
        audioUri: uri
      });
      setResult(res);
      setScreenState('VERDICT');
    } catch (err: any) {
      setErrorMsg(err.message || 'Analysis failed');
      setScreenState('ERROR');
    }
  };

  const submitStructuredAnalysis = async () => {
    setScreenState('ANALYZING');
    try {
      const res = await analyzeCall({
        inputMode: 'structured',
        orgClaimed,
        actionsRequested: actions,
        warningPhrases: warnings
      });
      setResult(res);
      setScreenState('VERDICT');
    } catch (err: any) {
      setErrorMsg(err.message || 'Analysis failed');
      setScreenState('ERROR');
    }
  };

  const canSubmitStructured = orgClaimed.length > 0 || actions.length >= 1 || warnings.length >= 1;

  if (screenState === 'ANALYZING') {
    return (
      <View style={styles.centerContainer}>
        <ActivityIndicator size="large" color="#00f3ff" />
        <Text style={styles.analyzingText}>Analyzing call patterns...</Text>
        <Text style={styles.subText}>SafeMail X Scam Intelligence Engine is running.</Text>
      </View>
    );
  }

  if (screenState === 'ERROR') {
    return (
      <View style={styles.centerContainer}>
        <Ionicons name="alert-circle" size={48} color="#ff3d71" />
        <Text style={styles.errorText}>Analysis Failed</Text>
        <Text style={styles.subText}>{errorMsg}</Text>
        <TouchableOpacity style={styles.primaryBtn} onPress={() => setScreenState('CHOOSING')}>
          <Text style={styles.btnText}>Try Again</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (screenState === 'VERDICT' && result) {
    const isSafe = result.risk_band === 'SAFE';
    const isCritical = result.risk_band === 'CRITICAL';
    const color = isCritical ? '#ff3d71' : (isSafe ? '#34C759' : '#ffaa00');

    return (
      <ScrollView style={styles.container} contentContainerStyle={{ padding: 24, paddingBottom: 100 }}>
        <View style={[styles.verdictHeader, { backgroundColor: `${color}20`, borderColor: color }]}>
          <Text style={[styles.verdictScore, { color }]}>
            {isCritical ? '🔴 CRITICAL' : (isSafe ? '🟢 SAFE' : '🟡 SUSPICIOUS')} — {result.score_display}/100
          </Text>
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Caller Claims</Text>
          <Text style={styles.cardText}>From: {result.org_claimed || 'Unknown'}</Text>
          <Text style={styles.cardText}>Purpose: {result.purpose_detected || 'Unknown'}</Text>
        </View>

        {result.why_flagged.length > 0 && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Why SafeMail X flagged this:</Text>
            {result.why_flagged.map((flag, idx) => (
              <Text key={idx} style={styles.bulletItem}>• {flag}</Text>
            ))}
          </View>
        )}

        <Text style={styles.actionPrompt}>{result.recommended_action}</Text>

        <TouchableOpacity 
          style={[styles.actionBtn, { backgroundColor: '#ff3d71' }]}
          onPress={() => Linking.openURL('tel:')}
        >
          <Text style={styles.btnText}>📵 Hang Up Now</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.secondaryBtn} onPress={onClose}>
          <Text style={styles.secondaryBtnText}>Close</Text>
        </TouchableOpacity>
      </ScrollView>
    );
  }

  if (screenState === 'RECORDING') {
    return (
      <View style={styles.centerContainer}>
        <View style={styles.recordingPulsar}>
          <Ionicons name="mic" size={48} color="#ff3d71" />
        </View>
        <Text style={styles.timerText}>00:{timeLeft.toString().padStart(2, '0')}</Text>
        <Text style={styles.subText}>Describe the call briefly. Be specific.</Text>
        
        <TouchableOpacity style={styles.stopBtn} onPress={() => stopRecording()}>
          <Text style={styles.btnText}>Stop & Analyze</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (screenState === 'STRUCTURED') {
    return (
      <ScrollView style={styles.container} contentContainerStyle={{ padding: 24, paddingBottom: 100 }}>
        <Text style={styles.headerTitle}>Describe the Call</Text>
        
        <Text style={styles.sectionLabel}>Who do they claim to be?</Text>
        <View style={styles.chipRow}>
          {['SBI Bank', 'HDFC', 'ICICI', 'UIDAI', 'Police/CBI', 'Customs', 'Income Tax'].map(org => (
            <TouchableOpacity 
              key={org} 
              style={[styles.chip, orgClaimed === org && styles.chipActive]}
              onPress={() => setOrgClaimed(org === orgClaimed ? '' : org)}
            >
              <Text style={[styles.chipText, orgClaimed === org && styles.chipTextActive]}>{org}</Text>
            </TouchableOpacity>
          ))}
        </View>

        <Text style={styles.sectionLabel}>What did they ask for? (tap all that apply)</Text>
        <View style={styles.chipRow}>
          {['OTP or PIN', 'Card details / CVV', 'Aadhaar number', 'Transfer money', 'Install an app', 'Share screen'].map(action => {
            const active = actions.includes(action);
            return (
              <TouchableOpacity 
                key={action} 
                style={[styles.chip, active && styles.chipActive]}
                onPress={() => toggleItem(actions, setActions, action)}
              >
                <Text style={[styles.chipText, active && styles.chipTextActive]}>{action}</Text>
              </TouchableOpacity>
            )
          })}
        </View>

        <Text style={styles.sectionLabel}>Did they say any of these?</Text>
        <View style={styles.chipRow}>
          {['Account will be blocked', 'Arrest warrant / FIR', "Don't tell anyone", "Stay on the line"].map(warning => {
            const active = warnings.includes(warning);
            return (
              <TouchableOpacity 
                key={warning} 
                style={[styles.chip, active && styles.chipActive]}
                onPress={() => toggleItem(warnings, setWarnings, warning)}
              >
                <Text style={[styles.chipText, active && styles.chipTextActive]}>{warning}</Text>
              </TouchableOpacity>
            )
          })}
        </View>

        <TouchableOpacity 
          style={[styles.primaryBtn, { opacity: canSubmitStructured ? 1 : 0.5, marginTop: 24 }]}
          disabled={!canSubmitStructured}
          onPress={submitStructuredAnalysis}
        >
          <Text style={styles.btnText}>Analyze Now</Text>
        </TouchableOpacity>
      </ScrollView>
    );
  }

  // CHOOSING
  return (
    <View style={styles.centerContainer}>
      <Text style={styles.headerTitle}>Suspicious Call?</Text>
      <Text style={styles.subText}>Tell SafeMail X what is happening to get an instant analysis.</Text>

      <TouchableOpacity style={styles.largeChoiceBtn} onPress={startRecording}>
        <Ionicons name="mic-outline" size={28} color="#00f3ff" />
        <View style={{ marginLeft: 16 }}>
          <Text style={styles.choiceBtnTitle}>Speak it</Text>
          <Text style={styles.choiceBtnSub}>Record a 20-sec description</Text>
        </View>
      </TouchableOpacity>

      <TouchableOpacity style={styles.largeChoiceBtn} onPress={() => setScreenState('STRUCTURED')}>
        <Ionicons name="list-outline" size={28} color="#8c52ff" />
        <View style={{ marginLeft: 16 }}>
          <Text style={styles.choiceBtnTitle}>Tap to describe</Text>
          <Text style={styles.choiceBtnSub}>Use quick checkboxes</Text>
        </View>
      </TouchableOpacity>
      
      <TouchableOpacity style={{ marginTop: 32 }} onPress={onClose}>
        <Text style={{ color: '#6a7d8c', fontSize: 16 }}>Cancel</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#09101a' },
  centerContainer: { flex: 1, backgroundColor: '#09101a', justifyContent: 'center', alignItems: 'center', padding: 24 },
  headerTitle: { fontSize: 24, fontWeight: '700', color: '#fff', marginBottom: 12, textAlign: 'center' },
  subText: { fontSize: 15, color: '#6a7d8c', textAlign: 'center', marginBottom: 32, lineHeight: 22 },
  
  largeChoiceBtn: { 
    flexDirection: 'row', alignItems: 'center', backgroundColor: '#111a26', 
    padding: 20, borderRadius: 16, width: '100%', marginBottom: 16,
    borderWidth: 1, borderColor: 'rgba(255,255,255,0.1)'
  },
  choiceBtnTitle: { fontSize: 18, color: '#fff', fontWeight: '600' },
  choiceBtnSub: { fontSize: 13, color: '#6a7d8c', marginTop: 4 },
  
  sectionLabel: { fontSize: 14, color: '#00f3ff', fontWeight: '600', marginTop: 24, marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 },
  chipRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 10 },
  chip: { 
    paddingVertical: 10, paddingHorizontal: 16, borderRadius: 20, 
    backgroundColor: '#111a26', borderWidth: 1, borderColor: 'rgba(255,255,255,0.1)'
  },
  chipActive: { backgroundColor: 'rgba(0, 243, 255, 0.15)', borderColor: '#00f3ff' },
  chipText: { color: '#6a7d8c', fontSize: 14, fontWeight: '500' },
  chipTextActive: { color: '#00f3ff', fontWeight: '600' },
  
  primaryBtn: { backgroundColor: '#2972ff', padding: 16, borderRadius: 12, width: '100%', alignItems: 'center' },
  btnText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  
  timerText: { fontSize: 48, fontWeight: '200', color: '#fff', marginTop: 32, marginBottom: 16, fontVariant: ['tabular-nums'] },
  recordingPulsar: { width: 120, height: 120, borderRadius: 60, backgroundColor: 'rgba(255, 61, 113, 0.1)', justifyContent: 'center', alignItems: 'center', borderWidth: 2, borderColor: '#ff3d71' },
  stopBtn: { backgroundColor: '#111a26', padding: 16, borderRadius: 12, width: '100%', alignItems: 'center', borderWidth: 1, borderColor: '#ff3d71', marginTop: 20 },
  
  analyzingText: { fontSize: 20, color: '#fff', fontWeight: '600', marginTop: 24, marginBottom: 8 },
  errorText: { fontSize: 20, color: '#fff', fontWeight: '600', marginTop: 16, marginBottom: 8 },
  
  verdictHeader: { padding: 16, borderRadius: 12, borderWidth: 1, marginBottom: 24, alignItems: 'center' },
  verdictScore: { fontSize: 20, fontWeight: '700' },
  card: { backgroundColor: '#111a26', padding: 16, borderRadius: 12, marginBottom: 16, borderWidth: 1, borderColor: 'rgba(255,255,255,0.05)' },
  cardTitle: { color: '#00f3ff', fontSize: 13, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 },
  cardText: { color: '#fff', fontSize: 15, marginBottom: 8 },
  bulletItem: { color: '#fff', fontSize: 14, lineHeight: 22, marginBottom: 12, fontStyle: 'italic' },
  
  actionPrompt: { color: '#fff', fontSize: 15, fontWeight: '500', textAlign: 'center', marginTop: 8, marginBottom: 24, lineHeight: 22 },
  actionBtn: { padding: 16, borderRadius: 12, width: '100%', alignItems: 'center', marginBottom: 12 },
  secondaryBtn: { padding: 16, borderRadius: 12, width: '100%', alignItems: 'center', backgroundColor: '#111a26' },
  secondaryBtnText: { color: '#6a7d8c', fontSize: 16, fontWeight: '600' }
});
