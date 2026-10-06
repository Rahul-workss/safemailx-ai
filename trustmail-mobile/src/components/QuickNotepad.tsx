/**
 * SafeMail X — Quick Notepad (Assistive Touch)
 * Liquid glass theme — matches App.tsx TmCard exactly.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Animated, Keyboard, ScrollView, StyleSheet, Text,
  TextInput, TouchableOpacity, View,
} from 'react-native';
import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { TM } from './LiquidGlass';

const NOTES_KEY = 'safemail_quick_notes';
const MAX_SAVED = 5;

interface SavedNote { text: string; ts: number; }

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true })
    + ' · ' + d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
}

interface Props { onClose: () => void; visible: boolean; }

export default function QuickNotepad({ onClose, visible }: Props) {
  const [draft, setDraft] = useState('');
  const [saved, setSaved] = useState<SavedNote[]>([]);
  const [saving, setSaving] = useState(false);
  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(24)).current;
  const saveTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const inputRef = useRef<TextInput>(null);

  useEffect(() => {
    AsyncStorage.getItem(NOTES_KEY).then(raw => { if (raw) setSaved(JSON.parse(raw)); });
  }, []);

  useEffect(() => {
    if (visible) {
      Animated.parallel([
        Animated.timing(fadeIn, { toValue: 1, duration: 220, useNativeDriver: true }),
        Animated.spring(slideUp, { toValue: 0, tension: 80, friction: 10, useNativeDriver: true }),
      ]).start(() => inputRef.current?.focus());
    } else {
      Animated.parallel([
        Animated.timing(fadeIn, { toValue: 0, duration: 150, useNativeDriver: true }),
        Animated.timing(slideUp, { toValue: 24, duration: 150, useNativeDriver: true }),
      ]).start();
    }
  }, [visible]);

  const autosave = useCallback((text: string) => {
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(async () => {
      if (!text.trim()) return;
      setSaving(true);
      const note: SavedNote = { text: text.trim(), ts: Date.now() };
      const updated = [note, ...saved].slice(0, MAX_SAVED);
      await AsyncStorage.setItem(NOTES_KEY, JSON.stringify(updated));
      setSaved(updated);
      setSaving(false);
    }, 800);
  }, [saved]);

  const saveAndClose = async () => {
    clearTimeout(saveTimer.current);
    if (draft.trim()) {
      const note: SavedNote = { text: draft.trim(), ts: Date.now() };
      const updated = [note, ...saved].slice(0, MAX_SAVED);
      await AsyncStorage.setItem(NOTES_KEY, JSON.stringify(updated));
      setSaved(updated);
    }
    setDraft('');
    Keyboard.dismiss();
    onClose();
  };

  const deleteNote = async (ts: number) => {
    const updated = saved.filter(n => n.ts !== ts);
    setSaved(updated);
    await AsyncStorage.setItem(NOTES_KEY, JSON.stringify(updated));
  };

  if (!visible) return null;

  return (
    <Animated.View style={[S.shell, { opacity: fadeIn, transform: [{ translateY: slideUp }] }]}>
      {/* Liquid glass layers */}
      <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />
      <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.40)' }]} />
      <LinearGradient
        colors={['rgba(255,255,255,0.08)','rgba(255,255,255,0.01)','rgba(255,255,255,0.00)','rgba(255,255,255,0.03)']}
        start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
        style={StyleSheet.absoluteFillObject}
      />
      <View style={S.shimmer} />

      {/* Content */}
      <View style={S.header}>
        <View style={S.headerLeft}>
          <View style={[S.iconRing, { borderColor: TM.gold, backgroundColor: 'rgba(232,168,76,0.15)' }]}>
            <Ionicons name="document-text-outline" size={13} color={TM.gold} />
          </View>
          <Text style={[S.title, { color: TM.gold }]}>Quick Notes</Text>
          {saving && <Text style={S.savingHint}>saving…</Text>}
        </View>
        <TouchableOpacity onPress={saveAndClose} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
          <Ionicons name="checkmark-circle" size={22} color={TM.emerald} />
        </TouchableOpacity>
      </View>

      {/* Gold shimmer divider */}
      <LinearGradient
        colors={['transparent', 'rgba(232,168,76,0.22)', 'transparent']}
        start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }}
        style={{ height: 1, marginBottom: 12 }}
      />

      <TextInput
        ref={inputRef}
        style={S.input}
        placeholder="Caller name, number, what they said…"
        placeholderTextColor="rgba(242,234,253,0.25)"
        multiline
        value={draft}
        onChangeText={t => { setDraft(t); autosave(t); }}
        maxLength={600}
      />

      {saved.length > 0 && (
        <>
          <Text style={S.recentsLabel}>RECENT NOTES</Text>
          <ScrollView style={{ maxHeight: 150 }} showsVerticalScrollIndicator={false}>
            {saved.map(note => (
              <View key={note.ts} style={S.noteChip}>
                <BlurView intensity={14} tint="dark" style={StyleSheet.absoluteFillObject} />
                <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(255,255,255,0.04)', borderRadius: 12 }]} />
                <View style={{ flex: 1 }}>
                  <Text style={S.noteText} numberOfLines={2}>{note.text}</Text>
                  <Text style={S.noteTime}>{formatTime(note.ts)}</Text>
                </View>
                <TouchableOpacity onPress={() => deleteNote(note.ts)} hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}>
                  <Ionicons name="close" size={13} color={TM.frost4} />
                </TouchableOpacity>
              </View>
            ))}
          </ScrollView>
        </>
      )}
    </Animated.View>
  );
}

const S = StyleSheet.create({
  shell: {
    borderRadius: 20, borderWidth: 1,
    borderColor: 'rgba(232,168,76,0.28)',
    padding: 16, width: 300, overflow: 'hidden',
    shadowColor: '#e8a84c', shadowOffset: { width: 0, height: 16 },
    shadowOpacity: 0.35, shadowRadius: 20, elevation: 10,
  },
  shimmer: { position: 'absolute', top: 0, left: 0, right: 0, height: 1.2, backgroundColor: 'rgba(255,255,255,0.35)' },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 },
  headerLeft: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  iconRing: { width: 26, height: 26, borderRadius: 13, borderWidth: 1, alignItems: 'center', justifyContent: 'center' },
  title: { fontSize: 12, fontWeight: '700', letterSpacing: 1.2, textTransform: 'uppercase' },
  savingHint: { color: TM.frost4, fontSize: 10 },
  input: {
    color: TM.frost, fontSize: 14, lineHeight: 21,
    minHeight: 80, maxHeight: 130, textAlignVertical: 'top',
    marginBottom: 12,
  },
  recentsLabel: {
    color: TM.frost4, fontSize: 9, fontWeight: '700',
    letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8,
  },
  noteChip: {
    flexDirection: 'row', alignItems: 'flex-start', gap: 10,
    borderRadius: 12, padding: 10, marginBottom: 6, overflow: 'hidden',
    borderWidth: 1, borderColor: TM.line2,
  },
  noteText: { color: TM.frost2, fontSize: 12, lineHeight: 17 },
  noteTime: { color: TM.frost4, fontSize: 10, marginTop: 3 },
});
