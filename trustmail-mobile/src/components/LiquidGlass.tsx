/**
 * SafeMail X — Liquid Glass Shell
 * Shared glass card component matching the exact App.tsx TmCard recipe.
 * Import into assistive touch sheets to stay on-theme.
 */

import React from 'react';
import { View, StyleSheet, ViewStyle } from 'react-native';
import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';

export const TM = {
  bg:          '#010104',
  ink3:        '#151538',
  frost:       '#f2eafd',
  frost2:      '#d6cce8',
  frost3:      '#a39ab8',
  frost4:      '#83808c',
  violet:      '#3b41bf',
  violetSoft:  '#5a60d8',
  violetGlow:  '#8a8ff0',
  emerald:     '#6fd9b8',
  rose:        '#e08aae',
  gold:        '#e8a84c',
  cyan:        'rgba(0,240,255,1)',
  cyanBorder:  'rgba(0,240,255,0.16)',
  cyanDim:     'rgba(0,240,255,0.10)',
  line:        'rgba(242,234,253,0.05)',
  line2:       'rgba(242,234,253,0.12)',
};

interface GlassCardProps {
  children: React.ReactNode;
  style?: ViewStyle | ViewStyle[];
  gold?: boolean;
  /** Override border colour (e.g. accent for verdict cards) */
  accentBorder?: string;
  /** Override shadow colour */
  accentShadow?: string;
}

export function GlassCard({ children, style, gold, accentBorder, accentShadow }: GlassCardProps) {
  const borderColor = accentBorder ?? (gold ? 'rgba(232,168,76,0.28)' : TM.cyanBorder);
  const shadowColor = accentShadow ?? (gold ? '#e8a84c' : '#000');
  const shadowOpacity = accentShadow ? 0.45 : gold ? 0.35 : 0.8;

  return (
    <View
      style={[
        S.card,
        { borderColor, shadowColor, shadowOpacity },
        style,
      ]}
    >
      {/* Layer 1 — frosted blur */}
      <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />

      {/* Layer 2 — dark glass fill */}
      <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.38)' }]} />

      {/* Layer 3 — diagonal specular sheen */}
      <LinearGradient
        colors={[
          'rgba(255,255,255,0.08)',
          'rgba(255,255,255,0.01)',
          'rgba(255,255,255,0.00)',
          'rgba(255,255,255,0.03)',
        ]}
        start={{ x: 0.1, y: 0 }}
        end={{ x: 0.9, y: 1 }}
        style={StyleSheet.absoluteFillObject}
      />

      {/* Layer 4 — crystal top lip shimmer */}
      <View style={S.shimmer} />

      {children}
    </View>
  );
}

/** A thinner glass row/pill — used for inputs, result rows */
export function GlassRow({ children, style }: { children: React.ReactNode; style?: ViewStyle }) {
  return (
    <View style={[S.row, style]}>
      <BlurView intensity={18} tint="dark" style={StyleSheet.absoluteFillObject} />
      <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.25)' }]} />
      <View style={S.rowShimmer} />
      {children}
    </View>
  );
}

/** Violet primary button matching TmPrimaryBtn */
export function GlassPrimaryBtn({
  label, onPress, icon, color, textColor,
}: {
  label: string;
  onPress: () => void;
  icon?: string;
  color?: [string, string, string];
  textColor?: string;
}) {
  const { TouchableOpacity, Text } = require('react-native');
  const { Ionicons } = require('@expo/vector-icons');
  const grad: [string, string, string] = color ?? ['#5a60d8', '#3b41bf', '#151538'];
  return (
    <TouchableOpacity onPress={onPress} activeOpacity={0.82}>
      <LinearGradient
        colors={grad}
        start={{ x: 0.5, y: 0 }}
        end={{ x: 0.5, y: 1 }}
        style={S.primaryBtn}
      >
        {icon && <Ionicons name={icon} size={15} color={textColor ?? TM.frost} style={{ marginRight: 6 }} />}
        <Text style={[S.primaryBtnText, textColor ? { color: textColor } : undefined]}>{label}</Text>
      </LinearGradient>
    </TouchableOpacity>
  );
}

const S = StyleSheet.create({
  card: {
    borderRadius: 20,
    borderWidth: 1,
    padding: 16,
    overflow: 'hidden',
    shadowOffset: { width: 0, height: 16 },
    shadowRadius: 20,
    elevation: 8,
  },
  shimmer: {
    position: 'absolute', top: 0, left: 0, right: 0, height: 1.2,
    backgroundColor: 'rgba(255,255,255,0.35)',
  },
  row: {
    borderRadius: 14,
    borderWidth: 1,
    borderColor: TM.line2,
    overflow: 'hidden',
    padding: 12,
  },
  rowShimmer: {
    position: 'absolute', top: 0, left: 0, right: 0, height: 1,
    backgroundColor: 'rgba(255,255,255,0.18)',
  },
  primaryBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 14,
    paddingVertical: 13,
    borderWidth: 1,
    borderColor: 'rgba(242,234,253,0.22)',
    shadowColor: '#3b41bf',
    shadowOffset: { width: 0, height: 14 },
    shadowOpacity: 0.7,
    shadowRadius: 20,
    elevation: 8,
  },
  primaryBtnText: {
    color: '#f2eafd',
    fontWeight: '600',
    fontSize: 13,
    letterSpacing: 0.4,
  },
});
