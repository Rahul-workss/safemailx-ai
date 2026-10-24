/**
 * SafeMailX AI — Subscription & Upgrade Screen
 * Indigo Nocturne design system · Liquid Glass · Reanimated-free (uses core Animated API)
 *
 * States: PLAN_SELECT → PROCESSING → SUCCESS | ERROR
 * Payments: Razorpay web checkout on Android (expo-web-browser deep-link flow)
 *            Placeholder on iOS (Apple IAP to be wired separately)
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  Animated,
  Dimensions,
  Easing,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { C } from '../theme';
import { createSubscriptionOrder, verifySubscriptionPayment } from '../services/subscriptionService';
import * as Linking from 'expo-linking';
import * as WebBrowser from 'expo-web-browser';

const { width: SW } = Dimensions.get('window');

// ─── Plan data ────────────────────────────────────────────────────────────────
type PlanKey = 'free' | 'shield' | 'pro';

const PLANS: Record<PlanKey, {
  label: string;
  price: string;
  priceNote: string;
  description: string;
  features: string[];
  accentColor: string;
  glowColor: string;
  icon: string;
}> = {
  free: {
    label: 'Free',
    price: '₹0',
    priceNote: 'Always free',
    description: 'Basic protection to get started',
    features: [
      '5 scam scans per day',
      '3 UPI QR checks per day',
      '2 vishing call analyses per day',
      'Basic caller lookup',
      'Assistive Touch overlay',
    ],
    accentColor: C.frost4,
    glowColor: 'rgba(131,128,140,0.3)',
    icon: 'shield-outline',
  },
  shield: {
    label: 'Shield',
    price: '₹399',
    priceNote: '/ year · ≈ ₹33/month',
    description: 'Full protection for one device',
    features: [
      'Unlimited scam scans — SMS, email, links',
      'Unlimited vishing call analysis',
      'Full Assistive Touch toolkit',
      'Aadhaar & document deep verification',
      'One-tap DoT Chakshu reporting',
      'Complete scan history log',
      'Works offline for instant checks',
    ],
    accentColor: C.violetSoft,
    glowColor: 'rgba(90,96,216,0.35)',
    icon: 'shield-half-outline',
  },
  pro: {
    label: 'Shield Pro',
    price: '₹699',
    priceNote: '/ year · ≈ ₹58/month',
    description: '3 devices — protect your whole family',
    features: [
      'Everything in Shield Plan',
      'Up to 3 phones on one plan',
      'Weekly threat summary report',
      'Priority support',
      'Early access to new features',
    ],
    accentColor: C.gold,
    glowColor: 'rgba(232,168,76,0.35)',
    icon: 'shield-checkmark-outline',
  },
};

type ScreenState = 'PLAN_SELECT' | 'PROCESSING' | 'SUCCESS' | 'ERROR';

// ─── Props ────────────────────────────────────────────────────────────────────
interface SubscriptionScreenProps {
  onClose: () => void;
  /** Which plan the user currently has */
  currentPlan?: PlanKey;
}

// ─── Main Screen ──────────────────────────────────────────────────────────────
export default function SubscriptionScreen({ onClose, currentPlan = 'free' }: SubscriptionScreenProps) {
  const insets = useSafeAreaInsets();
  const [selectedPlan, setSelectedPlan] = useState<PlanKey>(currentPlan === 'free' ? 'shield' : currentPlan);
  const [screenState, setScreenState] = useState<ScreenState>('PLAN_SELECT');
  const [errorMsg, setErrorMsg] = useState('');

  // ── Entry animations ──────────────────────────────────────────────────────
  const overlayAnim   = useRef(new Animated.Value(0)).current;
  const headerAnim    = useRef(new Animated.Value(0)).current;
  const toggleAnim    = useRef(new Animated.Value(0)).current;
  const cardAnim      = useRef(new Animated.Value(0)).current;
  const btnAnim       = useRef(new Animated.Value(0)).current;

  // ── Card swap animation ───────────────────────────────────────────────────
  const cardSlideX = useRef(new Animated.Value(0)).current;
  const cardOpacity = useRef(new Animated.Value(1)).current;

  // ── Processing pulse ──────────────────────────────────────────────────────
  const pulsAnim = useRef(new Animated.Value(1)).current;
  const dotAnims = [
    useRef(new Animated.Value(0.3)).current,
    useRef(new Animated.Value(0.3)).current,
    useRef(new Animated.Value(0.3)).current,
  ];

  // ── Success ───────────────────────────────────────────────────────────────
  const shieldScale   = useRef(new Animated.Value(0)).current;
  const shieldGlow    = useRef(new Animated.Value(0)).current;
  const successText   = useRef(new Animated.Value(0)).current;
  const successBtn    = useRef(new Animated.Value(0)).current;
  const particles     = Array.from({ length: 8 }, () => ({
    x: useRef(new Animated.Value(0)).current,
    y: useRef(new Animated.Value(0)).current,
    op: useRef(new Animated.Value(0)).current,
  }));

  // ── Entry animation sequence ──────────────────────────────────────────────
  useEffect(() => {
    Animated.stagger(70, [
      Animated.timing(overlayAnim, { toValue: 1, duration: 280, easing: Easing.out(Easing.ease), useNativeDriver: true }),
      Animated.spring(headerAnim,  { toValue: 1, damping: 20, stiffness: 180, useNativeDriver: true }),
      Animated.spring(toggleAnim,  { toValue: 1, damping: 18, stiffness: 160, useNativeDriver: true }),
      Animated.spring(cardAnim,    { toValue: 1, damping: 15, stiffness: 140, useNativeDriver: true }),
      Animated.timing(btnAnim,     { toValue: 1, duration: 220, easing: Easing.out(Easing.ease), useNativeDriver: true }),
    ]).start();
  }, []);

  // ── Processing animations ─────────────────────────────────────────────────
  useEffect(() => {
    if (screenState !== 'PROCESSING') return;
    const pulseLoop = Animated.loop(
      Animated.sequence([
        Animated.timing(pulsAnim, { toValue: 1.12, duration: 800, easing: Easing.inOut(Easing.ease), useNativeDriver: true }),
        Animated.timing(pulsAnim, { toValue: 1.0,  duration: 800, easing: Easing.inOut(Easing.ease), useNativeDriver: true }),
      ])
    );
    const dotLoop = Animated.loop(
      Animated.stagger(220, dotAnims.map(d =>
        Animated.sequence([
          Animated.timing(d, { toValue: 1,   duration: 350, useNativeDriver: true }),
          Animated.timing(d, { toValue: 0.3, duration: 350, useNativeDriver: true }),
        ])
      ))
    );
    pulseLoop.start();
    dotLoop.start();
    return () => { pulseLoop.stop(); dotLoop.stop(); };
  }, [screenState]);

  // ── Success animations ────────────────────────────────────────────────────
  useEffect(() => {
    if (screenState !== 'SUCCESS') return;

    // Particle burst
    const angles = [0, 45, 90, 135, 180, 225, 270, 315];
    const particleAnims = particles.map((p, i) => {
      const angle = (angles[i] * Math.PI) / 180;
      const dist = 55 + Math.random() * 25;
      return Animated.parallel([
        Animated.timing(p.x, { toValue: Math.cos(angle) * dist, duration: 600, easing: Easing.out(Easing.cubic), useNativeDriver: true }),
        Animated.timing(p.y, { toValue: Math.sin(angle) * dist, duration: 600, easing: Easing.out(Easing.cubic), useNativeDriver: true }),
        Animated.sequence([
          Animated.timing(p.op, { toValue: 1, duration: 200, useNativeDriver: true }),
          Animated.timing(p.op, { toValue: 0, duration: 400, delay: 100, useNativeDriver: true }),
        ]),
      ]);
    });

    Animated.sequence([
      // 1. Particle burst
      Animated.parallel(particleAnims),
      // 2. Shield bounces in (overshoot)
      Animated.spring(shieldScale, { toValue: 1.2, damping: 5, stiffness: 300, useNativeDriver: true }),
    ]).start(() => {
      // 3. Settle
      Animated.spring(shieldScale, { toValue: 1, damping: 12, useNativeDriver: true }).start();
    });

    // Glow + text + button staggered
    Animated.stagger(180, [
      Animated.timing(shieldGlow,  { toValue: 1, duration: 500, useNativeDriver: false }),
      Animated.timing(successText, { toValue: 1, duration: 320, easing: Easing.out(Easing.ease), useNativeDriver: true }),
      Animated.spring(successBtn,  { toValue: 1, damping: 16, stiffness: 150, useNativeDriver: true }),
    ]).start();
  }, [screenState]);

  // ── Plan card swap ────────────────────────────────────────────────────────
  function handleSelectPlan(plan: PlanKey) {
    if (plan === selectedPlan) return;
    const goingRight = ['free', 'shield', 'pro'].indexOf(plan) > ['free', 'shield', 'pro'].indexOf(selectedPlan);
    const exitDir = goingRight ? -SW * 0.6 : SW * 0.6;
    const enterDir = goingRight ? SW * 0.6 : -SW * 0.6;

    Animated.parallel([
      Animated.timing(cardSlideX, { toValue: exitDir, duration: 180, easing: Easing.in(Easing.ease), useNativeDriver: true }),
      Animated.timing(cardOpacity, { toValue: 0, duration: 150, useNativeDriver: true }),
    ]).start(() => {
      setSelectedPlan(plan);
      cardSlideX.setValue(enterDir);
      Animated.parallel([
        Animated.spring(cardSlideX,  { toValue: 0, damping: 20, stiffness: 200, useNativeDriver: true }),
        Animated.timing(cardOpacity, { toValue: 1, duration: 180, useNativeDriver: true }),
      ]).start();
    });
  }

  // ── Payment flow ──────────────────────────────────────────────────────────
  async function handleSubscribe() {
    if (selectedPlan === 'free') { onClose(); return; }
    setScreenState('PROCESSING');

    try {
      if (Platform.OS === 'ios') {
        // iOS: Apple In-App Purchase — placeholder until StoreKit is wired
        setTimeout(() => {
          setErrorMsg('iOS in-app purchase coming soon. Use Android for now.');
          setScreenState('ERROR');
        }, 1500);
        return;
      }

      // Android: Razorpay web checkout
      const order = await createSubscriptionOrder(selectedPlan);
      const checkoutUrl = order.checkout_url;

      // Open Razorpay hosted checkout
      const result = await WebBrowser.openAuthSessionAsync(
        checkoutUrl,
        'safemailx://payment-callback'
      );

      if (result.type === 'success' && result.url) {
        const parsed = Linking.parse(result.url);
        const paymentId = parsed.queryParams?.razorpay_payment_id as string | undefined;
        const signature = parsed.queryParams?.razorpay_signature as string | undefined;

        if (paymentId && signature) {
          const verified = await verifySubscriptionPayment(order.order_id, paymentId, signature);
          if (verified) {
            setScreenState('SUCCESS');
            return;
          }
        }
        setErrorMsg('Payment verification failed. Contact support if amount was deducted.');
        setScreenState('ERROR');
      } else {
        // User cancelled or dismissed
        setScreenState('PLAN_SELECT');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Something went wrong. Please try again.');
      setScreenState('ERROR');
    }
  }

  const plan = PLANS[selectedPlan];

  // ─────────────────────────────────────────────────────────────────────────
  if (screenState === 'PROCESSING') return <ProcessingState pulsAnim={pulsAnim} dotAnims={dotAnims} />;
  if (screenState === 'SUCCESS')    return <SuccessState plan={plan} shieldScale={shieldScale} shieldGlow={shieldGlow} successText={successText} successBtn={successBtn} particles={particles} onClose={onClose} />;
  if (screenState === 'ERROR')      return <ErrorState message={errorMsg} onRetry={() => setScreenState('PLAN_SELECT')} onClose={onClose} />;

  // ─── PLAN_SELECT ──────────────────────────────────────────────────────────
  return (
    <View style={[styles.root, { paddingTop: insets.top }]}>
      <TmBgOverlay opacity={overlayAnim} />

      <ScrollView
        contentContainerStyle={styles.scroll}
        showsVerticalScrollIndicator={false}
        bounces={false}
      >
        {/* ── Header ── */}
        <Animated.View style={[styles.headerRow, {
          opacity: headerAnim,
          transform: [{ translateY: headerAnim.interpolate({ inputRange: [0, 1], outputRange: [-16, 0] }) }],
        }]}>
          <View style={styles.headerSpacer} />
          <Text style={styles.eyebrow}>UPGRADE YOUR SHIELD</Text>
          <TouchableOpacity onPress={onClose} style={styles.closeBtn} hitSlop={{ top: 12, right: 12, bottom: 12, left: 12 }}>
            <Ionicons name="close" size={20} color={C.frost3} />
          </TouchableOpacity>
        </Animated.View>

        {/* ── Title ── */}
        <Animated.Text style={[styles.title, {
          opacity: headerAnim,
          transform: [{ translateY: headerAnim.interpolate({ inputRange: [0, 1], outputRange: [10, 0] }) }],
        }]}>
          Full Protection,{'\n'}Zero Compromise
        </Animated.Text>

        {/* ── Plan Toggle ── */}
        <Animated.View style={[{
          opacity: toggleAnim,
          transform: [{ translateY: toggleAnim.interpolate({ inputRange: [0, 1], outputRange: [24, 0] }) }],
        }]}>
          <PlanToggle selected={selectedPlan} onSelect={handleSelectPlan} currentPlan={currentPlan} />
        </Animated.View>

        {/* ── Plan Card ── */}
        <Animated.View style={{
          opacity: Animated.multiply(cardAnim, cardOpacity),
          transform: [
            { translateY: cardAnim.interpolate({ inputRange: [0, 1], outputRange: [40, 0] }) },
            { translateX: cardSlideX },
          ],
        }}>
          <PlanCard plan={plan} planKey={selectedPlan} />
        </Animated.View>

        {/* ── Spacer ── */}
        <View style={{ height: 24 }} />

        {/* ── CTA Button ── */}
        <Animated.View style={{
          opacity: btnAnim,
          transform: [{ translateY: btnAnim.interpolate({ inputRange: [0, 1], outputRange: [16, 0] }) }],
        }}>
          <SubscribeButton plan={plan} planKey={selectedPlan} onPress={handleSubscribe} />
          <Text style={styles.trustLine}>
            🔒  Secure payment · No ads · Cancel anytime
          </Text>
          {selectedPlan !== 'free' && (
            <Text style={styles.trustSub}>
              Android: Pay via UPI, card, or net banking via Razorpay
            </Text>
          )}
        </Animated.View>

        <View style={{ height: 32 }} />
      </ScrollView>
    </View>
  );
}

// ─── Background overlay ───────────────────────────────────────────────────────
function TmBgOverlay({ opacity }: { opacity: Animated.Value }) {
  return (
    <Animated.View style={[StyleSheet.absoluteFill, { opacity }]} pointerEvents="none">
      <View style={[StyleSheet.absoluteFill, { backgroundColor: C.bg }]} />
      <LinearGradient
        colors={['rgba(59,65,191,0.18)', 'transparent', 'rgba(59,65,191,0.08)']}
        start={{ x: 0.5, y: 0 }} end={{ x: 0.5, y: 1 }}
        style={StyleSheet.absoluteFill}
      />
    </Animated.View>
  );
}

// ─── Plan toggle pill row ─────────────────────────────────────────────────────
function PlanToggle({ selected, onSelect, currentPlan }: {
  selected: PlanKey;
  onSelect: (p: PlanKey) => void;
  currentPlan: PlanKey;
}) {
  const plans: PlanKey[] = ['free', 'shield', 'pro'];
  return (
    <View style={toggle.container}>
      <BlurView intensity={20} tint="dark" style={StyleSheet.absoluteFillObject} />
      <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.30)' }]} />
      <View style={toggle.inner}>
        {plans.map(p => (
          <PlanPill
            key={p}
            planKey={p}
            selected={selected === p}
            isCurrent={currentPlan === p}
            label={PLANS[p].label}
            accentColor={PLANS[p].accentColor}
            onPress={() => onSelect(p)}
          />
        ))}
      </View>
    </View>
  );
}

function PlanPill({ planKey, selected, isCurrent, label, accentColor, onPress }: {
  planKey: PlanKey; selected: boolean; isCurrent: boolean;
  label: string; accentColor: string; onPress: () => void;
}) {
  const scaleAnim = useRef(new Animated.Value(selected ? 1.04 : 1)).current;
  const glowAnim  = useRef(new Animated.Value(selected ? 1 : 0)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.spring(scaleAnim, { toValue: selected ? 1.04 : 1, damping: 16, useNativeDriver: true }),
      Animated.timing(glowAnim,  { toValue: selected ? 1 : 0, duration: 200, useNativeDriver: false }),
    ]).start();
  }, [selected]);

  const bgColor = glowAnim.interpolate({ inputRange: [0, 1], outputRange: ['rgba(255,255,255,0.0)', `${accentColor}22`] });
  const borderColor = glowAnim.interpolate({ inputRange: [0, 1], outputRange: ['rgba(255,255,255,0.0)', accentColor] });

  return (
    <TouchableOpacity onPress={onPress} activeOpacity={0.75} style={{ flex: 1 }}>
      <Animated.View style={{ transform: [{ scale: scaleAnim }] }}>
        {selected ? (
          <LinearGradient
            colors={planKey === 'pro'
              ? ['rgba(232,168,76,0.30)', 'rgba(232,168,76,0.12)']
              : ['rgba(90,96,216,0.38)', 'rgba(59,65,191,0.20)']}
            start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
            style={[toggle.pill, { borderColor: accentColor, borderWidth: 1.5 }]}
          >
            <Text style={[toggle.pillText, { color: accentColor, fontWeight: '700' }]}>{label}</Text>
            {isCurrent && <View style={[toggle.currentDot, { backgroundColor: accentColor }]} />}
          </LinearGradient>
        ) : (
          <Animated.View style={[toggle.pill, { backgroundColor: bgColor, borderColor, borderWidth: 1 }]}>
            <Text style={[toggle.pillText, { color: C.frost4 }]}>{label}</Text>
            {isCurrent && <View style={[toggle.currentDot, { backgroundColor: C.frost4 }]} />}
          </Animated.View>
        )}
      </Animated.View>
    </TouchableOpacity>
  );
}

const toggle = StyleSheet.create({
  container: {
    borderRadius: 18,
    borderWidth: 1,
    borderColor: 'rgba(242,234,253,0.08)',
    overflow: 'hidden',
    marginBottom: 20,
    marginHorizontal: 0,
  },
  inner: {
    flexDirection: 'row',
    padding: 6,
    gap: 6,
  },
  pill: {
    flex: 1,
    paddingVertical: 10,
    paddingHorizontal: 8,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 42,
  },
  pillText: {
    fontSize: 13,
    fontWeight: '600',
    letterSpacing: 0.2,
    textAlign: 'center',
  },
  currentDot: {
    width: 4,
    height: 4,
    borderRadius: 2,
    marginTop: 3,
  },
});

// ─── Plan card ────────────────────────────────────────────────────────────────
function PlanCard({ plan, planKey }: { plan: typeof PLANS[PlanKey]; planKey: PlanKey }) {
  // Stagger feature rows
  const featureAnims = plan.features.map(() => useRef(new Animated.Value(0)).current);
  useEffect(() => {
    const anims = featureAnims.map(a => {
      a.setValue(0);
      return Animated.timing(a, { toValue: 1, duration: 260, easing: Easing.out(Easing.ease), useNativeDriver: true });
    });
    Animated.stagger(45, anims).start();
  }, [planKey]);

  const isUpgrade = planKey !== 'free';

  return (
    <View style={[card.container, {
      borderColor: isUpgrade ? `${plan.accentColor}45` : 'rgba(242,234,253,0.08)',
      shadowColor: isUpgrade ? plan.accentColor : '#000',
      shadowOpacity: isUpgrade ? 0.35 : 0.5,
    }]}>
      {/* Frosted blur */}
      <BlurView intensity={28} tint="dark" style={StyleSheet.absoluteFillObject} />

      {/* Dark glass fill */}
      <View style={[StyleSheet.absoluteFillObject, { backgroundColor: 'rgba(0,0,0,0.38)' }]} />

      {/* Diagonal specular sheen */}
      <LinearGradient
        colors={['rgba(255,255,255,0.09)', 'rgba(255,255,255,0.01)', 'rgba(255,255,255,0.0)', 'rgba(255,255,255,0.03)']}
        start={{ x: 0.1, y: 0 }} end={{ x: 0.9, y: 1 }}
        style={StyleSheet.absoluteFillObject}
      />

      {/* Crystal top lip shimmer */}
      <View style={card.shimmer} />

      {/* Accent top strip for paid plans */}
      {isUpgrade && (
        <LinearGradient
          colors={[plan.accentColor, 'transparent']}
          start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }}
          style={card.accentStrip}
        />
      )}

      {/* Content */}
      <View style={card.content}>
        {/* Icon + plan name row */}
        <View style={card.titleRow}>
          <View style={[card.iconWrap, { backgroundColor: `${plan.accentColor}18`, borderColor: `${plan.accentColor}30` }]}>
            <Ionicons name={plan.icon as any} size={22} color={plan.accentColor} />
          </View>
          <View style={{ flex: 1 }}>
            <Text style={[card.planName, { color: plan.accentColor }]}>{plan.label}</Text>
            <Text style={card.planDesc}>{plan.description}</Text>
          </View>
          {planKey === 'pro' && (
            <View style={card.bestValueBadge}>
              <Text style={card.bestValueText}>BEST VALUE</Text>
            </View>
          )}
        </View>

        {/* Price */}
        <View style={card.priceRow}>
          <Text style={[card.price, { color: isUpgrade ? C.frost : C.frost3 }]}>{plan.price}</Text>
          <Text style={card.priceNote}>{plan.priceNote}</Text>
        </View>

        {/* Divider */}
        <LinearGradient
          colors={['transparent', `${plan.accentColor}35`, 'transparent']}
          start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }}
          style={card.divider}
        />

        {/* Feature list */}
        {plan.features.map((feature, i) => (
          <Animated.View
            key={feature}
            style={[card.featureRow, {
              opacity: featureAnims[i],
              transform: [{ translateX: featureAnims[i].interpolate({ inputRange: [0, 1], outputRange: [-14, 0] }) }],
            }]}
          >
            <Ionicons
              name={planKey === 'free' ? 'remove-outline' : 'checkmark-circle'}
              size={16}
              color={planKey === 'free' ? C.frost4 : C.emerald}
              style={{ marginTop: 1 }}
            />
            <Text style={[card.featureText, planKey === 'free' && { color: C.frost4 }]}>{feature}</Text>
          </Animated.View>
        ))}
      </View>
    </View>
  );
}

const card = StyleSheet.create({
  container: {
    borderRadius: 22,
    borderWidth: 1,
    overflow: 'hidden',
    shadowOffset: { width: 0, height: 18 },
    shadowRadius: 24,
    elevation: 10,
  },
  shimmer: {
    position: 'absolute', top: 0, left: 0, right: 0, height: 1.2,
    backgroundColor: 'rgba(255,255,255,0.32)',
  },
  accentStrip: {
    position: 'absolute', top: 0, left: 0, right: 0, height: 2,
  },
  content: {
    padding: 20,
    paddingTop: 22,
    gap: 0,
  },
  titleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 18,
  },
  iconWrap: {
    width: 44, height: 44,
    borderRadius: 14,
    borderWidth: 1,
    alignItems: 'center', justifyContent: 'center',
  },
  planName: {
    fontSize: 18,
    fontWeight: '700',
    letterSpacing: 0.3,
  },
  planDesc: {
    fontSize: 11,
    color: C.frost4,
    marginTop: 2,
  },
  bestValueBadge: {
    backgroundColor: 'rgba(232,168,76,0.18)',
    borderWidth: 1,
    borderColor: 'rgba(232,168,76,0.35)',
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 4,
  },
  bestValueText: {
    fontSize: 9,
    fontWeight: '800',
    color: C.gold,
    letterSpacing: 0.8,
  },
  priceRow: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: 6,
    marginBottom: 16,
  },
  price: {
    fontSize: 34,
    fontWeight: '700',
    letterSpacing: -0.5,
  },
  priceNote: {
    fontSize: 13,
    color: C.frost4,
    fontWeight: '400',
  },
  divider: {
    height: 1,
    marginBottom: 16,
  },
  featureRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 10,
    paddingVertical: 6,
  },
  featureText: {
    flex: 1,
    fontSize: 14,
    color: C.frost2,
    lineHeight: 20,
    fontWeight: '400',
  },
});

// ─── Subscribe button ─────────────────────────────────────────────────────────
function SubscribeButton({ plan, planKey, onPress }: {
  plan: typeof PLANS[PlanKey]; planKey: PlanKey; onPress: () => void;
}) {
  const scaleAnim = useRef(new Animated.Value(1)).current;
  const pi = () => Animated.spring(scaleAnim, { toValue: 0.97, useNativeDriver: true }).start();
  const po = () => Animated.spring(scaleAnim, { toValue: 1,    useNativeDriver: true }).start();

  const label = planKey === 'free'
    ? 'Continue with Free'
    : `Subscribe · ${plan.price}/year`;

  const gradColors: [string, string, string] = planKey === 'pro'
    ? ['#e8a84c', '#b07830', '#2c2e6e']
    : ['#5a60d8', '#3b41bf', '#151538'];

  return (
    <Pressable onPressIn={pi} onPressOut={po} onPress={onPress}>
      <Animated.View style={{ transform: [{ scale: scaleAnim }] }}>
        <LinearGradient
          colors={gradColors}
          start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
          style={btn.gradient}
        >
          <Ionicons
            name={planKey === 'free' ? 'arrow-forward' : 'shield-checkmark'}
            size={17}
            color={C.frost}
            style={{ marginRight: 8 }}
          />
          <Text style={btn.label}>{label}</Text>
        </LinearGradient>
      </Animated.View>
    </Pressable>
  );
}

const btn = StyleSheet.create({
  gradient: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 16,
    paddingVertical: 16,
    borderWidth: 1,
    borderColor: 'rgba(242,234,253,0.18)',
    shadowColor: '#3b41bf',
    shadowOffset: { width: 0, height: 14 },
    shadowOpacity: 0.55,
    shadowRadius: 22,
    elevation: 10,
  },
  label: {
    color: C.frost,
    fontSize: 15,
    fontWeight: '700',
    letterSpacing: 0.3,
  },
});

// ─── Processing state ─────────────────────────────────────────────────────────
function ProcessingState({ pulsAnim, dotAnims }: {
  pulsAnim: Animated.Value;
  dotAnims: Animated.Value[];
}) {
  const insets = useSafeAreaInsets();
  return (
    <View style={[styles.root, styles.centeredState, { paddingTop: insets.top }]}>
      <LinearGradient
        colors={['rgba(59,65,191,0.15)', 'transparent']}
        start={{ x: 0.5, y: 0 }} end={{ x: 0.5, y: 1 }}
        style={StyleSheet.absoluteFill}
      />
      <Animated.View style={[proc.logoWrap, { transform: [{ scale: pulsAnim }] }]}>
        <Ionicons name="shield-half-outline" size={52} color={C.violetGlow} />
        <View style={proc.logoGlow} />
      </Animated.View>
      <Text style={proc.title}>Completing your subscription…</Text>
      <View style={proc.dots}>
        {dotAnims.map((d, i) => (
          <Animated.View key={i} style={[proc.dot, { opacity: d }]} />
        ))}
      </View>
      <Text style={proc.sub}>Please wait — do not close the app</Text>
    </View>
  );
}

const proc = StyleSheet.create({
  logoWrap: { alignItems: 'center', justifyContent: 'center', marginBottom: 28 },
  logoGlow: {
    position: 'absolute', width: 100, height: 100, borderRadius: 50,
    backgroundColor: 'rgba(90,96,216,0.25)',
  },
  title: { color: C.frost, fontSize: 18, fontWeight: '600', textAlign: 'center', marginBottom: 20 },
  dots: { flexDirection: 'row', gap: 8, marginBottom: 16 },
  dot: {
    width: 8, height: 8, borderRadius: 4,
    backgroundColor: C.violetGlow,
  },
  sub: { color: C.frost4, fontSize: 12, textAlign: 'center' },
});

// ─── Success state ────────────────────────────────────────────────────────────
function SuccessState({ plan, shieldScale, shieldGlow, successText, successBtn, particles, onClose }: {
  plan: typeof PLANS[PlanKey];
  shieldScale: Animated.Value;
  shieldGlow: Animated.Value;
  successText: Animated.Value;
  successBtn: Animated.Value;
  particles: { x: Animated.Value; y: Animated.Value; op: Animated.Value }[];
  onClose: () => void;
}) {
  const insets = useSafeAreaInsets();
  const glowRadius = shieldGlow.interpolate({ inputRange: [0, 1], outputRange: [0, 60] });

  return (
    <View style={[styles.root, styles.centeredState, { paddingTop: insets.top }]}>
      <LinearGradient
        colors={['rgba(111,217,184,0.12)', 'transparent']}
        start={{ x: 0.5, y: 0 }} end={{ x: 0.5, y: 1 }}
        style={StyleSheet.absoluteFill}
      />

      {/* Particle layer */}
      <View style={success.particleOrigin} pointerEvents="none">
        {particles.map((p, i) => (
          <Animated.View
            key={i}
            style={[success.particle, {
              opacity: p.op,
              transform: [{ translateX: p.x }, { translateY: p.y }],
              backgroundColor: i % 2 === 0 ? C.emerald : C.violetGlow,
            }]}
          />
        ))}
      </View>

      {/* Shield icon */}
      <View style={{ alignItems: 'center', justifyContent: 'center', marginBottom: 24 }}>
        <Animated.View style={[success.glowRing, { width: glowRadius, height: glowRadius, borderRadius: 60 }]} />
        <Animated.View style={{ transform: [{ scale: shieldScale }] }}>
          <View style={success.shieldWrap}>
            <Ionicons name="shield-checkmark" size={56} color={C.emerald} />
          </View>
        </Animated.View>
      </View>

      {/* Text */}
      <Animated.View style={{ opacity: successText, transform: [{ translateY: successText.interpolate({ inputRange: [0, 1], outputRange: [12, 0] }) }] }}>
        <Text style={success.title}>{plan.label} Activated</Text>
        <Text style={success.sub}>Your device is now fully protected.{'\n'}Stay safe out there.</Text>
      </Animated.View>

      {/* CTA */}
      <Animated.View style={[success.btnWrap, {
        opacity: successBtn,
        transform: [{ translateY: successBtn.interpolate({ inputRange: [0, 1], outputRange: [20, 0] }) }],
      }]}>
        <Pressable onPress={onClose}>
          <LinearGradient
            colors={['#6fd9b8', '#3a9e7f', '#1a4d3f']}
            start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
            style={btn.gradient}
          >
            <Ionicons name="checkmark-circle" size={18} color="#fff" style={{ marginRight: 8 }} />
            <Text style={btn.label}>Continue</Text>
          </LinearGradient>
        </Pressable>
      </Animated.View>
    </View>
  );
}

const success = StyleSheet.create({
  particleOrigin: {
    position: 'absolute',
    top: '38%',
    left: '50%',
    alignItems: 'center',
    justifyContent: 'center',
  },
  particle: {
    position: 'absolute',
    width: 7, height: 7, borderRadius: 4,
  },
  glowRing: {
    position: 'absolute',
    backgroundColor: 'rgba(111,217,184,0.20)',
  },
  shieldWrap: {
    width: 100, height: 100, borderRadius: 50,
    backgroundColor: 'rgba(111,217,184,0.12)',
    borderWidth: 1,
    borderColor: 'rgba(111,217,184,0.30)',
    alignItems: 'center', justifyContent: 'center',
    shadowColor: C.emerald,
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.6,
    shadowRadius: 24,
    elevation: 10,
  },
  title: {
    color: C.frost,
    fontSize: 26,
    fontWeight: '700',
    textAlign: 'center',
    marginBottom: 10,
    letterSpacing: 0.2,
  },
  sub: {
    color: C.frost3,
    fontSize: 14,
    textAlign: 'center',
    lineHeight: 22,
  },
  btnWrap: {
    marginTop: 36,
    width: SW - 64,
  },
});

// ─── Error state ──────────────────────────────────────────────────────────────
function ErrorState({ message, onRetry, onClose }: {
  message: string; onRetry: () => void; onClose: () => void;
}) {
  const insets = useSafeAreaInsets();
  const shakeAnim = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.sequence([
      Animated.timing(shakeAnim, { toValue: 8,  duration: 70, useNativeDriver: true }),
      Animated.timing(shakeAnim, { toValue: -8, duration: 70, useNativeDriver: true }),
      Animated.timing(shakeAnim, { toValue: 6,  duration: 60, useNativeDriver: true }),
      Animated.timing(shakeAnim, { toValue: -6, duration: 60, useNativeDriver: true }),
      Animated.timing(shakeAnim, { toValue: 0,  duration: 50, useNativeDriver: true }),
    ]).start();
  }, []);

  return (
    <View style={[styles.root, styles.centeredState, { paddingTop: insets.top, paddingHorizontal: 32 }]}>
      <LinearGradient
        colors={['rgba(224,138,174,0.10)', 'transparent']}
        start={{ x: 0.5, y: 0 }} end={{ x: 0.5, y: 1 }}
        style={StyleSheet.absoluteFill}
      />
      <Animated.View style={[err.iconWrap, { transform: [{ translateX: shakeAnim }] }]}>
        <Ionicons name="alert-circle" size={52} color={C.rose} />
      </Animated.View>
      <Text style={err.title}>Payment Failed</Text>
      <Text style={err.message}>{message}</Text>
      <View style={err.actions}>
        <Pressable onPress={onRetry} style={err.retryBtn}>
          <LinearGradient colors={['#5a60d8', '#3b41bf', '#151538']} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={err.retryGrad}>
            <Text style={err.retryText}>Try Again</Text>
          </LinearGradient>
        </Pressable>
        <Pressable onPress={onClose} style={err.cancelBtn}>
          <Text style={err.cancelText}>Go Back</Text>
        </Pressable>
      </View>
    </View>
  );
}

const err = StyleSheet.create({
  iconWrap: { alignItems: 'center', marginBottom: 20 },
  title: { color: C.rose, fontSize: 22, fontWeight: '700', textAlign: 'center', marginBottom: 10 },
  message: { color: C.frost3, fontSize: 14, textAlign: 'center', lineHeight: 22, marginBottom: 32 },
  actions: { width: '100%', gap: 12 },
  retryBtn: { width: '100%' },
  retryGrad: {
    borderRadius: 14, paddingVertical: 15, alignItems: 'center',
    borderWidth: 1, borderColor: 'rgba(242,234,253,0.16)',
  },
  retryText: { color: C.frost, fontSize: 15, fontWeight: '700' },
  cancelBtn: {
    alignItems: 'center', paddingVertical: 12,
    borderWidth: 1, borderColor: 'rgba(242,234,253,0.10)', borderRadius: 14,
  },
  cancelText: { color: C.frost4, fontSize: 14, fontWeight: '500' },
});

// ─── Root stylesheet ──────────────────────────────────────────────────────────
const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: C.bg,
  },
  centeredState: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  scroll: {
    paddingHorizontal: 20,
    paddingTop: 12,
    paddingBottom: 40,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 6,
  },
  headerSpacer: {
    width: 32,
  },
  eyebrow: {
    color: C.frost4,
    fontSize: 10,
    fontWeight: '600',
    letterSpacing: 2.5,
    textAlign: 'center',
    flex: 1,
  },
  closeBtn: {
    width: 32, height: 32,
    alignItems: 'center', justifyContent: 'center',
    borderRadius: 16,
    backgroundColor: 'rgba(255,255,255,0.06)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.10)',
  },
  title: {
    color: C.frost,
    fontSize: 28,
    fontWeight: '700',
    letterSpacing: -0.3,
    textAlign: 'center',
    marginBottom: 24,
    lineHeight: 36,
  },
  trustLine: {
    color: C.frost4,
    fontSize: 12,
    textAlign: 'center',
    marginTop: 14,
    letterSpacing: 0.2,
  },
  trustSub: {
    color: C.frost4,
    fontSize: 10,
    textAlign: 'center',
    marginTop: 6,
    opacity: 0.7,
  },
});
