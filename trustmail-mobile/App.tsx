/**
 * SafeMail X Mobile — Indigo Nocturne UI
 * Pixel-perfect React Native port of the Lovable luxury-app-glow design.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Animated,
  Pressable,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
  RefreshControl,
  Dimensions,
  Image,
  ActivityIndicator,
  Switch,
  Alert,
  KeyboardAvoidingView,
} from "react-native";
import * as Linking from "expo-linking";
import { SafeAreaProvider, useSafeAreaInsets } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import { LinearGradient } from "expo-linear-gradient";
import { BlurView } from "expo-blur";
import { Ionicons } from "@expo/vector-icons";
import * as DocumentPicker from "expo-document-picker";
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Video, ResizeMode, AVPlaybackStatus } from "expo-av";
import { 
  useFonts, 
  CormorantGaramond_300Light, 
  CormorantGaramond_600SemiBold,
  CormorantGaramond_300Light_Italic
} from '@expo-google-fonts/cormorant-garamond';
import {
  DMSans_300Light,
  DMSans_400Regular,
  DMSans_500Medium
} from '@expo-google-fonts/dm-sans';
import MaskedView from '@react-native-masked-view/masked-view';
import Svg, { Path, Defs, LinearGradient as SvgLinearGradient, Stop, Line, Circle, Rect } from 'react-native-svg';
import {
  confirmPasswordReset, createManualScan, fetchGmailOAuthStatus,
  fetchHealth, fetchScans, getApiBaseUrl, getReportDownloadUrl,
  Health, login, registerPushToken, requestPasswordReset,
  ScanSummary, setApiBaseUrl, startGmailOAuth, uploadScanFile,
  fetchGoogleBackupStatus, startGoogleBackupOAuth, disconnectGoogleBackup,
  setAccessToken, fetchThreatBulletin, register, sendRegistrationOtp, scanSms,
  uploadScreenshot, scanUrl, fetchNotificationPreferences,
  saveNotificationPreferences, NotificationPreferences,
  InstantScanResult, scanInstantFile, submitScanFeedback,
  UnauthorizedError, NetworkError, exchangeOAuthCode, logoutSession
} from "./src/api";
import {
  saveSession, loadSession, clearSession,
  registerSessionExpiredHandler,
} from "./src/session";
import { C, colors, verdictColor } from "./src/theme";
const { width: SW } = Dimensions.get("window");

type Tab = "dashboard" | "scans" | "new" | "reports" | "settings" | "privacy" | "help";

// ─── Error Boundary ───────────────────────────────────────────────────────────
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; errorMsg: string }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, errorMsg: "" };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, errorMsg: error.message };
  }
  render() {
    if (this.state.hasError) {
      return (
        <View style={[S.root, { justifyContent: "center", alignItems: "center", padding: 24 }]}>
          <TmBg />
          <Ionicons name="warning" size={44} color={C.rose} />
          <Text style={[S.frost, { fontSize: 18, fontWeight: "800", marginTop: 14 }]}>App Error</Text>
          <Text style={[S.muted, { textAlign: "center", marginTop: 6 }]}>{this.state.errorMsg}</Text>
          <TmPrimaryBtn label="Try Again" onPress={() => this.setState({ hasError: false })} />
        </View>
      );
    }
    return this.props.children;
  }
}

export default function AppWrapper() {
  const [fontsLoaded, fontError] = useFonts({
    CormorantGaramond_300Light,
    CormorantGaramond_600SemiBold,
    CormorantGaramond_300Light_Italic,
    DMSans_300Light,
    DMSans_400Regular,
    DMSans_500Medium
  });

  // Fallback: proceed without custom fonts after 5s so the app doesn't hang
  const [fontTimeout, setFontTimeout] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setFontTimeout(true), 5000);
    return () => clearTimeout(timer);
  }, []);

  const ready = fontsLoaded || fontError != null || fontTimeout;

  if (!ready) {
    // Show a branded loading screen instead of returning null
    // (returning null causes Expo Go's default white spinner)
    return (
      <View style={{ flex: 1, backgroundColor: "#010104", alignItems: "center", justifyContent: "center" }}>
        <Image
          source={require('./assets/new-logo.png')}
          style={{ width: 90, height: 90, resizeMode: "contain", marginBottom: 24, opacity: 0.7 }}
        />
        <ActivityIndicator size="small" color="#8a8ff0" />
        <Text style={{ color: "rgba(242,234,253,0.4)", fontSize: 11, marginTop: 14, letterSpacing: 2, textTransform: "uppercase" }}>Loading</Text>
      </View>
    );
  }

  return (
    <SafeAreaProvider>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </SafeAreaProvider>
  );
}

// ─── Background — simple black background with shield logo ───────────────────
function TmBg() {
  return (
    <View style={StyleSheet.absoluteFill} pointerEvents="none">
      {/* Base Black Background */}
      <View style={[StyleSheet.absoluteFill, { backgroundColor: "#000000" }]} />
      
      {/* Centered Logo Background */}
      <View style={{
        ...StyleSheet.absoluteFillObject,
        justifyContent: "center",
        alignItems: "center",
      }}>
        <Image
          source={require('./assets/new-logo.png')}
          style={{
            width: SW * 0.85,
            height: SW * 0.85,
            resizeMode: "contain",
            opacity: 0.18,
          }}
        />
      </View>
    </View>
  );
}

// ─── Dot grid overlay (like .tm-grid) ─────────────────────────────────────────
// RN can't do CSS background-image grids, so we skip but keep the bg glow.

// ─── tm-card (glass card) ─────────────────────────────────────────────────────
function TmCard({ children, style, gold }: { children: React.ReactNode; style?: any; gold?: boolean }) {
  return (
    <View style={[S.tmCard, gold && S.tmCardGold, style]}>
      {/* Frosted glass blur */}
      <BlurView
        intensity={28}
        tint="dark"
        style={StyleSheet.absoluteFillObject}
      />
      {/* Liquid glass deep color fill — neutral dark glass */}
      <View style={[StyleSheet.absoluteFillObject, {
        backgroundColor: "rgba(0, 0, 0, 0.35)",
      }]} />
      
      {/* Diagonal specular glossy sheen (Liquid Glass Reflection) */}
      <LinearGradient
        colors={[
          "rgba(255, 255, 255, 0.08)",
          "rgba(255, 255, 255, 0.01)",
          "rgba(255, 255, 255, 0.0)",
          "rgba(255, 255, 255, 0.03)"
        ]}
        start={{ x: 0.1, y: 0 }}
        end={{ x: 0.9, y: 1 }}
        style={StyleSheet.absoluteFillObject}
      />

      {/* Polish crystal top lip highlight */}
      <View style={S.tmCardShimmer} />
      {children}
    </View>
  );
}

// ─── Primary button (exact .tm-btn-primary) ───────────────────────────────────
function TmPrimaryBtn({ label, onPress, disabled, icon }: {
  label: string; onPress: () => void; disabled?: boolean;
  icon?: keyof typeof Ionicons.glyphMap;
}) {
  const scale = useRef(new Animated.Value(1)).current;
  const pi = () => Animated.spring(scale, { toValue: 0.98, useNativeDriver: true }).start();
  const po = () => Animated.spring(scale, { toValue: 1, useNativeDriver: true }).start();
  return (
    <Pressable onPress={onPress} onPressIn={pi} onPressOut={po} disabled={disabled}>
      <Animated.View style={{ transform: [{ scale }] }}>
        <LinearGradient
          colors={["#5a60d8", "#3b41bf", "#151538"]}
          start={{ x: 0.5, y: 0 }} end={{ x: 0.5, y: 1 }}
          style={S.tmPrimaryBtn}
        >
          {icon && <Ionicons name={icon} size={15} color={C.frost} style={{ marginRight: 6 }} />}
          <Text style={S.tmPrimaryBtnText}>{label}</Text>
        </LinearGradient>
      </Animated.View>
    </Pressable>
  );
}

// ─── Ghost button (exact .tm-btn-ghost) ──────────────────────────────────────
function TmGhostBtn({ label, onPress, icon }: {
  label: string; onPress: () => void;
  icon?: keyof typeof Ionicons.glyphMap;
}) {
  return (
    <Pressable onPress={onPress} style={S.tmGhostBtn}>
      {icon && <Ionicons name={icon} size={14} color={C.frost2} style={{ marginRight: 6 }} />}
      <Text style={S.tmGhostBtnText}>{label}</Text>
    </Pressable>
  );
}

// ─── Section eyebrow label ────────────────────────────────────────────────────
function Eyebrow({ label }: { label: string }) {
  return <Text style={S.eyebrow}>{label.toUpperCase()}</Text>;
}

// ─── Divider (gold shimmer line from Lovable) ─────────────────────────────────
function Divider() {
  return (
    <LinearGradient
      colors={["transparent", "rgba(232,168,76,0.25)", "transparent"]}
      start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }}
      style={{ height: 1, marginVertical: 18 }}
    />
  );
}

// ─── Status pill (exact .tm-pill) ─────────────────────────────────────────────
function TmPill({ label }: { label: string }) {
  const online = ["online", "configured"].includes(label.toLowerCase());
  const offline = ["offline", "error"].includes(label.toLowerCase());
  const col = online ? C.emerald : offline ? C.rose : C.gold;
  const bg = online
    ? "rgba(111,217,184,0.10)" : offline
    ? "rgba(224,138,174,0.10)" : "rgba(232,168,76,0.10)";
  const border = online
    ? "rgba(111,217,184,0.25)" : offline
    ? "rgba(224,138,174,0.25)" : "rgba(232,168,76,0.25)";
  return (
    <View style={[S.pill, { backgroundColor: bg, borderColor: border }]}>
      <PulsingDot color={col} />
      <Text style={[S.pillText, { color: col }]}>{label}</Text>
    </View>
  );
}

// ─── Pulsing status dot ───────────────────────────────────────────────────────
function PulsingDot({ color }: { color: string }) {
  const pulse = useRef(new Animated.Value(1)).current;
  useEffect(() => {
    Animated.loop(Animated.sequence([
      Animated.timing(pulse, { toValue: 1.5, duration: 1200, useNativeDriver: true }),
      Animated.timing(pulse, { toValue: 1, duration: 1200, useNativeDriver: true }),
    ])).start();
  }, []);
  return (
    <View style={{ width: 12, height: 12, alignItems: "center", justifyContent: "center" }}>
      <Animated.View style={{
        position: "absolute", width: 12, height: 12, borderRadius: 6,
        backgroundColor: color, opacity: 0.35, transform: [{ scale: pulse }],
      }} />
      <View style={{ width: 7, height: 7, borderRadius: 3.5, backgroundColor: color,
        shadowColor: color, shadowOffset: { width: 0, height: 0 }, shadowRadius: 6, shadowOpacity: 1 }} />
    </View>
  );
}

// ─── Icon plate (tm-icon-plate) ───────────────────────────────────────────────
function IconPlate({ icon }: { icon: keyof typeof Ionicons.glyphMap }) {
  return (
    <View style={S.iconPlate}>
      <Ionicons name={icon} size={16} color={C.frost} />
    </View>
  );
}

// ─── App ──────────────────────────────────────────────────────────────────────
function App() {
  const insets = useSafeAreaInsets();
  const [activeTab, setActiveTab] = useState<Tab>("dashboard");
  const [health, setHealth] = useState<Health | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [manualText, setManualText] = useState("");
  const [smsText, setSmsText] = useState("");
  const [smsSender, setSmsSender] = useState("");
  const [urlText, setUrlText] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [registerStep, setRegisterStep] = useState<"none" | "form" | "otp">("none");
  const [registerName, setRegisterName] = useState("");
  const [registerLastName, setRegisterLastName] = useState("");
  const [registerOtp, setRegisterOtp] = useState("");
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotBusy, setForgotBusy] = useState(false);
  // Reset password (from email deep-link)
  const [resetToken, setResetToken] = useState("");
  const [resetNewPassword, setResetNewPassword] = useState("");
  const [resetConfirmPassword, setResetConfirmPassword] = useState("");
  const [resetBusy, setResetBusy] = useState(false);
  const [showResetScreen, setShowResetScreen] = useState(false);
  const [apiUrl, setApiUrl] = useState(getApiBaseUrl());
  const [authState, setAuthState] = useState("Local mode");
  const [gmailState, setGmailState] = useState("not checked");
  const [busy, setBusy] = useState(false);
  const [uploadBusy, setUploadBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: "error" | "success" | "" }>({ msg: "", type: "" });

  // Blocks rendering login/dashboard until cold-start session restore completes
  // (prevents the login-screen flash on valid session cold start)
  const [isRestoringSession, setIsRestoringSession] = useState(true);

  // Video Splash Screen State
  const [isVideoSplashFinished, setIsVideoSplashFinished] = useState(false);
  const splashOpacity = useRef(new Animated.Value(1)).current;
  const isSplashFadingOut = useRef(false);

  const handleVideoStatusUpdate = (status: AVPlaybackStatus) => {
    if (status.isLoaded) {
      if ((status.didJustFinish || status.positionMillis >= 5800) && !isSplashFadingOut.current) {
        isSplashFadingOut.current = true;
        Animated.timing(splashOpacity, {
          toValue: 0,
          duration: 400,
          useNativeDriver: true,
        }).start(() => setIsVideoSplashFinished(true));
      }
    }
  };

  // Google Backup & Sync States
  const [googleBackupUser, setGoogleBackupUser] = useState<string | null>(null);
  const [googleBackupSyncTime, setGoogleBackupSyncTime] = useState<string | null>(null);
  const [syncingBackup, setSyncingBackup] = useState(false);
  const [notificationPreferences, setNotificationPreferences] = useState<NotificationPreferences>({
    critical_alerts: true,
    weekly_summary: true,
  });

  // Tab fade/slide animation
  const fadeAnim = useRef(new Animated.Value(1)).current;
  const slideAnim = useRef(new Animated.Value(0)).current;
  const toastTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const scrollViewRef = useRef<ScrollView>(null);

  function switchTab(tab: Tab) {
    Animated.parallel([
      Animated.timing(fadeAnim, { toValue: 0, duration: 100, useNativeDriver: true }),
      Animated.timing(slideAnim, { toValue: 10, duration: 100, useNativeDriver: true }),
    ]).start(() => {
      setActiveTab(tab);
      slideAnim.setValue(-10);
      Animated.parallel([
        Animated.timing(fadeAnim, { toValue: 1, duration: 200, useNativeDriver: true }),
        Animated.timing(slideAnim, { toValue: 0, duration: 200, useNativeDriver: true }),
      ]).start();
    });
  }

  const showToast = (msg: string, type: "error" | "success" = "error") => {
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    setToast({ msg, type });
    toastTimerRef.current = setTimeout(() => setToast({ msg: "", type: "" }), 3500);
  };

  async function refresh() {
    try {
      const [h, s, g, p] = await Promise.all([
        fetchHealth(),
        fetchScans(),
        fetchGoogleBackupStatus().catch(() => ({ connected: false, email: null, name: null, last_sync: null })),
        fetchNotificationPreferences().catch(() => ({ critical_alerts: true, weekly_summary: true }))
      ]);
      setHealth(h);
      setScans(s);
      setGoogleBackupUser(g.connected ? g.email : null);
      setGoogleBackupSyncTime(g.connected ? g.last_sync : null);
      setNotificationPreferences(p);
    } catch (e) {
      // If session expired, the global handler already fired — don't mask it
      if (e instanceof UnauthorizedError) return;
      setHealth({ api: "offline", database: "unknown", redis: "unknown", ocr: "unknown", llm: "unknown", gmail_watcher: "unknown" });
    }
  }

  useEffect(() => {
    // Fallback: If the video splash screen doesn't finish in 6.5s, automatically hide it so the app isn't stuck.
    const timer = setTimeout(() => {
      if (!isSplashFadingOut.current) {
        isSplashFadingOut.current = true;
        Animated.timing(splashOpacity, {
          toValue: 0,
          duration: 400,
          useNativeDriver: true,
        }).start(() => setIsVideoSplashFinished(true));
      }
    }, 6500);
    return () => clearTimeout(timer);
  }, []);

  // NOTE: Do NOT call refresh() here — it requires auth and will 401 on fresh installs.
  // The cold-start session-restore effect below handles the first refresh after login.
  useEffect(() => { registerForPushNotifications(); }, []);
  const onRefresh = React.useCallback(async () => { setRefreshing(true); await refresh(); setRefreshing(false); }, []);

  // ── Register the global 401 expiry handler (covers ALL API calls, not just cold-start) ──
  useEffect(() => {
    registerSessionExpiredHandler(async () => {
      await clearSession();
      setAccessToken("");
      setEmail("");
      setAuthState("Local mode");
      setScans([]);
      setHealth(null);
      showToast("Your session expired. Please sign in again.");
    });
  }, []);

  // ── Cold-start session restore ────────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      try {
        const session = await loadSession();
        if (session) {
          setEmail(session.email);
          setAccessToken(session.token); // restore in-memory token used by api.ts
          setAuthState("Signed in");
          try {
            await refresh(); // validates token AND loads full dashboard data
          } catch (err) {
            if (err instanceof UnauthorizedError) {
              // Token expired — clear everything and go to login
              await clearSession();
              setAccessToken("");
              setEmail("");
              setAuthState("Local mode");
              showToast("Your session expired. Please sign in again.");
            } else if (err instanceof NetworkError) {
              // No internet — keep user logged in, do NOT clear session
              // Dashboard will show an offline/retry state via existing health check
            } else {
              // Unexpected error — rethrow so ErrorBoundary catches it
              throw err;
            }
          }
        } else {
          setAuthState("Local mode");
        }
      } finally {
        setIsRestoringSession(false);
      }
    })();
  }, []);

  const processIncomingUrl = React.useCallback(async (url: string) => {
    if (!url) return;
    try {
      const parsed = Linking.parse(url);
      const isOAuthCallback = parsed.scheme === "safemailxai" &&
        (parsed.hostname === "oauth-callback" || parsed.path === "oauth-callback" || parsed.path === "/oauth-callback");
      const isResetCallback = parsed.scheme === "safemailxai" &&
        (parsed.hostname === "reset-password" || parsed.path === "reset-password" || parsed.path === "/reset-password");

      if (isResetCallback) {
        const params = parsed.queryParams || {};
        const token = typeof params.token === "string" ? params.token : "";
        if (token) {
          setResetToken(token);
          setResetNewPassword("");
          setResetConfirmPassword("");
          setShowResetScreen(true);
        }
        return;
      }

      if (!isOAuthCallback) return;
      const params = parsed.queryParams || {};
      const code = typeof params.code === "string" ? params.code : "";

      if (code) {
        try {
          const tokens = await exchangeOAuthCode(code);
          const emailVal = tokens.email || "";

          setAccessToken(tokens.accessToken);
          setEmail(emailVal);
          await saveSession(tokens.accessToken, emailVal, tokens.refreshToken || null);
          setAuthState("Signed in");
          setActiveTab("dashboard");

          if (params.service === "gmail") {
            showToast(`Gmail connected for ${emailVal}!`, "success");
          } else if (params.service === "backup") {
            showToast(`Backup activated for ${emailVal}!`, "success");
          } else {
            showToast(`Welcome back, ${emailVal}!`, "success");
          }
          refresh();
          refreshGmailStatus();
        } catch {
          // Token was invalid or expired — clear it
          setAccessToken("");
          setEmail("");
          showToast("This sign-in link has expired. Please try again.");
        }
      }
    } catch (e) {
      console.warn("Deep link could not be processed");
    }
  }, []);

  useEffect(() => {
    const handleDeepLink = (event: { url: string }) => {
      processIncomingUrl(event.url);
    };
    const sub = Linking.addEventListener("url", handleDeepLink);

    Linking.getInitialURL().then((url) => {
      if (url) processIncomingUrl(url);
    });

    return () => {
      sub.remove();
    };
  }, [processIncomingUrl]);

  // ── Android Share Intent handler ("Share to SafeMail X") ───────────────
  // When user long-presses an SMS and taps "Share → SafeMail X", Android
  // opens the app with a safemailxai://share?text=<url-encoded-sms> URL.
  // We pre-fill the SMS scanner and open the unified scan screen automatically.
  // This is entirely additive — the existing deep-link handler is untouched.
  useEffect(() => {
    function handleShareIntent(event: { url: string }) {
      const url = event.url || "";
      if (!url.includes("safemailxai://share")) return;
      try {
        const textMatch = url.match(/[?&]text=([^&]*)/);
        if (textMatch && textMatch[1]) {
          const sharedText = decodeURIComponent(textMatch[1].replace(/\+/g, " "));
          setSmsText(sharedText);
          setActiveTab("new");
          showToast("SMS loaded — tap Scan SMS to analyse", "success");
        }
      } catch {
        // Malformed share URL — ignore silently
      }
    }
    const sub = Linking.addEventListener("url", handleShareIntent);
    // Handle cold-start shares (app was closed when user tapped Share)
    Linking.getInitialURL().then((url) => {
      if (url) handleShareIntent({ url });
    });
    return () => sub.remove();
  }, []);

  useEffect(() => {
    const hasQueued = scans.some(s => s.final_label === "queued");
    if (!hasQueued) return;
    const iv = setInterval(() => refresh(), 3000);
    return () => clearInterval(iv);
  }, [scans]);

  async function registerForPushNotifications() {
    if (process.env.EXPO_PUBLIC_ENABLE_PUSH !== "true") return;
    try {
      const N = await import("expo-notifications");
      const p = await N.requestPermissionsAsync();
      if (!p.granted) return;
      const t = await N.getExpoPushTokenAsync();
      await registerPushToken(t.data, Platform.OS);
    } catch (e) { console.log("Push skipped:", e); }
  }

  const stats = useMemo(() => ({
    safe: scans.filter(s => s.final_label === "legitimate").length,
    suspicious: scans.filter(s => s.final_label === "suspicious").length,
    phishing: scans.filter(s => s.final_label === "phishing").length,
  }), [scans]);

  async function submitManualScan() {
    if (!manualText.trim()) {
      showToast("Your text box is empty. Please paste something to scan.");
      return;
    }
    setBusy(true);
    try {
      await createManualScan(manualText.trim());
      setManualText(""); switchTab("scans"); await refresh();
      showToast("Scan queued successfully", "success");
    } catch (e: any) { showToast(e.message || "Scan failed"); }
    finally { setBusy(false); }
  }

  async function submitSmsScan() {
    if (!smsText.trim()) { showToast("Your SMS box is empty. Please paste a message to scan."); return; }
    setBusy(true);
    try {
      await scanSms(smsText.trim(), smsSender.trim());
      setSmsText(""); setSmsSender(""); switchTab("scans"); await refresh();
      showToast("SMS Scanned successfully", "success");
    } catch (e: any) { showToast(e.message || "SMS scan failed"); }
    finally { setBusy(false); }
  }

  async function submitUploadScan() {
    const r = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true, multiple: false,
      type: ["text/plain","message/rfc822","application/pdf","application/vnd.openxmlformats-officedocument.wordprocessingml.document","image/*"] });
    if (r.canceled || !r.assets[0]) return;
    setUploadBusy(true);
    try {
      const a = r.assets[0];
      await uploadScanFile({ uri: a.uri, name: a.name, mimeType: a.mimeType });
      switchTab("scans"); await refresh(); showToast("File scanned", "success");
    } catch (e: any) { showToast(e.message || "Upload failed"); }
    finally { setUploadBusy(false); }
  }

  async function submitScreenshotScan() {
    const r = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true, multiple: false, type: "image/*" });
    if (r.canceled || !r.assets[0]) return;
    setUploadBusy(true);
    try {
      const a = r.assets[0];
      await uploadScreenshot({ uri: a.uri, name: a.name, mimeType: a.mimeType });
      switchTab("scans"); await refresh(); showToast("Screenshot scanned", "success");
    } catch (e: any) { showToast(e.message || "Screenshot scan failed"); }
    finally { setUploadBusy(false); }
  }

  async function submitUrlScan() {
    if (!urlText.trim()) { showToast("Your URL box is empty. Please paste a URL to check."); return; }
    setBusy(true);
    try {
      await scanUrl(urlText.trim());
      setUrlText(""); switchTab("scans"); await refresh();
      showToast("URL scanned successfully", "success");
    } catch (e: any) { showToast(e.message || "URL scan failed"); }
    finally { setBusy(false); }
  }

  async function submitLogin() {
    if (!email.trim() || !password) { showToast("Please enter your email and password to sign in."); return; }
    setAuthState("Signing in…"); setBusy(true);
    try {
      const tokens = await login(email.trim(), password); setPassword("");
      await saveSession(tokens.accessToken, email.trim(), tokens.refreshToken || null); // persist to encrypted storage
      setAuthState("Signed in"); await refresh(); await refreshGmailStatus();
      setActiveTab("dashboard");
      showToast("Signed in successfully", "success");
    } catch (e: any) { setAuthState("Local mode"); showToast(e?.name === "NetworkError" || e?.message?.includes("timed out") || e?.message?.includes("failed") ? "Connection timed out. Please try again." : "Invalid email or password"); }
    finally { setBusy(false); }
  }

  async function requestOtp() {
    if (!email.trim() || !password || !registerName.trim()) return showToast("Name, Email, and password required");
    
    if (password.length < 8) return showToast("Password must be at least 8 characters");
    if (!/[0-9]/.test(password)) return showToast("Password must contain at least 1 number");
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return showToast("Password must contain at least 1 symbol");

    setBusy(true);
    try {
      await sendRegistrationOtp(email.trim());
      setRegisterStep("otp");
      showToast("OTP sent to your email", "success");
    } catch (e: any) { showToast(e.message || "Failed to send OTP"); }
    finally { setBusy(false); }
  }

  async function submitRegisterWithOtp() {
    if (!registerOtp.trim() || registerOtp.length !== 6) return showToast("Please enter a valid 6-digit OTP");
    setAuthState("Registering…"); setBusy(true);
    try {
      const tokens = await register(email.trim(), registerName.trim(), password, registerOtp.trim());
      await saveSession(tokens.accessToken, email.trim(), tokens.refreshToken || null); // persist to encrypted storage
      setAuthState("Signed in"); await refresh(); await refreshGmailStatus();
      setActiveTab("dashboard");
      setRegisterStep("none");
      showToast("Account created successfully", "success");
    } catch (e: any) { setAuthState("Local mode"); showToast(e.message || "Registration failed"); }
    finally { setBusy(false); }
  }

  async function handleLogout() {
    await logoutSession();
    await clearSession();
    AsyncStorage.removeItem('gmailLabelsReady').catch(() => {}); // clear gmail label cache
    setAccessToken("");
    setAuthState("Local mode");
    setEmail("");
    setPassword("");
    setScans([]);
    setHealth(null);
    setGmailState("not checked");
    setGoogleBackupUser(null);
    setGoogleBackupSyncTime(null);
    setRegisterStep("none");
    setRegisterName("");
    setRegisterOtp("");
    setNotificationPreferences({ critical_alerts: true, weekly_summary: true });
    setActiveTab("dashboard");
    showToast("Logged out successfully", "success");
  }

  function handleClearCache() {
    setScans([]);
    showToast("Local cache cleared", "success");
  }

  async function startGoogleLogin() {
    setBusy(true);
    try {
      const returnUrl = Linking.createURL("oauth-callback");
      const { startGoogleAuthLogin } = await import("./src/api");
      const url = await startGoogleAuthLogin(returnUrl);
      Linking.openURL(url);
      showToast("Google Sign-In opened...", "success");
    } catch (e: any) {
      showToast(e.message || "Failed to start Google Sign-In");
    } finally {
      setBusy(false);
    }
  }
  async function refreshGmailStatus() {
    try {
      const status = await fetchGmailOAuthStatus();
      const labelsReady = await AsyncStorage.getItem('gmailLabelsReady');
      if (status.connected) {
        if (labelsReady === 'true') {
          setGmailState("labels ready");
        } else {
          setGmailState("connected");
        }
      } else {
        setGmailState("not connected");
      }
    }
    catch { setGmailState("sign in required"); }
  }

  async function connectGmail() {
    setBusy(true);
    setGmailState("connecting…");
    try {
      const returnUrl = Linking.createURL("oauth-callback");
      const { startGmailOAuth } = await import("./src/api");
      const url = await startGmailOAuth(returnUrl);
      Linking.openURL(url);
      showToast("Google account flow opened...", "success");
    } catch (e: any) {
      showToast(e.message || "Failed to start Google Sign-In");
    } finally {
      setBusy(false);
    }
  }

  async function submitForgotPassword() {
    if (!forgotEmail.trim()) { showToast("Please enter your email address."); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(forgotEmail.trim())) { showToast("Please enter a valid email address."); return; }
    setForgotBusy(true);
    try {
      const { requestPasswordReset } = await import("./src/api");
      await requestPasswordReset(forgotEmail.trim());
      setShowForgotModal(false);
      setForgotEmail("");
      showToast("If that email exists, a reset link has been sent.", "success");
    } catch (e: any) {
      showToast(e?.name === "NetworkError" ? "Connection failed. Please try again." : "Failed to send reset email. Try again.");
    } finally {
      setForgotBusy(false);
    }
  }

  async function connectGoogleBackup() {
    setBusy(true);
    try {
      const returnUrl = Linking.createURL("oauth-callback");
      const url = await startGoogleBackupOAuth(returnUrl);
      await Linking.openURL(url);
      showToast("Google Backup flow opened...", "success");
    } catch (e: any) {
      showToast(e.message || "Failed to start Google Backup");
    } finally {
      setBusy(false);
    }
  }

  async function handleDisconnectGoogle() {
    setBusy(true);
    try {
      await disconnectGoogleBackup();
      setGoogleBackupUser(null);
      setGoogleBackupSyncTime(null);
      showToast("Google Backup disconnected", "success");
    } catch (e: any) {
      showToast(e.message || "Failed to disconnect Google account");
    } finally {
      setBusy(false);
    }
  }

  async function syncGoogleBackup() {
    setSyncingBackup(true);
    try {
      const { triggerGoogleBackupSync } = await import("./src/api");
      const res = await triggerGoogleBackupSync();
      setGoogleBackupSyncTime(res.last_sync);
      await refresh();
      showToast("Cloud sync completed!", "success");
    } catch (e: any) {
      showToast(e.message || "Failed to sync cloud backup");
    } finally {
      setSyncingBackup(false);
    }
  }

  async function setupGmailLabels() {
    setBusy(true);
    try {
      const { ensureGmailLabels } = await import("./src/api");
      const l = await ensureGmailLabels(); 
      setGmailState(`labels ready — ${l.scan}`);
      await AsyncStorage.setItem('gmailLabelsReady', 'true');
      showToast("Gmail labels ready", "success");
    } catch (e: any) { showToast(e.message || "Label setup failed"); }
    finally { setBusy(false); }
  }

  async function runGmailScan() {
    setBusy(true);
    try {
      const { runGmailLabelScan } = await import("./src/api");
      const r = await runGmailLabelScan(); setGmailState(`${r.enqueued} queued from ${r.scanned_label}`);
      await refresh(); switchTab("scans");
      showToast(`${r.enqueued} Gmail message(s) queued`, "success");
    } catch (e: any) { showToast(e.message || "Label scan failed"); }
    finally { setBusy(false); }
  }

  async function saveApiUrl(url: string) {
    if (!url.trim()) return;
    if (!setApiBaseUrl(url.trim())) {
      showToast("API changes are available only in developer builds.");
      return;
    }
    setApiUrl(getApiBaseUrl()); await refresh();
    showToast("API server updated", "success");
  }

  async function updateNotificationSetting(key: keyof NotificationPreferences, value: boolean) {
    const previous = notificationPreferences;
    const next = { ...previous, [key]: value };
    setNotificationPreferences(next);
    try {
      const saved = await saveNotificationPreferences(next);
      setNotificationPreferences(saved);
      showToast(`${key === "critical_alerts" ? "Critical Alerts" : "Weekly Summary"} ${value ? "enabled" : "disabled"}.`, "success");
    } catch (e: any) {
      setNotificationPreferences(previous);
      showToast(e.message || "Failed to update notification preferences");
    }
  }

  async function openReport(scanId: string, kind: "pdf" | "json") {
    try { await Linking.openURL(await getReportDownloadUrl(scanId, kind)); }
    catch (e: any) { showToast(e.message || "Report unavailable"); }
  }

  return (
    <View style={S.root}>
      <StatusBar style="light" translucent />
      <TmBg />

      {/* ── Session restore loading gate — prevents login-screen flash on cold start ── */}
      {isRestoringSession && (
        <View style={[StyleSheet.absoluteFill, { backgroundColor: "#000", alignItems: "center", justifyContent: "center", zIndex: 999 }]}>
          <Image
            source={require('./assets/new-logo.png')}
            style={{ width: 80, height: 80, resizeMode: "contain", opacity: 0.7, marginBottom: 20 }}
          />
          <ActivityIndicator size="small" color="#8a8ff0" />
        </View>
      )}

      {/* ── Header ── */}
      {authState === "Signed in" && (
        <View style={[S.header, { paddingTop: insets.top + 8 }]}>
          <Text style={S.logo}>
            SafeMail<Text style={{ color: C.violetGlow }}> X AI</Text>
          </Text>
          <TmPill label={health?.api || "loading"} />
        </View>
      )}

      {/* ── Content ── */}
      {authState !== "Signed in" ? (
        <>
          <AuthScreen 
            email={email} password={password} onEmail={setEmail} onPassword={setPassword} 
            onLogin={submitLogin} onGoogleAuth={startGoogleLogin} busy={busy}
            registerStep={registerStep} setRegisterStep={setRegisterStep}
            registerName={registerName} setRegisterName={setRegisterName}
            registerLastName={registerLastName} setRegisterLastName={setRegisterLastName}
            registerOtp={registerOtp} setRegisterOtp={setRegisterOtp}
            requestOtp={requestOtp} submitRegisterWithOtp={submitRegisterWithOtp}
            onForgot={() => { setForgotEmail(email); setShowForgotModal(true); }}
          />
        </>
      ) : (
        <>
          <ScrollView
            ref={scrollViewRef}
            style={{ flex: 1 }}
            contentContainerStyle={{ paddingHorizontal: 20, paddingBottom: 110 }}
            refreshControl={
              <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={C.violetGlow} colors={[C.violet]} />
            }
          >
            <Animated.View style={{ opacity: fadeAnim, transform: [{ translateY: slideAnim }] }}>
              <View style={{ display: activeTab === "dashboard" ? "flex" : "none" }}>
                <DashboardScreen 
                  health={health} 
                  stats={stats} 
                  scans={scans} 
                  googleBackupUser={googleBackupUser}
                  googleBackupSyncTime={googleBackupSyncTime}
                  syncingBackup={syncingBackup}
                  onConnectGoogle={connectGoogleBackup}
                  onDisconnectGoogle={handleDisconnectGoogle}
                  onSyncGoogle={syncGoogleBackup}
                  onOpenReport={openReport}
                />
              </View>
              <View style={{ display: activeTab === "scans" ? "flex" : "none" }}>
                <ScansScreen scans={scans} />
              </View>
              <View style={{ display: activeTab === "new" ? "flex" : "none" }}>
                <UnifiedScanScreen
                  gmailState={gmailState} busy={busy}
                  onConnectGmail={connectGmail} onRefreshGmail={refreshGmailStatus}
                  onSetupGmailLabels={setupGmailLabels} onRunGmailScan={runGmailScan}
                  smsText={smsText} setSmsText={setSmsText}
                  smsSender={smsSender} setSmsSender={setSmsSender}
                  urlText={urlText} setUrlText={setUrlText}
                  manualText={manualText} setManualText={setManualText}
                  onSubmitManual={submitManualScan}
                  refreshApp={refresh}
                  scrollViewRef={scrollViewRef}
                  onShowToast={showToast}
                />
              </View>
              <View style={{ display: activeTab === "reports" ? "flex" : "none" }}>
                <ReportsScreen scans={scans} onOpenReport={openReport} />
              </View>
              <View style={{ display: activeTab === "settings" ? "flex" : "none" }}>
                <SettingsScreen
                  health={health} email={email} password={password} apiUrl={apiUrl}
                  authState={authState} gmailState={gmailState}
                  onEmail={setEmail} onPassword={setPassword} onApiUrl={setApiUrl}
                  onSaveApiUrl={saveApiUrl} onLogin={submitLogin}
                  onConnectGmail={connectGmail} onRefreshGmail={refreshGmailStatus}
                  onSetupGmailLabels={setupGmailLabels} onRunGmailScan={runGmailScan}
                  onShowToast={showToast}
                  notificationPreferences={notificationPreferences}
                  onUpdateNotificationPreference={updateNotificationSetting}
                  googleBackupUser={googleBackupUser}
                  googleBackupSyncTime={googleBackupSyncTime}
                  syncingBackup={syncingBackup}
                  scans={scans}
                  onConnectGoogle={connectGoogleBackup}
                  onDisconnectGoogle={handleDisconnectGoogle}
                  onSyncGoogle={syncGoogleBackup}
                  onSwitchTab={switchTab}
                  onLogout={handleLogout}
                  onClearCache={handleClearCache}
                />
              </View>
              <View style={{ display: activeTab === "privacy" ? "flex" : "none" }}>
                <PrivacyPolicyScreen onBack={() => switchTab("settings")} />
              </View>
              <View style={{ display: activeTab === "help" ? "flex" : "none" }}>
                <HelpCenterScreen onBack={() => switchTab("settings")} />
              </View>
            </Animated.View>
          </ScrollView>
          <BottomNavBar active={activeTab} onSwitch={switchTab} bottomInset={insets.bottom} />
        </>
      )}

      {/* ── Toast ── */}
      {toast.msg ? (
        <View style={[S.toast,
          { borderColor: toast.type === "error" ? "rgba(224,138,174,0.6)" : "rgba(111,217,184,0.6)",
            top: insets.top + 20, zIndex: 99999, elevation: 99999, backgroundColor: "rgba(10, 15, 20, 0.9)", shadowColor: toast.type === "error" ? C.rose : C.emerald, shadowOpacity: 0.5, shadowRadius: 15 }
        ]}>
          <PulsingDot color={toast.type === "error" ? C.rose : C.emerald} />
          <Text style={[S.toastText, { color: toast.type === "error" ? C.rose : C.emerald, fontWeight: "600" }]}>{toast.msg}</Text>
        </View>
      ) : null}

      {/* ── Loading overlay ── */}
      {busy && (
        <View style={S.overlay}>
          <TmCard style={{ padding: 30, alignItems: "center" }}>
            <SpinIcon />
            <Text style={[S.frost, { fontWeight: "700", marginTop: 12 }]}>Processing…</Text>
          </TmCard>
        </View>
      )}

      {/* ── Forgot Password Modal ── */}
      {showForgotModal && (
        <ForgotPasswordModal
          forgotEmail={forgotEmail}
          setForgotEmail={setForgotEmail}
          forgotBusy={forgotBusy}
          onClose={() => { setShowForgotModal(false); setForgotEmail(""); }}
          onSubmit={submitForgotPassword}
        />
      )}

      {/* ── Reset Password Screen (from email deep-link) ── */}
      {showResetScreen && (
        <ResetPasswordScreen
          token={resetToken}
          newPassword={resetNewPassword}
          setNewPassword={setResetNewPassword}
          confirmPassword={resetConfirmPassword}
          setConfirmPassword={setResetConfirmPassword}
          busy={resetBusy}
          onClose={() => { setShowResetScreen(false); setResetToken(""); setResetNewPassword(""); setResetConfirmPassword(""); }}
          onSubmit={async () => {
            if (!resetNewPassword.trim()) { showToast("Please enter a new password."); return; }
            if (resetNewPassword.length < 8) { showToast("Password must be at least 8 characters."); return; }
            if (resetNewPassword !== resetConfirmPassword) { showToast("Passwords do not match."); return; }
            setResetBusy(true);
            try {
              const { confirmPasswordReset } = await import("./src/api");
              await confirmPasswordReset(resetToken, resetNewPassword);
              setShowResetScreen(false);
              setResetToken(""); setResetNewPassword(""); setResetConfirmPassword("");
              showToast("Password updated! Please sign in.", "success");
            } catch (e: any) {
              showToast(e?.message === "Password reset confirmation failed" ? "Reset link expired or already used." : "Failed to reset. Please try again.");
            } finally {
              setResetBusy(false);
            }
          }}
        />
      )}

      {/* ── Video Splash Screen ── */}
      {!isVideoSplashFinished && (
        <Animated.View style={[StyleSheet.absoluteFill, { opacity: splashOpacity, zIndex: 9999999, elevation: 9999999, backgroundColor: "#000" }]}>
          <Video
            source={require('./assets/V2.mp4')}
            style={StyleSheet.absoluteFillObject}
            resizeMode={ResizeMode.COVER}
            shouldPlay
            isMuted={false}
            onPlaybackStatusUpdate={handleVideoStatusUpdate}
            onError={(error) => {
              console.log("Video playback error:", error);
              if (!isSplashFadingOut.current) {
                isSplashFadingOut.current = true;
                Animated.timing(splashOpacity, {
                  toValue: 0,
                  duration: 400,
                  useNativeDriver: true,
                }).start(() => setIsVideoSplashFinished(true));
              }
            }}
          />
        </Animated.View>
      )}
    </View>
  );
}

// ─── Auth Gatekeeper Screen ────────────────────────────────────────────────────
const authStyles = StyleSheet.create({
  wrap: {
    flexGrow: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  phone: {
    width: '100%',
    paddingHorizontal: 25,
    paddingVertical: 50,
    flex: 1,
  },
  snav: {
    fontFamily: 'DMSans_300Light', fontSize: 14, color: 'rgba(0,180,255,0.65)', letterSpacing: 1
  },
  badge: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: 'rgba(0,140,255,0.1)',
    borderWidth: 0.5, borderColor: 'rgba(0,180,255,0.28)',
    borderRadius: 20, paddingVertical: 6, paddingHorizontal: 12,
    alignSelf: 'flex-start', marginBottom: 20
  },
  bdot: {
    width: 6, height: 6, borderRadius: 3, backgroundColor: '#00c6ff', marginRight: 6
  },
  btxt: {
    fontFamily: 'DMSans_400Regular', fontSize: 10, letterSpacing: 1.2, color: '#7de0ff', textTransform: 'uppercase'
  },
  brandRow: {
    flexDirection: 'row', alignItems: 'center', marginBottom: 30
  },
  brandName: {
    fontFamily: 'CormorantGaramond_600SemiBold', fontSize: 20, color: 'rgba(255,255,255,0.9)', letterSpacing: 0.5, marginLeft: 12
  },
  heroFrame: {
    paddingLeft: 18, marginBottom: 30, borderLeftWidth: 2, borderLeftColor: 'rgba(0,160,255,0.5)'
  },
  hl: {
    fontFamily: 'CormorantGaramond_300Light', fontSize: 50, lineHeight: 52, color: 'rgba(255,255,255,0.93)'
  },
  hsub: {
    fontFamily: 'CormorantGaramond_300Light', fontSize: 14, letterSpacing: 2, color: 'rgba(255,255,255,0.38)', textTransform: 'uppercase', marginTop: 10, lineHeight: 22
  },
  divl: {
    width: 40, height: 1, backgroundColor: '#0a6bff', marginBottom: 30
  },
  btnP: {
    width: '100%', borderRadius: 16,
    justifyContent: 'center', alignItems: 'center', marginBottom: 12, overflow: 'hidden'
  },
  btnPInner: {
    paddingVertical: 16, width: '100%', alignItems: 'center'
  },
  btnPText: {
    fontFamily: 'DMSans_500Medium', fontSize: 14, letterSpacing: 1.5, color: '#fff'
  },
  btnS: {
    width: '100%', paddingVertical: 16, borderRadius: 16, borderWidth: 0.5, borderColor: 'rgba(255,255,255,0.11)',
    backgroundColor: 'rgba(255,255,255,0.04)', justifyContent: 'center', alignItems: 'center'
  },
  btnSText: {
    fontFamily: 'DMSans_300Light', fontSize: 14, letterSpacing: 0.5, color: 'rgba(255,255,255,0.6)'
  },
  scTitle: {
    fontFamily: 'CormorantGaramond_300Light', fontSize: 32, textAlign: 'center', color: 'rgba(255,255,255,0.9)', marginBottom: 4, letterSpacing: 0.5
  },
  flabel: {
    fontFamily: 'DMSans_500Medium', fontSize: 11, letterSpacing: 1.5, textTransform: 'uppercase', color: 'rgba(255,255,255,0.38)', marginBottom: 8, marginTop: 16
  },
  fbox: {
    width: '100%', backgroundColor: 'rgba(255,255,255,0.04)', borderWidth: 0.5, borderColor: 'rgba(255,255,255,0.09)', borderRadius: 12, paddingHorizontal: 16, height: 50, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center'
  },
  finput: {
    flex: 1, fontFamily: 'DMSans_300Light', fontSize: 15, color: '#fff'
  },
  forgot: {
    alignSelf: 'flex-end', marginTop: 12, marginBottom: 20
  },
  forgotTxt: {
    fontFamily: 'DMSans_300Light', fontSize: 13, color: 'rgba(0,180,255,0.65)', letterSpacing: 0.5
  },
  divOr: {
    flexDirection: 'row', alignItems: 'center', marginVertical: 20
  },
  divOrLine: {
    flex: 1, height: 0.5, backgroundColor: 'rgba(255,255,255,0.06)'
  },
  divOrTxt: {
    fontFamily: 'DMSans_300Light', fontSize: 12, color: 'rgba(255,255,255,0.22)', letterSpacing: 1, marginHorizontal: 12
  },
  socRow: {
    flexDirection: 'row', gap: 12
  },
  socBtn: {
    flex: 1, paddingVertical: 14, borderRadius: 14, borderWidth: 0.5, borderColor: 'rgba(255,255,255,0.09)', backgroundColor: 'rgba(255,255,255,0.04)', flexDirection: 'row', alignItems: 'center', justifyContent: 'center'
  },
  socBtnTxt: {
    fontFamily: 'DMSans_300Light', fontSize: 14, color: 'rgba(255,255,255,0.6)', marginLeft: 8
  }
});

function HtmlSvgLogo({ size = 110 }) {
  return (
    <Image 
      source={require('./assets/shield_AI_transparent.png')} 
      style={{ width: size, height: size, resizeMode: 'contain', borderRadius: size / 4 }} 
    />
  );
}

function GradientText({ text, style, colors }: { text: string; style: any; colors: any }) {
  return (
    <MaskedView maskElement={<Text style={[style, { backgroundColor: 'transparent' }]}>{text}</Text>}>
      <LinearGradient colors={colors} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}>
        <Text style={[style, { opacity: 0 }]}>{text}</Text>
      </LinearGradient>
    </MaskedView>
  );
}

// ─── Forgot Password Modal ────────────────────────────────────────────────────
function ForgotPasswordModal({ forgotEmail, setForgotEmail, forgotBusy, onClose, onSubmit }: {
  forgotEmail: string; setForgotEmail: (v: string) => void;
  forgotBusy: boolean; onClose: () => void; onSubmit: () => void;
}) {
  const slideAnim = useRef(new Animated.Value(40)).current;
  const fadeAnim = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(slideAnim, { toValue: 0, duration: 350, useNativeDriver: true }),
      Animated.timing(fadeAnim, { toValue: 1, duration: 350, useNativeDriver: true }),
    ]).start();
  }, []);

  return (
    <View style={[StyleSheet.absoluteFill, { backgroundColor: "rgba(4,8,16,0.88)", zIndex: 99998, elevation: 99998, justifyContent: "center", alignItems: "center" }]}>
      <LinearGradient colors={['rgba(10,40,90,0.5)', 'rgba(4,8,16,0.0)']} start={{x:0,y:0}} end={{x:1,y:1}} style={StyleSheet.absoluteFillObject} />
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={{ width: "100%", alignItems: "center" }}>
        <Animated.View style={{ width: "88%", maxWidth: 380, opacity: fadeAnim, transform: [{ translateY: slideAnim }] }}>
          {/* Card */}
          <View style={{ backgroundColor: "rgba(11,19,34,0.97)", borderRadius: 24, borderWidth: 0.5, borderColor: "rgba(0,180,255,0.18)", padding: 28, overflow: "hidden" }}>
            <LinearGradient colors={['rgba(0,107,255,0.07)', 'transparent']} start={{x:0,y:0}} end={{x:1,y:1}} style={StyleSheet.absoluteFillObject} />

            {/* Icon + title */}
            <View style={{ alignItems: "center", marginBottom: 20 }}>
              <View style={{ width: 56, height: 56, borderRadius: 28, backgroundColor: "rgba(0,107,255,0.12)", borderWidth: 0.5, borderColor: "rgba(0,180,255,0.3)", alignItems: "center", justifyContent: "center", marginBottom: 14 }}>
                <Text style={{ fontSize: 24 }}>🔑</Text>
              </View>
              <Text style={{ fontFamily: "CormorantGaramond_300Light", fontSize: 28, color: "#fff", letterSpacing: 0.5, textAlign: "center" }}>Reset Password</Text>
              <Text style={{ fontFamily: "DMSans_300Light", fontSize: 13, color: "rgba(255,255,255,0.38)", textAlign: "center", marginTop: 6, lineHeight: 18, letterSpacing: 0.3 }}>
                Enter your email and we'll send{"\n"}a secure reset link
              </Text>
            </View>

            {/* Divider */}
            <View style={{ width: 40, height: 1, backgroundColor: "#0a6bff", alignSelf: "center", marginBottom: 22 }} />

            {/* Email field */}
            <Text style={authStyles.flabel}>Email Address</Text>
            <View style={[authStyles.fbox, { marginBottom: 22 }]}>
              <TextInput
                value={forgotEmail}
                onChangeText={setForgotEmail}
                placeholder="Enter your email"
                placeholderTextColor="rgba(255,255,255,0.28)"
                autoCapitalize="none"
                keyboardType="email-address"
                editable={!forgotBusy}
                autoFocus
                style={authStyles.finput}
              />
              <Text style={{ fontSize: 18, color: "rgba(0,180,255,0.5)" }}>✉</Text>
            </View>

            {/* Send button */}
            <Pressable onPress={onSubmit} disabled={forgotBusy}>
              <View style={[authStyles.btnP, { opacity: forgotBusy ? 0.65 : 1 }]}>
                <LinearGradient colors={['#0a6bff', '#00b4ff']} start={{x:0,y:0}} end={{x:1,y:1}} style={authStyles.btnPInner}>
                  <Text style={authStyles.btnPText}>{forgotBusy ? "SENDING…" : "SEND RESET LINK"}</Text>
                </LinearGradient>
                <LinearGradient colors={['rgba(255,255,255,0.14)', 'transparent']} style={StyleSheet.absoluteFill} />
              </View>
            </Pressable>

            {/* Cancel */}
            <Pressable onPress={onClose} style={authStyles.btnS} disabled={forgotBusy}>
              <Text style={authStyles.btnSText}>Cancel</Text>
            </Pressable>
          </View>
        </Animated.View>
      </KeyboardAvoidingView>
    </View>
  );
}

// ─── Reset Password Screen (deep-link entry) ──────────────────────────────────
function ResetPasswordScreen({ token, newPassword, setNewPassword, confirmPassword, setConfirmPassword, busy, onClose, onSubmit }: {
  token: string; newPassword: string; setNewPassword: (v: string) => void;
  confirmPassword: string; setConfirmPassword: (v: string) => void;
  busy: boolean; onClose: () => void; onSubmit: () => void;
}) {
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const slideAnim = useRef(new Animated.Value(60)).current;
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const insets = useSafeAreaInsets();

  useEffect(() => {
    Animated.parallel([
      Animated.timing(slideAnim, { toValue: 0, duration: 400, useNativeDriver: true }),
      Animated.timing(fadeAnim, { toValue: 1, duration: 400, useNativeDriver: true }),
    ]).start();
  }, []);

  const strength = newPassword.length === 0 ? 0 : newPassword.length < 8 ? 1 : newPassword.length < 12 ? 2 : 3;
  const strengthColor = ["transparent", C.rose, C.gold, C.emerald][strength];
  const strengthLabel = ["", "Too short", "Good", "Strong"][strength];

  return (
    <View style={[StyleSheet.absoluteFill, { backgroundColor: "#04080e", zIndex: 99999, elevation: 99999 }]}>
      <LinearGradient
        colors={['rgba(0,30,80,0.6)', 'rgba(4,8,16,0.95)', '#04080e']}
        start={{x:0.3,y:0}} end={{x:0.7,y:1}}
        style={StyleSheet.absoluteFillObject}
      />

      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={{ flex: 1 }}>
        <ScrollView contentContainerStyle={{ flexGrow: 1, paddingTop: insets.top + 20, paddingBottom: insets.bottom + 40, paddingHorizontal: 25 }} keyboardShouldPersistTaps="handled">
          <Animated.View style={{ opacity: fadeAnim, transform: [{ translateY: slideAnim }] }}>

            {/* Back button */}
            <Pressable onPress={onClose} hitSlop={16} style={{ flexDirection: "row", alignItems: "center", marginBottom: 32 }}>
              <Text style={{ color: "rgba(0,180,255,0.65)", fontSize: 18, marginRight: 6 }}>‹</Text>
              <Text style={{ fontFamily: "DMSans_300Light", fontSize: 14, color: "rgba(0,180,255,0.65)", letterSpacing: 0.5 }}>Back to sign in</Text>
            </Pressable>

            {/* Logo */}
            <View style={{ alignItems: "center", marginBottom: 24 }}>
              <View style={{ width: 80, height: 80, borderRadius: 40, backgroundColor: "rgba(0,107,255,0.1)", borderWidth: 0.5, borderColor: "rgba(0,180,255,0.25)", alignItems: "center", justifyContent: "center" }}>
                <Text style={{ fontSize: 36 }}>🔐</Text>
              </View>
            </View>

            {/* Title */}
            <Text style={[authStyles.scTitle, { marginBottom: 4 }]}>Choose a New</Text>
            <GradientText
              text="Password"
              style={{ fontFamily: "CormorantGaramond_300Light_Italic", fontSize: 32, textAlign: "center", marginBottom: 8, letterSpacing: 0.5 }}
              colors={["#55d6ff", "#0a6bff"]}
            />
            <Text style={{ fontFamily: "DMSans_300Light", fontSize: 13, color: "rgba(255,255,255,0.35)", textAlign: "center", letterSpacing: 0.3, marginBottom: 30, lineHeight: 18 }}>
              Make it strong. At least 8 characters.
            </Text>

            {/* New password */}
            <Text style={authStyles.flabel}>New Password</Text>
            <View style={authStyles.fbox}>
              <TextInput
                value={newPassword}
                onChangeText={setNewPassword}
                placeholder="Enter new password"
                placeholderTextColor="rgba(255,255,255,0.28)"
                secureTextEntry={!showNew}
                style={authStyles.finput}
                editable={!busy}
              />
              <Pressable onPress={() => setShowNew(v => !v)} hitSlop={8}>
                <Text style={{ fontSize: 16, color: "rgba(0,180,255,0.5)" }}>{showNew ? "◉" : "◎"}</Text>
              </Pressable>
            </View>

            {/* Strength bar */}
            {newPassword.length > 0 && (
              <View style={{ flexDirection: "row", alignItems: "center", marginTop: 8, marginBottom: 4, gap: 4 }}>
                {[1, 2, 3].map(i => (
                  <View key={i} style={{ flex: 1, height: 3, borderRadius: 2, backgroundColor: i <= strength ? strengthColor : "rgba(255,255,255,0.08)" }} />
                ))}
                <Text style={{ fontFamily: "DMSans_300Light", fontSize: 11, color: strengthColor, marginLeft: 6, width: 55 }}>{strengthLabel}</Text>
              </View>
            )}

            {/* Confirm password */}
            <Text style={authStyles.flabel}>Confirm Password</Text>
            <View style={[authStyles.fbox, { marginBottom: 8 }]}>
              <TextInput
                value={confirmPassword}
                onChangeText={setConfirmPassword}
                placeholder="Repeat new password"
                placeholderTextColor="rgba(255,255,255,0.28)"
                secureTextEntry={!showConfirm}
                style={authStyles.finput}
                editable={!busy}
              />
              <Pressable onPress={() => setShowConfirm(v => !v)} hitSlop={8}>
                <Text style={{ fontSize: 16, color: "rgba(0,180,255,0.5)" }}>{showConfirm ? "◉" : "◎"}</Text>
              </Pressable>
            </View>

            {/* Match indicator */}
            {confirmPassword.length > 0 && (
              <Text style={{ fontFamily: "DMSans_300Light", fontSize: 12, color: newPassword === confirmPassword ? C.emerald : C.rose, marginBottom: 4, letterSpacing: 0.3 }}>
                {newPassword === confirmPassword ? "✓ Passwords match" : "✗ Passwords don't match"}
              </Text>
            )}

            {/* Submit */}
            <View style={{ marginTop: 28 }}>
              <Pressable onPress={onSubmit} disabled={busy || newPassword.length < 8 || newPassword !== confirmPassword}>
                <View style={[authStyles.btnP, { opacity: (busy || newPassword.length < 8 || newPassword !== confirmPassword) ? 0.5 : 1 }]}>
                  <LinearGradient colors={['#0a6bff', '#00b4ff']} start={{x:0,y:0}} end={{x:1,y:1}} style={authStyles.btnPInner}>
                    <Text style={authStyles.btnPText}>{busy ? "UPDATING…" : "SET NEW PASSWORD"}</Text>
                  </LinearGradient>
                  <LinearGradient colors={['rgba(255,255,255,0.14)', 'transparent']} style={StyleSheet.absoluteFill} />
                </View>
              </Pressable>
            </View>

          </Animated.View>
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
  );
}

function AuthScreen({
  email, password, onEmail, onPassword, onLogin, onGoogleAuth, busy,
  registerStep, setRegisterStep, registerName, setRegisterName,
  registerLastName, setRegisterLastName,
  registerOtp, setRegisterOtp,
  requestOtp, submitRegisterWithOtp, onForgot
}: {
  email: string; password: string; onEmail: (v: string) => void; onPassword: (v: string) => void;
  onLogin: () => void; onGoogleAuth: () => void; busy: boolean;
  registerStep: "none" | "form" | "otp"; setRegisterStep: (v: "none" | "form" | "otp") => void;
  registerName: string; setRegisterName: (v: string) => void;
  registerLastName: string; setRegisterLastName: (v: string) => void;
  registerOtp: string; setRegisterOtp: (v: string) => void;
  requestOtp: () => void; submitRegisterWithOtp: () => void;
  onForgot: () => void;
}) {
  const [authStep, setAuthStep] = useState<"splash" | "login" | "register" | "otp">("splash");
  const slideAnim = useRef(new Animated.Value(0)).current;
  const { width: SCREEN_WIDTH } = Dimensions.get("window");

  useEffect(() => {
    if (registerStep === "form" && authStep !== "register") setAuthStep("register");
    if (registerStep === "otp" && authStep !== "otp") setAuthStep("otp");
    if (registerStep === "none" && (authStep === "register" || authStep === "otp")) setAuthStep("login");
  }, [registerStep]);

  useEffect(() => {
    let target = 0;
    if (authStep === "login") target = 1;
    if (authStep === "register") target = 2;
    if (authStep === "otp") target = 3;

    Animated.timing(slideAnim, {
      toValue: -SCREEN_WIDTH * target,
      duration: 400,
      useNativeDriver: true,
    }).start();
  }, [authStep]);

  const handleModeSwitch = (mode: "login" | "register") => {
    setAuthStep(mode);
    setRegisterStep(mode === "login" ? "none" : "form");
    if (mode === "register") {
      setRegisterName(""); onEmail(""); onPassword(""); setRegisterOtp("");
    }
  };

  const screenStyle = { width: SCREEN_WIDTH, paddingHorizontal: 25, paddingVertical: 50, flex: 1 };

  return (
    <View style={StyleSheet.absoluteFill}>
      <LinearGradient colors={['rgba(255,255,255,0.06)', 'rgba(10,40,90,0.4)']} start={{x: 0, y: 0}} end={{x: 1, y: 1}} style={StyleSheet.absoluteFillObject} />
      
      {authStep !== "splash" && (
        <Pressable style={{ position: "absolute", top: 60, right: 30, zIndex: 10 }} onPress={() => handleModeSwitch(authStep === "login" ? "register" : "login")} hitSlop={15}>
          <Text style={authStyles.snav}>{authStep === "login" ? "Sign up" : "Sign in"}</Text>
        </Pressable>
      )}

      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : 'height'} style={{ flex: 1 }}>
        <ScrollView contentContainerStyle={{ flexGrow: 1 }} keyboardShouldPersistTaps="handled">
          <View style={{ flex: 1, width: SCREEN_WIDTH, overflow: 'hidden' }}>
            <Animated.View style={{ flex: 1, flexDirection: 'row', width: SCREEN_WIDTH * 4, transform: [{ translateX: slideAnim }] }}>

            {/* Splash */}
            <View style={screenStyle}>
              <View style={{ flex: 1, justifyContent: "center" }}>
                <View style={authStyles.badge}>
                  <View style={authStyles.bdot} />
                  <Text style={authStyles.btxt}>On-Device AI Protection</Text>
                </View>
                <View style={authStyles.brandRow}>
                  <HtmlSvgLogo size={36} />
                  <Text style={authStyles.brandName}>SafeMail X AI</Text>
                </View>
                <View style={authStyles.heroFrame}>
                  <Text style={authStyles.hl}>AI</Text>
                  <Text style={authStyles.hl}>Email</Text>
                  <GradientText text="Defence." style={[authStyles.hl, { fontFamily: 'CormorantGaramond_300Light_Italic' }]} colors={['#55d6ff', '#0a6bff']} />
                  <Text style={authStyles.hsub}>Triple Layer{'\n'}Engine.</Text>
                </View>
                <View style={authStyles.divl} />
                
                <Pressable onPress={() => handleModeSwitch("login")} disabled={busy}>
                  <View style={authStyles.btnP}>
                    <LinearGradient colors={['#0a6bff', '#00b4ff']} start={{x: 0, y: 0}} end={{x: 1, y: 1}} style={authStyles.btnPInner}>
                      <Text style={authStyles.btnPText}>GET STARTED</Text>
                    </LinearGradient>
                    <LinearGradient colors={['rgba(255,255,255,0.14)', 'transparent']} style={StyleSheet.absoluteFill} />
                  </View>
                </Pressable>
                <Pressable onPress={() => handleModeSwitch("login")} style={authStyles.btnS} disabled={busy}>
                  <Text style={authStyles.btnSText}>I already have an account</Text>
                </Pressable>
              </View>
            </View>

            {/* Login */}
            <View style={screenStyle}>
              <View style={{ flex: 1, justifyContent: "center", paddingTop: 40 }}>
                <View style={{ alignItems: "center", marginBottom: 20 }}>
                  <HtmlSvgLogo size={90} />
                </View>
                <Text style={authStyles.scTitle}>Sign In to</Text>
                <GradientText text="SafeMail X AI" style={{ fontFamily: 'CormorantGaramond_300Light_Italic', fontSize: 24, textAlign: 'center', marginBottom: 30, letterSpacing: 0.5 }} colors={['#55d6ff', '#0a6bff']} />
                
                <Text style={authStyles.flabel}>Email Address</Text>
                <View style={authStyles.fbox}>
                  <TextInput value={email} onChangeText={onEmail} placeholder="Enter your email" placeholderTextColor="rgba(255,255,255,0.28)" autoCapitalize="none" keyboardType="email-address" style={authStyles.finput} editable={!busy} />
                  <Text style={{ fontSize: 18, color: "rgba(0,180,255,0.5)" }}>✉</Text>
                </View>

                <Text style={authStyles.flabel}>Password</Text>
                <View style={authStyles.fbox}>
                  <TextInput value={password} onChangeText={onPassword} placeholder="Enter your password" placeholderTextColor="rgba(255,255,255,0.28)" secureTextEntry style={authStyles.finput} editable={!busy} />
                  <Text style={{ fontSize: 18, color: "rgba(0,180,255,0.5)" }}>◎</Text>
                </View>

                <Pressable style={authStyles.forgot} onPress={onForgot}>
                  <Text style={authStyles.forgotTxt}>Forgot password?</Text>
                </Pressable>

                <Pressable onPress={onLogin} disabled={busy}>
                  <View style={authStyles.btnP}>
                    <LinearGradient colors={['#0a6bff', '#00b4ff']} start={{x: 0, y: 0}} end={{x: 1, y: 1}} style={authStyles.btnPInner}>
                      <Text style={authStyles.btnPText}>SECURE SIGN IN</Text>
                    </LinearGradient>
                    <LinearGradient colors={['rgba(255,255,255,0.14)', 'transparent']} style={StyleSheet.absoluteFill} />
                  </View>
                </Pressable>

                <View style={authStyles.divOr}>
                  <View style={authStyles.divOrLine} />
                  <Text style={authStyles.divOrTxt}>or continue with</Text>
                  <View style={authStyles.divOrLine} />
                </View>

                <View style={authStyles.socRow}>
                  <Pressable onPress={onGoogleAuth} style={({pressed}) => [authStyles.socBtn, { opacity: pressed || busy ? 0.7 : 1 }]} disabled={busy}>
                    <GradientText text="G" style={{ fontSize: 18, fontWeight: '700' }} colors={['#ea4335', '#fbbc05', '#34a853', '#4285f4']} />
                    <Text style={authStyles.socBtnTxt}>Sign in with Google</Text>
                  </Pressable>
                </View>
              </View>
            </View>

            {/* Register */}
            <View style={screenStyle}>
              <View style={{ flex: 1, justifyContent: "center", paddingTop: 40 }}>
                <View style={{ alignItems: "center", marginBottom: 10 }}>
                  <HtmlSvgLogo size={80} />
                </View>
                <Text style={authStyles.scTitle}>Create Your</Text>
                <Text style={[authStyles.scTitle, { fontFamily: 'CormorantGaramond_600SemiBold', marginBottom: 20 }]}>Secure Account</Text>
                
                <View style={{ flexDirection: 'row', gap: 10 }}>
                  <View style={{ flex: 1 }}>
                    <Text style={authStyles.flabel}>First Name</Text>
                    <View style={authStyles.fbox}>
                      <TextInput value={registerName} onChangeText={setRegisterName} placeholder="First" placeholderTextColor="rgba(255,255,255,0.28)" style={authStyles.finput} editable={!busy} />
                    </View>
                  </View>
                  <View style={{ flex: 1 }}>
                    <Text style={authStyles.flabel}>Last Name</Text>
                    <View style={authStyles.fbox}>
                      <TextInput value={registerLastName} onChangeText={setRegisterLastName} placeholder="Last" placeholderTextColor="rgba(255,255,255,0.28)" style={authStyles.finput} editable={!busy} />
                    </View>
                  </View>
                </View>

                <Text style={authStyles.flabel}>Email Address</Text>
                <View style={authStyles.fbox}>
                  <TextInput value={email} onChangeText={onEmail} placeholder="Enter your email" placeholderTextColor="rgba(255,255,255,0.28)" autoCapitalize="none" keyboardType="email-address" style={authStyles.finput} editable={!busy} />
                  <Text style={{ fontSize: 18, color: "rgba(0,180,255,0.5)" }}>✉</Text>
                </View>

                <Text style={authStyles.flabel}>Password</Text>
                <View style={[authStyles.fbox, { marginBottom: 20 }]}>
                  <TextInput value={password} onChangeText={onPassword} placeholder="Enter your password" placeholderTextColor="rgba(255,255,255,0.28)" secureTextEntry style={authStyles.finput} editable={!busy} />
                  <Text style={{ fontSize: 18, color: "rgba(0,180,255,0.5)" }}>◎</Text>
                </View>

                <Pressable onPress={requestOtp} disabled={busy}>
                  <View style={authStyles.btnP}>
                    <LinearGradient colors={['#0a6bff', '#00b4ff']} start={{x: 0, y: 0}} end={{x: 1, y: 1}} style={authStyles.btnPInner}>
                      <Text style={authStyles.btnPText}>CONTINUE</Text>
                    </LinearGradient>
                    <LinearGradient colors={['rgba(255,255,255,0.14)', 'transparent']} style={StyleSheet.absoluteFill} />
                  </View>
                </Pressable>

                <View style={authStyles.divOr}>
                  <View style={authStyles.divOrLine} />
                  <Text style={authStyles.divOrTxt}>or sign up with</Text>
                  <View style={authStyles.divOrLine} />
                </View>

                <View style={authStyles.socRow}>
                  <Pressable onPress={onGoogleAuth} style={({pressed}) => [authStyles.socBtn, { opacity: pressed || busy ? 0.7 : 1 }]} disabled={busy}>
                    <GradientText text="G" style={{ fontSize: 18, fontWeight: '700' }} colors={['#ea4335', '#fbbc05', '#34a853', '#4285f4']} />
                    <Text style={authStyles.socBtnTxt}>Sign in with Google</Text>
                  </Pressable>
                </View>
              </View>
            </View>

            {/* OTP */}
            <View style={screenStyle}>
              <View style={{ flex: 1, justifyContent: "center", paddingTop: 40 }}>
                <View style={{ alignItems: "center", marginBottom: 20 }}>
                  <HtmlSvgLogo size={90} />
                </View>
                <Text style={authStyles.scTitle}>Verify Code</Text>
                <Text style={[authStyles.flabel, { textAlign: 'center', lineHeight: 18, marginBottom: 30, textTransform: 'none' }]}>
                  We sent a 6-digit registration code to{"\n"}<Text style={{ fontWeight: "700", color: "#fff", fontSize: 12 }}>{email}</Text>
                </Text>

                <Text style={authStyles.flabel}>Verification Code</Text>
                <View style={[authStyles.fbox, { marginBottom: 30 }]}>
                  <TextInput value={registerOtp} onChangeText={setRegisterOtp} placeholder="123456" maxLength={6} placeholderTextColor="rgba(255,255,255,0.28)" keyboardType="number-pad" style={[authStyles.finput, { fontSize: 24, letterSpacing: 10, textAlign: "center" }]} editable={!busy} />
                </View>

                <Pressable onPress={submitRegisterWithOtp} disabled={busy || registerOtp.length !== 6}>
                  <View style={[authStyles.btnP, { opacity: registerOtp.length !== 6 ? 0.5 : 1 }]}>
                    <LinearGradient colors={['#0a6bff', '#00b4ff']} start={{x: 0, y: 0}} end={{x: 1, y: 1}} style={authStyles.btnPInner}>
                      <Text style={authStyles.btnPText}>VERIFY & CREATE</Text>
                    </LinearGradient>
                    <LinearGradient colors={['rgba(255,255,255,0.14)', 'transparent']} style={StyleSheet.absoluteFill} />
                  </View>
                </Pressable>

                <View style={{ flexDirection: "row", justifyContent: "space-between", marginTop: 20 }}>
                  <Pressable onPress={() => setRegisterStep("form")} hitSlop={12}>
                    <Text style={{ color: C.frost4, fontSize: 13 }}>← Back</Text>
                  </Pressable>
                  <Pressable onPress={requestOtp} disabled={busy} hitSlop={12}>
                    <Text style={{ color: "#0a6bff", fontSize: 13, fontWeight: "600" }}>Resend Code</Text>
                  </Pressable>
                </View>
              </View>
            </View>

          </Animated.View>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
  );
}

// ─── Bottom Nav — exact Lovable layout ────────────────────────────────────────
function BottomNavBar({ active, onSwitch, bottomInset }: { active: Tab; onSwitch: (t: Tab) => void; bottomInset: number }) {
  // Float shield button pulse
  const glow = useRef(new Animated.Value(0.55)).current;
  useEffect(() => {
    Animated.loop(Animated.sequence([
      Animated.timing(glow, { toValue: 0.9, duration: 1800, useNativeDriver: true }),
      Animated.timing(glow, { toValue: 0.55, duration: 1800, useNativeDriver: true }),
    ])).start();
  }, []);

  return (
    <LinearGradient
      colors={["#0a0f1c", "#06080f"]}
      style={[S.navContainer, { paddingBottom: bottomInset + 12 }]}
    >
      {/* Left items */}
      <NavItem label="Home" icon="home-outline" active={active === "dashboard"} onPress={() => onSwitch("dashboard")} />
      <NavItem label="Scans" icon="list-outline" active={active === "scans"} onPress={() => onSwitch("scans")} />

      {/* Center floating shield button — lifts above nav bar */}
      <View style={{ alignItems: "center", flex: 1 }}>
        <Pressable onPress={() => onSwitch("new")}>
          <Animated.View style={[S.navShield, { shadowOpacity: glow, marginBottom: bottomInset > 0 ? 8 : 10 }]}>
            <View style={{ width: 42, height: 42, borderRadius: 21, overflow: "hidden", backgroundColor: "#000", alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "rgba(0, 240, 255, 0.2)" }}>
              <Image source={require('./assets/custom-shield.png')} style={{ width: 44, height: 44, resizeMode: 'cover' }} />
            </View>
          </Animated.View>
        </Pressable>
      </View>

      {/* Right items */}
      <NavItem label="Reports" icon="document-text-outline" active={active === "reports"} onPress={() => onSwitch("reports")} />
      <NavItem label="Settings" icon="settings-outline" active={active === "settings"} onPress={() => onSwitch("settings")} />
    </LinearGradient>
  );
}

function NavItem({ label, icon, active, onPress }: {
  label: string; icon: keyof typeof Ionicons.glyphMap; active: boolean; onPress: () => void;
}) {
  return (
    <Pressable onPress={onPress} style={S.navItem}>
      <Ionicons name={icon} size={20} color={active ? C.violetGlow : C.frost4} />
      <Text style={[S.navLabel, active && { color: C.violetGlow }]}>{label.toUpperCase()}</Text>
    </Pressable>
  );
}

// ─── Dashboard Screen ─────────────────────────────────────────────────────────
function formatLastSync(timeStr: string | null) {
  if (!timeStr) return "Never synced";
  try {
    const date = new Date(timeStr);
    const time = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const day = date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    return `Last Sync: ${time}, ${day}`;
  } catch {
    return `Last Sync: ${timeStr}`;
  }
}

// ─── Dashboard Screen ─────────────────────────────────────────────────────────
function DashboardScreen({ 
  health, 
  stats, 
  scans, 
  googleBackupUser, 
  googleBackupSyncTime,
  syncingBackup,
  onConnectGoogle, 
  onDisconnectGoogle,
  onSyncGoogle,
  onOpenReport,
}: {
  health: Health | null;
  stats: { safe: number; suspicious: number; phishing: number };
  scans: ScanSummary[];
  googleBackupUser: string | null;
  googleBackupSyncTime: string | null;
  syncingBackup: boolean;
  onConnectGoogle: () => void;
  onDisconnectGoogle: () => void;
  onSyncGoogle: () => void;
  onOpenReport: (id: string, kind: "pdf" | "json") => void;
}) {
  return (
    <View style={{ gap: 0, paddingBottom: 20 }}>
      <SafeMailEngineCore stats={stats} />
      <SecurityBulletin />
      <ThreatMatrix scans={scans} />
      <LiveIntakeStream scans={scans} />
    </View>
  );
}

// ─── SafeMail Engine Core ──────────────────────────────────────────────────────
function SafeMailEngineCore({ stats }: { stats: { safe: number; suspicious: number; phishing: number } }) {
  const bootScale = useRef(new Animated.Value(0.9)).current;
  const bootOpacity = useRef(new Animated.Value(0)).current;
  const pulseAnim = useRef(new Animated.Value(1)).current;
  const ringRotate1 = useRef(new Animated.Value(0)).current;
  const ringRotate2 = useRef(new Animated.Value(0)).current;
  const ringRotate3 = useRef(new Animated.Value(0)).current;
  const scoreAnim = useRef(new Animated.Value(0)).current;
  const [displayScore, setDisplayScore] = useState(0);

  const totalScans = stats.safe + stats.suspicious + stats.phishing;
  const score = totalScans === 0 ? 100 : Math.max(0, Math.round(100 - (((stats.phishing + 0.4 * stats.suspicious) / totalScans) * 100)));
  const coreColor = stats.phishing > 0 ? C.rose : stats.suspicious > 0 ? C.gold : "#00f3ff";

  useEffect(() => {
    Animated.parallel([
      Animated.timing(bootScale, { toValue: 1, duration: 800, useNativeDriver: true }),
      Animated.timing(bootOpacity, { toValue: 1, duration: 800, useNativeDriver: true }),
    ]).start();

    scoreAnim.addListener(({ value }) => setDisplayScore(Math.round(value)));
    Animated.timing(scoreAnim, { toValue: score, duration: 1500, useNativeDriver: false }).start();

    Animated.loop(Animated.sequence([
      Animated.timing(pulseAnim, { toValue: 1.02, duration: 2500, useNativeDriver: true }),
      Animated.timing(pulseAnim, { toValue: 0.98, duration: 2500, useNativeDriver: true }),
    ])).start();

    Animated.loop(Animated.timing(ringRotate1, { toValue: 1, duration: 12000, useNativeDriver: true })).start();
    Animated.loop(Animated.timing(ringRotate2, { toValue: 1, duration: 18000, useNativeDriver: true })).start();
    Animated.loop(Animated.timing(ringRotate3, { toValue: 1, duration: 24000, useNativeDriver: true })).start();

    return () => scoreAnim.removeAllListeners();
  }, [score]);

  const spin1 = ringRotate1.interpolate({ inputRange: [0, 1], outputRange: ["0deg", "360deg"] });
  const spin2 = ringRotate2.interpolate({ inputRange: [0, 1], outputRange: ["360deg", "0deg"] });
  const spin3 = ringRotate3.interpolate({ inputRange: [0, 1], outputRange: ["0deg", "-360deg"] });

  // Calculating widths for the real-time proportion bar
  const safePercent = totalScans === 0 ? 0 : (stats.safe / totalScans) * 100;
  const suspPercent = totalScans === 0 ? 0 : (stats.suspicious / totalScans) * 100;
  const phishPercent = totalScans === 0 ? 0 : (stats.phishing / totalScans) * 100;

  return (
    <Animated.View style={{ alignItems: "center", justifyContent: "center", marginVertical: 16, opacity: bootOpacity, transform: [{ scale: bootScale }] }}>
      <TmCard style={{ width: "100%", paddingVertical: 24, paddingHorizontal: 16, alignItems: "center", backgroundColor: "rgba(5,5,5,0.4)", borderColor: "rgba(0,243,255,0.15)" }}>
        <View style={{ flexDirection: "row", width: "100%", justifyContent: "space-between", alignItems: "center", paddingHorizontal: 8, marginBottom: 32 }}>
          <View>
            <Text style={{ color: "#fff", fontSize: 16, fontWeight: "700" }}>SafeMail Engine Core</Text>
            <Text style={{ color: C.frost4, fontSize: 10 }}>Continuous real-time threat intelligence</Text>
          </View>
        </View>

        <View style={{ alignItems: "center", justifyContent: "center", width: 220, height: 220, marginBottom: 10 }}>
          {/* Deep Glow Base */}
          <Animated.View style={{ position: "absolute", width: 140, height: 140, borderRadius: 70, backgroundColor: `${coreColor}20`, transform: [{ scale: pulseAnim }], shadowColor: coreColor, shadowRadius: 50, shadowOpacity: 0.8, elevation: 15 }} />
          
          {/* Orbital Ring 1 - Fast Clockwise, tilted 65° */}
          <Animated.View style={{ position: "absolute", width: 210, height: 210, borderRadius: 105, borderWidth: 1, borderColor: `${coreColor}15`, borderTopWidth: 3, borderTopColor: coreColor, transform: [{ rotateX: "65deg" }, { rotate: spin1 }] }} />
          
          {/* Orbital Ring 2 - Medium Counter-Clockwise, tilted 75° + 25° Y */}
          <Animated.View style={{ position: "absolute", width: 186, height: 186, borderRadius: 93, borderWidth: 2, borderColor: `${coreColor}25`, borderBottomColor: "rgba(255,255,255,0.8)", borderLeftColor: C.violetGlow, transform: [{ rotateX: "75deg" }, { rotateY: "25deg" }, { rotate: spin2 }] }} />
          
          {/* Orbital Ring 3 - Slow Reverse, tilted 50° + -30° Y */}
          <Animated.View style={{ position: "absolute", width: 160, height: 160, borderRadius: 80, borderWidth: 1, borderColor: "rgba(255,255,255,0.1)", borderRightWidth: 4, borderRightColor: `${coreColor}90`, transform: [{ rotateX: "50deg" }, { rotateY: "-30deg" }, { rotate: spin3 }] }} />

          {/* Central Hub with Breathing Pulse */}
          <Animated.View style={{ width: 124, height: 124, borderRadius: 62, backgroundColor: "rgba(6,8,15,0.85)", borderWidth: 2, borderColor: `${coreColor}99`, alignItems: "center", justifyContent: "center", transform: [{ scale: pulseAnim }], shadowColor: "#000", shadowOffset: { width: 0, height: 10 }, shadowOpacity: 0.6, shadowRadius: 10 }}>
            <Text style={{ color: C.frost2, fontSize: 10, fontWeight: "600", marginBottom: -4, letterSpacing: 0.5 }}>SECURITY SCORE</Text>
            <Text style={{ color: "#fff", fontSize: 46, fontWeight: "900", letterSpacing: -1.5, textShadowColor: coreColor, textShadowOffset: { width: 0, height: 0 }, textShadowRadius: 15 }}>{displayScore}</Text>
          </Animated.View>
        </View>

        {/* Dynamic Neon Gradient Stat Bar */}
        <View style={{ width: "90%", marginTop: 24, marginBottom: 12 }}>
          <View style={{ flexDirection: "row", justifyContent: "space-between", marginBottom: 6 }}>
             <Text style={{ color: C.frost4, fontSize: 9, fontWeight: "700", letterSpacing: 1 }}>THREAT PROPORTIONS</Text>
             <Text style={{ color: C.frost4, fontSize: 9, fontWeight: "700" }}>{totalScans} TOTAL SCANS</Text>
          </View>
          <View style={{ height: 6, width: "100%", backgroundColor: "rgba(255,255,255,0.05)", borderRadius: 3, overflow: "hidden", flexDirection: "row" }}>
            {totalScans > 0 ? (
              <>
                {safePercent > 0 && (
                  <View style={{ width: `${safePercent}%`, height: "100%" }}>
                    <LinearGradient colors={["#00f3ff", "rgba(0,243,255,0.6)"]} style={{ flex: 1 }} start={{x: 0, y: 0}} end={{x: 1, y: 0}} />
                  </View>
                )}
                {suspPercent > 0 && (
                  <View style={{ width: `${suspPercent}%`, height: "100%" }}>
                    <LinearGradient colors={[C.gold, "rgba(232,168,76,0.6)"]} style={{ flex: 1 }} start={{x: 0, y: 0}} end={{x: 1, y: 0}} />
                  </View>
                )}
                {phishPercent > 0 && (
                  <View style={{ width: `${phishPercent}%`, height: "100%" }}>
                    <LinearGradient colors={[C.rose, "rgba(224,138,174,0.6)"]} style={{ flex: 1 }} start={{x: 0, y: 0}} end={{x: 1, y: 0}} />
                  </View>
                )}
              </>
            ) : (
              <View style={{ width: "100%", height: "100%", backgroundColor: "rgba(255,255,255,0.1)" }} />
            )}
          </View>
        </View>

        <View style={{ flexDirection: "row", width: "100%", justifyContent: "space-between", paddingHorizontal: 16, marginTop: 16 }}>
          <StatBox label="Scanned" value={totalScans} color="#00f3ff" delay={100} />
          <StatBox label="Safe" value={stats.safe} color="#00f3ff" delay={200} />
          <StatBox label="Phishing" value={stats.phishing} color={C.rose} delay={300} />
        </View>
      </TmCard>
    </Animated.View>
  );
}

function StatBox({ label, value, color, delay }: { label: string; value: number; color: string; delay: number }) {
  const slideAnim = useRef(new Animated.Value(20)).current;
  const opacAnim = useRef(new Animated.Value(0)).current;
  const scoreAnim = useRef(new Animated.Value(0)).current;
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    Animated.sequence([
      Animated.delay(delay),
      Animated.parallel([
        Animated.timing(slideAnim, { toValue: 0, duration: 400, useNativeDriver: true }),
        Animated.timing(opacAnim, { toValue: 1, duration: 400, useNativeDriver: true })
      ])
    ]).start();

    scoreAnim.addListener(({ value: v }) => setDisplayValue(Math.round(v)));
    Animated.timing(scoreAnim, { toValue: value, duration: 1500, useNativeDriver: false }).start();
    return () => scoreAnim.removeAllListeners();
  }, [delay, value]);

  return (
    <Animated.View style={{ alignItems: "center", opacity: opacAnim, transform: [{ translateY: slideAnim }] }}>
      <Text style={{ color: C.frost4, fontSize: 10, marginBottom: 4, letterSpacing: 0.5, fontWeight: "600", textTransform: "uppercase" }}>{label}</Text>
      <Text style={{ color, fontSize: 24, fontWeight: "800", letterSpacing: 0.5, textShadowColor: `${color}80`, textShadowOffset: { width: 0, height: 0 }, textShadowRadius: 8 }}>{displayValue}</Text>
    </Animated.View>
  );
}

// ─── Threat Matrix ────────────────────────────────────────────────────────────
function ThreatMatrix({ scans }: { scans: ScanSummary[] }) {
  const bootOpacity = useRef(new Animated.Value(0)).current;
  const slideAnim = useRef(new Animated.Value(20)).current;
  useEffect(() => {
    Animated.sequence([
      Animated.delay(400),
      Animated.parallel([
        Animated.timing(slideAnim, { toValue: 0, duration: 500, useNativeDriver: true }),
        Animated.timing(bootOpacity, { toValue: 1, duration: 500, useNativeDriver: true }),
      ])
    ]).start();
  }, []);

  const points = scans.length === 0 
    ? Array.from({ length: 20 }, (_, i) => ({ x: 10 + Math.random()*60, y: 1 + Math.random()*10 }))
    : scans.slice(0, 30).map((s, i) => ({ x: 5 + (i * 2.5) % 75, y: (s.final_score || 0) * 10 + 1 }));

  return (
    <Animated.View style={{ opacity: bootOpacity, transform: [{ translateY: slideAnim }], marginBottom: 16 }}>
      <TmCard style={{ padding: 16, backgroundColor: "rgba(5,5,5,0.4)", borderColor: "rgba(255,255,255,0.1)" }}>
        <View style={{ flexDirection: "row", justifyContent: "space-between", marginBottom: 16 }}>
          <View>
            <Text style={{ color: "#fff", fontSize: 15, fontWeight: "700" }}>Threat Matrix</Text>
            <Text style={{ color: C.frost4, fontSize: 11 }}>Calculated by risk level</Text>
          </View>
        </View>

        <View style={{ height: 160, position: "relative", borderLeftWidth: 1, borderBottomWidth: 1, borderColor: "rgba(255,255,255,0.2)", marginLeft: 20, marginBottom: 20 }}>
          {[12, 10, 8, 6, 4, 2, 0].map((v, i) => (
            <Text key={`y${i}`} style={{ position: "absolute", left: -20, top: i * (160/6) - 6, color: C.frost4, fontSize: 9 }}>{v}</Text>
          ))}
          {[1,2,3,4,5,6].map(i => (
            <View key={`hl${i}`} style={{ position: "absolute", top: i * (160/6), width: "100%", height: 1, backgroundColor: "rgba(255,255,255,0.05)" }} />
          ))}
          {[1,2,3,4,5,6,7].map(i => (
            <View key={`vl${i}`} style={{ position: "absolute", left: (i * (100/8) + "%") as any, height: "100%", width: 1, backgroundColor: "rgba(255,255,255,0.05)" }} />
          ))}
          <View style={{ flexDirection: "row", position: "absolute", bottom: -20, left: 0, right: 0, justifyContent: "space-between", paddingHorizontal: 5 }}>
            {[0, 10, 20, 30, 40, 50, 60, 70, 80].map(v => (
              <Text key={`x${v}`} style={{ color: C.frost4, fontSize: 9 }}>{v}</Text>
            ))}
          </View>

          {points.map((p, i) => {
            const isThreat = p.y > 6;
            const color = isThreat ? C.rose : "#00f3ff";
            return <MatrixDot key={i} x={p.x} y={p.y} color={color} delay={i * 50} />;
          })}
        </View>
        <Text style={{ position: "absolute", left: -10, top: 110, transform: [{ rotate: "-90deg" }], color: C.frost4, fontSize: 9 }}>Risk Level</Text>
        <Text style={{ position: "absolute", bottom: 4, left: "40%", color: C.frost4, fontSize: 9 }}>Calculated level</Text>
      </TmCard>
    </Animated.View>
  );
}

function MatrixDot({ x, y, color, delay }: { x: number; y: number; color: string; delay: number }) {
  const scale = useRef(new Animated.Value(0)).current;
  const opac = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.sequence([
      Animated.delay(600 + delay),
      Animated.parallel([
        Animated.spring(scale, { toValue: 1, useNativeDriver: true }),
        Animated.timing(opac, { toValue: 1, duration: 200, useNativeDriver: true })
      ])
    ]).start();
  }, [delay]);
  return (
    <Animated.View style={{
      position: "absolute", left: `${x}%`, bottom: `${(y/12)*100}%`,
      width: 8, height: 8, borderRadius: 4, backgroundColor: color,
      shadowColor: color, shadowRadius: 6, shadowOpacity: 0.8,
      opacity: opac, transform: [{ scale }]
    }} />
  );
}

// ─── Live Intake Stream ───────────────────────────────────────────────────────
function LiveIntakeStream({ scans }: { scans: ScanSummary[] }) {
  const bootOpacity = useRef(new Animated.Value(0)).current;
  const slideAnim = useRef(new Animated.Value(20)).current;
  useEffect(() => {
    Animated.sequence([
      Animated.delay(800),
      Animated.parallel([
        Animated.timing(slideAnim, { toValue: 0, duration: 500, useNativeDriver: true }),
        Animated.timing(bootOpacity, { toValue: 1, duration: 500, useNativeDriver: true }),
      ])
    ]).start();
  }, []);

  if (scans.length === 0) {
    return (
      <Animated.View style={{ opacity: bootOpacity, transform: [{ translateY: slideAnim }], marginBottom: 20 }}>
        <TmCard style={{ padding: 16, backgroundColor: "rgba(5,5,5,0.4)", borderColor: "rgba(255,255,255,0.1)" }}>
          <View style={{ flexDirection: "row", justifyContent: "space-between", marginBottom: 12 }}>
            <View>
              <Text style={{ color: "#fff", fontSize: 15, fontWeight: "700" }}>Live Intake Stream</Text>
              <Text style={{ color: C.frost4, fontSize: 11 }}>Recently scanned emails</Text>
            </View>
          </View>
          <Text style={{ color: C.frost4, fontSize: 12, textAlign: "center", paddingVertical: 20 }}>No scans yet. Use the scanner to analyze your first email.</Text>
        </TmCard>
      </Animated.View>
    );
  }

  const displayScans = scans.slice(0, 5);

  return (
    <Animated.View style={{ opacity: bootOpacity, transform: [{ translateY: slideAnim }], marginBottom: 20 }}>
      <TmCard style={{ padding: 16, backgroundColor: "rgba(5,5,5,0.4)", borderColor: "rgba(255,255,255,0.1)" }}>
        <View style={{ flexDirection: "row", justifyContent: "space-between", marginBottom: 12 }}>
          <View>
            <Text style={{ color: "#fff", fontSize: 15, fontWeight: "700" }}>Live Intake Stream</Text>
            <Text style={{ color: C.frost4, fontSize: 11 }}>Recently scanned emails</Text>
          </View>
        </View>

        <View>
          {displayScans.map((s, i) => (
            <IntakeRow key={s.id || i} scan={s} index={i} />
          ))}
        </View>
      </TmCard>
    </Animated.View>
  );
}

function IntakeRow({ scan, index }: { scan: any; index: number }) {
  const isThreat = scan.final_label !== "legitimate";
  const tagColor = isThreat ? C.rose : "#00f3ff";
  const tagBg = isThreat ? "rgba(255,0,60,0.15)" : "rgba(0,243,255,0.15)";
  const tagText = isThreat ? "Threat" : "Safe";
  
  const slideAnim = useRef(new Animated.Value(20)).current;
  const opacAnim = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.sequence([
      Animated.delay(1000 + index * 100),
      Animated.parallel([
        Animated.timing(slideAnim, { toValue: 0, duration: 300, useNativeDriver: true }),
        Animated.timing(opacAnim, { toValue: 1, duration: 300, useNativeDriver: true })
      ])
    ]).start();
  }, [index]);

  return (
    <Animated.View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: "rgba(255,255,255,0.05)", opacity: opacAnim, transform: [{ translateY: slideAnim }] }}>
      <View style={{ flex: 1, borderLeftWidth: 2, borderLeftColor: tagColor, paddingLeft: 10 }}>
        <Text style={{ color: "#fff", fontSize: 13, fontWeight: "600", marginBottom: 2 }}>{scan.sender || "Unknown Sender"}</Text>
        <Text style={{ color: C.frost4, fontSize: 11 }} numberOfLines={1}>{scan.subject}</Text>
      </View>
      <View style={{ alignItems: "flex-end" }}>
        <Text style={{ color: C.frost4, fontSize: 10, marginBottom: 4 }}>{scan.created_at ? new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ""}</Text>
        <View style={{ backgroundColor: tagBg, paddingHorizontal: 6, paddingVertical: 2, borderRadius: 4 }}>
          <Text style={{ color: tagColor, fontSize: 9, fontWeight: "700" }}>{tagText}</Text>
        </View>
      </View>
    </Animated.View>
  );
}



// ─── Scans list screen ────────────────────────────────────────────────────────
function ScansScreen({ scans }: { scans: ScanSummary[] }) {
  if (scans.length === 0) {
    return (
      <TmCard style={{ alignItems: "center", padding: 30 }}>
        <Ionicons name="mail-open-outline" size={32} color={C.frost4} />
        <Text style={[S.muted, { marginTop: 10, textAlign: "center" }]}>No scans yet. Run a manual scan or connect Gmail.</Text>
      </TmCard>
    );
  }
  return (
    <View style={{ gap: 10 }}>
      {scans.map(s => <ScanCard key={s.id} scan={s} />)}
    </View>
  );
}

// ─── Scan card ────────────────────────────────────────────────────────────────
function ScanCard({ scan }: { scan: ScanSummary }) {
  const col = verdictColor(scan.final_label);
  return (
    <TmCard>
      <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
        <Text style={[S.frost, { fontSize: 13, fontWeight: "600", flex: 1 }]} numberOfLines={1}>{scan.subject}</Text>
        <View style={{
          borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3,
          backgroundColor: col + "20", borderWidth: 1, borderColor: col + "55",
        }}>
          <Text style={{ fontSize: 9, fontWeight: "800", color: col, letterSpacing: 0.5 }}>
            {scan.final_label.toUpperCase()}
          </Text>
        </View>
      </View>
      <Text style={[S.muted, { marginTop: 4 }]}>{scan.sender}</Text>
      {/* Score bar */}
      <View style={{ height: 4, backgroundColor: C.ink4, borderRadius: 999, marginTop: 10, overflow: "hidden" }}>
        <LinearGradient
          colors={[col + "80", col]}
          start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }}
          style={{ height: 4, borderRadius: 999, width: `${Math.round(scan.final_score * 100)}%` as any }}
        />
      </View>
      <Text style={[S.muted, { marginTop: 6 }]}>
        {Math.round(scan.final_score * 100)}/100 · Qwen {scan.llm_used ? "✓" : "–"}
      </Text>
    </TmCard>
  );
}

function SecurityBulletin() {
  const [items, setItems] = useState<{ title: string; link: string }[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const fadeAnim = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    fetchThreatBulletin().then(res => {
      if (res.length > 0) setItems(res);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (items.length <= 1) return;
    const interval = setInterval(() => {
      Animated.sequence([
        Animated.timing(fadeAnim, { toValue: 0, duration: 300, useNativeDriver: true }),
        Animated.timing(fadeAnim, { toValue: 1, duration: 300, useNativeDriver: true })
      ]).start();
      setTimeout(() => setCurrentIndex(prev => (prev + 1) % items.length), 300);
    }, 6000);
    return () => clearInterval(interval);
  }, [items, fadeAnim]);

  if (items.length === 0) return null;
  const currentItem = items[currentIndex];

  return (
    <Pressable onPress={() => currentItem.link ? Linking.openURL(currentItem.link) : null}>
      <TmCard style={{ padding: 16, marginTop: 4 }}>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 12 }}>
          <View style={{ width: 36, height: 36, borderRadius: 18, backgroundColor: "rgba(255,100,100,0.1)", alignItems: "center", justifyContent: "center" }}>
            <Ionicons name="megaphone" size={18} color="#ff6b6b" />
          </View>
          <Animated.View style={{ flex: 1, opacity: fadeAnim }}>
            <Text style={{ fontSize: 11, fontWeight: "700", color: "#ff6b6b", marginBottom: 2 }}>SECURITY BULLETIN</Text>
            <Text style={{ fontSize: 13, color: C.frost, lineHeight: 18 }}>{currentItem.title}</Text>
          </Animated.View>
        </View>
      </TmCard>
    </Pressable>
  );
}

// ─── Unified Scan Screen ─────────────────────────────────────────────────────────
function UnifiedScanScreen({
  gmailState, busy: appBusy, onConnectGmail, onRefreshGmail, onSetupGmailLabels, onRunGmailScan,
  smsText, setSmsText, smsSender, setSmsSender,
  urlText, setUrlText,
  manualText, setManualText, onSubmitManual, refreshApp, scrollViewRef, onShowToast
}: {
  gmailState: string; busy: boolean;
  onConnectGmail: () => void; onRefreshGmail: () => void;
  onSetupGmailLabels: () => void; onRunGmailScan: () => void;
  smsText: string; setSmsText: (v: string) => void;
  smsSender: string; setSmsSender: (v: string) => void;
  urlText: string; setUrlText: (v: string) => void;
  manualText: string; setManualText: (v: string) => void;
  onSubmitManual: () => void;
  refreshApp: () => Promise<void>;
  scrollViewRef: React.RefObject<ScrollView | null>;
  onShowToast: (msg: string, type?: "error" | "success") => void;
}) {
  const [mode, setMode] = useState<"email" | "sms" | "text" | "url">("email");
  const [showInfo, setShowInfo] = useState(false);
  const [localBusy, setLocalBusy] = useState(false);
  const [inlineResult, setInlineResult] = useState<InstantScanResult | null>(null);
  const [feedbackChoice, setFeedbackChoice] = useState<"correct" | "false_positive" | "false_negative" | null>(null);
  const [feedbackBusy, setFeedbackBusy] = useState<"correct" | "false_positive" | "false_negative" | null>(null);
  const resultRef = useRef<View>(null);

  useEffect(() => {
    setInlineResult(null);
    setFeedbackChoice(null);
    setFeedbackBusy(null);
  }, [mode]);

  // Auto-scroll to results when a scan completes
  useEffect(() => {
    if (inlineResult && resultRef.current && scrollViewRef?.current) {
      setTimeout(() => {
        resultRef.current?.measureLayout(
          scrollViewRef.current as any,
          (_x: number, y: number) => {
            scrollViewRef.current?.scrollTo({ y: Math.max(0, y - 20), animated: true });
          },
          () => {} // onFail — do nothing
        );
      }, 150); // small delay for render to complete
    }
  }, [inlineResult]);
  
  const connected = gmailState.toLowerCase() !== "not connected" && gmailState.toLowerCase() !== "sign in required";
  const hasLabels = gmailState.toLowerCase().includes("labels ready");
  const busy = appBusy || localBusy;

  async function handleSmsScan() {
    if (!smsText.trim()) {
      onShowToast("Your SMS box is empty. Please paste a message to scan.");
      return;
    }
    setLocalBusy(true); setInlineResult(null);
    setFeedbackChoice(null);
    try {
      const res = await scanSms(smsText.trim(), smsSender.trim());
      setInlineResult(res); await refreshApp();
    } catch (e: any) { onShowToast(e.message || "SMS scan failed"); }
    finally { setLocalBusy(false); }
  }

  async function handleUrlScan() {
    if (!urlText.trim()) {
      onShowToast("Your URL box is empty. Please paste a URL to scan.");
      return;
    }
    setLocalBusy(true); setInlineResult(null);
    setFeedbackChoice(null);
    try {
      const res = await scanUrl(urlText.trim());
      setInlineResult(res); await refreshApp();
    } catch (e: any) { onShowToast(e.message || "URL scan failed"); }
    finally { setLocalBusy(false); }
  }

  async function handleFileScan() {
    const r = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true, multiple: false,
      type: [
        "text/plain",
        "text/html",
        "message/rfc822",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
      ] });
    if (r.canceled || !r.assets[0]) return;
    setLocalBusy(true); setInlineResult(null);
    setFeedbackChoice(null);
    try {
      const a = r.assets[0];
      const res = await scanInstantFile({ uri: a.uri, name: a.name, mimeType: a.mimeType });
      setInlineResult(res); await refreshApp();
    } catch (e: any) { onShowToast(e.message || "Upload failed"); }
    finally { setLocalBusy(false); }
  }

  async function handleScreenshotScan() {
    const r = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true, multiple: false, type: "image/*" });
    if (r.canceled || !r.assets[0]) return;
    setLocalBusy(true); setInlineResult(null);
    setFeedbackChoice(null);
    try {
      const a = r.assets[0];
      const res = await scanInstantFile({ uri: a.uri, name: a.name, mimeType: a.mimeType });
      setInlineResult(res); await refreshApp();
    } catch (e: any) { onShowToast(e.message || "Screenshot scan failed"); }
    finally { setLocalBusy(false); }
  }

  async function handleInlineFeedback(choice: "correct" | "false_positive" | "false_negative") {
    if (!inlineResult?.scan_id) return;
    setFeedbackBusy(choice);
    try {
      await submitScanFeedback(inlineResult.scan_id, choice);
      setFeedbackChoice(choice);
      onShowToast("Feedback saved — thanks for tuning!", "success");
    } catch (e: any) {
      onShowToast(e.message || "Could not save scan feedback.");
    } finally {
      setFeedbackBusy(null);
    }
  }

  return (
    <View style={{ flex: 1, gap: 14 }}>
      {/* Mode Selector */}
      <View style={S.modeRow}>
        <Pressable onPress={() => setMode("email")} style={[S.modeBtn, mode === "email" && { backgroundColor: "rgba(138,143,240,0.15)" }]}>
          <Text style={[S.modeBtnText, mode === "email" && { color: C.violetGlow }]}>Email</Text>
        </Pressable>
        <Pressable onPress={() => setMode("sms")} style={[S.modeBtn, mode === "sms" && { backgroundColor: "rgba(138,143,240,0.15)" }]}>
          <Text style={[S.modeBtnText, mode === "sms" && { color: C.violetGlow }]}>SMS</Text>
        </Pressable>
        <Pressable onPress={() => setMode("text")} style={[S.modeBtn, mode === "text" && { backgroundColor: "rgba(138,143,240,0.15)" }]}>
          <Text style={[S.modeBtnText, mode === "text" && { color: C.violetGlow }]}>Text / File</Text>
        </Pressable>
        <Pressable onPress={() => setMode("url")} style={[S.modeBtn, mode === "url" && { backgroundColor: "rgba(138,143,240,0.15)" }]}>
          <Text style={[S.modeBtnText, mode === "url" && { color: C.violetGlow }]}>URL</Text>
        </Pressable>
      </View>

      {mode === "email" && (
        <TmCard style={{ padding: 24, gap: 16 }}>
          <View style={{ flexDirection: "row", alignItems: "center", justifyContent: "space-between" }}>
            <View style={{ flexDirection: "row", alignItems: "center", gap: 12 }}>
              <View style={{ width: 36, height: 36, borderRadius: 18, backgroundColor: connected ? "rgba(111,217,184,0.15)" : "rgba(255,255,255,0.05)", alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: connected ? "rgba(111,217,184,0.3)" : "rgba(255,255,255,0.1)" }}>
                <Ionicons name={connected ? "checkmark" : "logo-google"} size={18} color={connected ? C.emerald : C.frost} />
              </View>
              <View>
                <Text style={{ fontSize: 14, fontWeight: "600", color: C.frost }}>1. Connect Account</Text>
                <Text style={{ fontSize: 10, color: connected ? C.emerald : C.frost4, marginTop: 2 }}>{connected ? "Connected" : "Requires sign in"}</Text>
              </View>
            </View>
            {!connected ? (
              <Pressable onPress={onConnectGmail} style={{ paddingHorizontal: 12, paddingVertical: 6, backgroundColor: C.violet, borderRadius: 8 }}>
                <Text style={{ fontSize: 11, fontWeight: "600", color: "#fff" }}>Connect</Text>
              </Pressable>
            ) : (
              <View style={{ flexDirection: "row", gap: 4, alignItems: "center" }}>
                <Pressable onPress={onRefreshGmail} style={{ padding: 8 }}>
                  <Ionicons name="refresh" size={18} color={C.frost3} />
                </Pressable>
                <Pressable onPress={onConnectGmail} style={{ paddingHorizontal: 12, paddingVertical: 6, backgroundColor: "rgba(255,255,255,0.1)", borderRadius: 8, borderWidth: 1, borderColor: "rgba(255,255,255,0.2)" }}>
                  <Text style={{ fontSize: 11, fontWeight: "600", color: C.frost }}>Switch</Text>
                </Pressable>
              </View>
            )}
          </View>

          <View style={{ flexDirection: "row", alignItems: "center", justifyContent: "space-between", opacity: connected ? 1 : 0.4 }}>
            <View style={{ flexDirection: "row", alignItems: "center", gap: 12 }}>
              <View style={{ width: 36, height: 36, borderRadius: 18, backgroundColor: hasLabels ? "rgba(111,217,184,0.15)" : "rgba(255,255,255,0.05)", alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: hasLabels ? "rgba(111,217,184,0.3)" : "rgba(255,255,255,0.1)" }}>
                <Ionicons name={hasLabels ? "checkmark" : "pricetag-outline"} size={18} color={hasLabels ? C.emerald : C.frost} />
              </View>
              <View>
                <Text style={{ fontSize: 14, fontWeight: "600", color: C.frost }}>2. Initialize Labels</Text>
                <Text style={{ fontSize: 10, color: hasLabels ? C.emerald : C.frost4, marginTop: 2 }}>{hasLabels ? "Ready" : "Pending"}</Text>
              </View>
            </View>
            {connected && !hasLabels && (
              <Pressable onPress={onSetupGmailLabels} style={{ paddingHorizontal: 12, paddingVertical: 6, backgroundColor: "rgba(255,255,255,0.1)", borderRadius: 8, borderWidth: 1, borderColor: "rgba(255,255,255,0.2)" }}>
                <Text style={{ fontSize: 11, fontWeight: "600", color: C.frost }}>Setup</Text>
              </Pressable>
            )}
          </View>

          {connected && hasLabels && (
            <View style={{ paddingTop: 16, borderTopWidth: 1, borderTopColor: C.line }}>
              <TmPrimaryBtn label={busy ? "Scanning Inbox..." : "Run Inbox Scan"} onPress={onRunGmailScan} disabled={busy} icon="shield-checkmark" />
            </View>
          )}
        </TmCard>
      )}

      {mode === "sms" && (
        <TmCard style={{ padding: 24 }}>
          <Text style={[S.frost, { marginBottom: 12, fontSize: 13, fontWeight: "600" }]}>Sender Number (Optional)</Text>
          <TextInput
            value={smsSender}
            onChangeText={setSmsSender}
            placeholder="e.g. +1234567890 or InfoSMS"
            placeholderTextColor={C.frost4}
            style={[S.tmInput, { marginBottom: 16 }]}
          />
          <Text style={[S.frost, { marginBottom: 12, fontSize: 13, fontWeight: "600" }]}>Message Content</Text>
          <TextInput
            value={smsText}
            onChangeText={setSmsText}
            placeholder="Paste suspicious SMS text here..."
            placeholderTextColor={C.frost4}
            multiline
            style={[S.scanInput, { minHeight: 120, marginBottom: 20 }]}
          />
          <TmPrimaryBtn label={busy ? "Scanning SMS..." : "Scan SMS"} onPress={handleSmsScan} disabled={busy} icon="chatbubble-ellipses-outline" />
          <QuickScanNotice
            title="Hybrid Security Checks"
            body="SMS scans may use local AI plus Google Safe Browsing, VirusTotal, IPQualityScore, and local threat feeds when configured. If the message contains links, those URLs and domains may be checked externally."
          />
        </TmCard>
      )}

      {mode === "text" && (
        <TmCard style={{ padding: 20 }}>
          {/* Text input section */}
          <Text style={[S.frost, { marginBottom: 8, fontSize: 13, fontWeight: "600" }]}>Paste Text or Email Content</Text>
          <TextInput
            value={manualText}
            onChangeText={setManualText}
            placeholder="Paste full email headers, body, or any suspicious text..."
            placeholderTextColor={C.frost4}
            multiline
            style={[S.scanInput, { minHeight: 110, marginBottom: 14 }]}
          />
          <TmPrimaryBtn label={busy ? "Scanning..." : "Scan Text"} onPress={onSubmitManual} disabled={busy} icon="document-text-outline" />

          {/* Divider */}
          <View style={{ flexDirection: "row", alignItems: "center", marginVertical: 18 }}>
            <View style={{ flex: 1, height: 1, backgroundColor: "rgba(255,255,255,0.07)" }} />
            <Text style={{ color: C.frost4, marginHorizontal: 12, fontSize: 11, fontWeight: "600", letterSpacing: 1 }}>OR UPLOAD</Text>
            <View style={{ flex: 1, height: 1, backgroundColor: "rgba(255,255,255,0.07)" }} />
          </View>

          {/* Upload options side by side */}
          <View style={{ flexDirection: "row", gap: 10 }}>
            <Pressable
              onPress={handleFileScan}
              style={{ flex: 1, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 7,
                paddingVertical: 12, borderRadius: 10, borderWidth: 1,
                borderColor: "rgba(138,143,240,0.3)", backgroundColor: "rgba(138,143,240,0.07)" }}
            >
              <Ionicons name="cloud-upload-outline" size={16} color={C.violetGlow} />
              <Text style={{ fontSize: 12, fontWeight: "600", color: C.violetGlow }}>File</Text>
              <Text style={{ fontSize: 10, color: C.frost4 }}>.eml .pdf .docx</Text>
            </Pressable>
            <Pressable
              onPress={handleScreenshotScan}
              style={{ flex: 1, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 7,
                paddingVertical: 12, borderRadius: 10, borderWidth: 1,
                borderColor: "rgba(138,143,240,0.3)", backgroundColor: "rgba(138,143,240,0.07)" }}
            >
              <Ionicons name="image-outline" size={16} color={C.violetGlow} />
              <Text style={{ fontSize: 12, fontWeight: "600", color: C.violetGlow }}>Image</Text>
              <Text style={{ fontSize: 10, color: C.frost4 }}>Screenshot</Text>
            </Pressable>
          </View>
          <QuickScanNotice
            title="File Privacy Notice"
            body="Quick file scans may use local AI plus Google Safe Browsing, VirusTotal, IPQualityScore, and local threat feeds when configured. Only extracted URLs, domains, and file hashes may be checked externally; raw file bytes are not sent to third-party providers."
          />
        </TmCard>
      )}

      {mode === "url" && (
        <TmCard style={{ padding: 24 }}>
          <Text style={[S.frost, { marginBottom: 12, fontSize: 13, fontWeight: "600" }]}>Suspicious URL</Text>
          <TextInput
            value={urlText}
            onChangeText={setUrlText}
            placeholder="https://example.com/login"
            placeholderTextColor={C.frost4}
            autoCapitalize="none"
            autoCorrect={false}
            style={[S.tmInput, { marginBottom: 20 }]}
          />
          <TmPrimaryBtn label={busy ? "Scanning URL..." : "Check URL"} onPress={handleUrlScan} disabled={busy} icon="link-outline" />
          <QuickScanNotice
            title="Controlled Link Fetching"
            body="URL scans may use Google Safe Browsing, VirusTotal, IPQualityScore, and local threat feeds when configured. Submitted URLs may also be fetched in a controlled no-login mode to resolve redirects and inspect lightweight HTML."
          />
        </TmCard>
      )}

      {localBusy && (
        <TmCard style={{ padding: 20, marginTop: 10, alignItems: "center", justifyContent: "center", gap: 12 }}>
          <ActivityIndicator size="large" color={C.violetGlow} />
          <Text style={{ color: C.frost2, fontSize: 14, fontWeight: "600" }}>Analyzing deeply...</Text>
        </TmCard>
      )}

      {!localBusy && inlineResult && (
        <View ref={resultRef}>
        <TmCard style={{ padding: 20, marginTop: 10, backgroundColor: inlineResult.verdict === "phishing" ? "rgba(255, 69, 58, 0.1)" : inlineResult.verdict === "suspicious" ? "rgba(255, 159, 10, 0.1)" : "rgba(48, 209, 88, 0.1)", borderColor: inlineResult.verdict === "phishing" ? "rgba(255, 69, 58, 0.5)" : inlineResult.verdict === "suspicious" ? "rgba(255, 159, 10, 0.5)" : "rgba(48, 209, 88, 0.5)" }}>
           <View style={{ flexDirection: "row", alignItems: "center", gap: 8, marginBottom: 12 }}>
             <Ionicons name={inlineResult.verdict === "legitimate" ? "shield-checkmark" : "warning"} size={24} color={inlineResult.verdict === "legitimate" ? C.emerald : inlineResult.verdict === "phishing" ? C.rose : C.gold} />
             <Text style={{ fontSize: 18, fontWeight: "700", color: "#fff", textTransform: "capitalize" }}>{inlineResult.verdict}</Text>
           </View>
           <Text style={{ color: C.frost4, fontSize: 11, marginBottom: 8 }}>
             Risk {Math.round(inlineResult.risk_score)}/100 | Confidence {Math.round((inlineResult.confidence || 0) * 100)}%
             {inlineResult.scan_category ? ` | ${String(inlineResult.scan_category).replace(/_/g, " ")}` : ""}
           </Text>
           <Text style={{ color: C.frost2, fontSize: 14, marginBottom: 10 }}>{inlineResult.summary}</Text>
           {inlineResult.top_signals.map((sig, i) => (
             <Text key={i} style={{ color: C.frost4, fontSize: 12, marginTop: 4 }}>- {sig.description}</Text>
           ))}
           {buildInlineArtifactRows(inlineResult).length > 0 && (
             <View style={{ marginTop: 14, padding: 12, borderRadius: 12, backgroundColor: "rgba(255,255,255,0.04)", borderWidth: 1, borderColor: "rgba(255,255,255,0.08)" }}>
               <Text style={{ color: C.violetGlow, fontSize: 11, fontWeight: "700", marginBottom: 8, letterSpacing: 0.5 }}>EXTRACTED EVIDENCE</Text>
               {buildInlineArtifactRows(inlineResult).map((row) => (
                 <View key={row.label} style={{ marginBottom: 8 }}>
                   <Text style={{ color: C.frost4, fontSize: 10, fontWeight: "700", marginBottom: 2, letterSpacing: 0.5 }}>{row.label}</Text>
                   <Text style={{ color: C.frost2, fontSize: 12, lineHeight: 18 }}>{row.value}</Text>
                 </View>
               ))}
             </View>
           )}
           {!!inlineResult.external_checks_used?.length && (
             <View style={{ marginTop: 14, paddingTop: 14, borderTopWidth: 1, borderTopColor: "rgba(255,255,255,0.1)" }}>
               <Text style={{ color: C.emerald, fontSize: 11, fontWeight: "700", marginBottom: 6, letterSpacing: 0.5 }}>CHECKS USED</Text>
               <Text style={{ color: C.frost3, fontSize: 12, lineHeight: 18 }}>{inlineResult.external_checks_used.join(", ")}</Text>
             </View>
           )}
           {!!inlineResult.external_checks_failed?.length && (
             <View style={{ marginTop: 10 }}>
               <Text style={{ color: C.gold, fontSize: 11, fontWeight: "700", marginBottom: 6, letterSpacing: 0.5 }}>LIMITED OR UNAVAILABLE</Text>
               <Text style={{ color: C.frost3, fontSize: 12, lineHeight: 18 }}>{inlineResult.external_checks_failed.join(", ")}</Text>
             </View>
           )}
           {inlineResult.privacy_notice && (
             <View style={{ marginTop: 14, padding: 12, borderRadius: 12, backgroundColor: "rgba(255,255,255,0.04)", borderWidth: 1, borderColor: "rgba(255,255,255,0.08)" }}>
               <Text style={{ color: C.frost4, fontSize: 11, fontWeight: "700", marginBottom: 4, letterSpacing: 0.5 }}>PRIVACY NOTICE</Text>
               <Text style={{ color: C.frost3, fontSize: 12, lineHeight: 18 }}>{inlineResult.privacy_notice}</Text>
             </View>
           )}
           {(inlineResult.structural_score != null || inlineResult.reputation_score != null || inlineResult.llm_score != null) && (
             <View style={{ marginTop: 14, paddingTop: 14, borderTopWidth: 1, borderTopColor: "rgba(255,255,255,0.1)" }}>
               <Text style={{ color: C.violetGlow, fontSize: 11, fontWeight: "700", marginBottom: 6, letterSpacing: 0.5 }}>SCORE BREAKDOWN</Text>
               <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 12 }}>
                 {inlineResult.structural_score != null && (
                   <Text style={{ color: C.frost, fontSize: 13 }}>Structural: <Text style={{ fontWeight: "700" }}>{inlineResult.structural_score}</Text></Text>
                 )}
                 {inlineResult.reputation_score != null && (
                   <Text style={{ color: C.frost, fontSize: 13 }}>Reputation: <Text style={{ fontWeight: "700" }}>{inlineResult.reputation_score}</Text></Text>
                 )}
                 {inlineResult.llm_score != null && (
                   <Text style={{ color: C.frost, fontSize: 13 }}>LLM: <Text style={{ fontWeight: "700" }}>{(inlineResult.llm_score * 100).toFixed(1)}%</Text></Text>
                 )}
               </View>
             </View>
           )}
           {inlineResult.llm_reasoning && (
             <View style={{ marginTop: 14, paddingTop: 14, borderTopWidth: 1, borderTopColor: "rgba(255,255,255,0.1)" }}>
               <Text style={{ color: C.violetGlow, fontSize: 11, fontWeight: "700", marginBottom: 6, letterSpacing: 0.5 }}>AI ANALYSIS</Text>
               <Text style={{ color: C.frost3, fontSize: 13, lineHeight: 18 }}>{inlineResult.llm_reasoning}</Text>
             </View>
           )}
           {!!inlineResult.degraded_reasons?.length && (
             <View style={{ marginTop: 10 }}>
               <Text style={{ color: C.gold, fontSize: 11, fontWeight: "700", marginBottom: 6, letterSpacing: 0.5 }}>DEGRADED ANALYSIS REASONS</Text>
               <Text style={{ color: C.frost3, fontSize: 12, lineHeight: 18 }}>{inlineResult.degraded_reasons.map((item) => item.replace(/_/g, " ")).join(", ")}</Text>
             </View>
           )}
           <View style={{ marginTop: 14, paddingTop: 14, borderTopWidth: 1, borderTopColor: "rgba(255,255,255,0.1)" }}>
             <Text style={{ color: C.violetGlow, fontSize: 11, fontWeight: "700", marginBottom: 8, letterSpacing: 0.5 }}>REVIEW OUTCOME</Text>
             <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
               {(["correct", "false_positive", "false_negative"] as const).map((choice) => {
                 const active = feedbackChoice === choice;
                 const label = choice === "correct" ? "Correct" : choice === "false_positive" ? "False Positive" : "False Negative";
                 return (
                   <Pressable
                     key={choice}
                     onPress={() => handleInlineFeedback(choice)}
                     disabled={feedbackBusy !== null}
                     style={{
                       paddingHorizontal: 12,
                       paddingVertical: 8,
                       borderRadius: 10,
                       borderWidth: 1,
                       borderColor: active ? C.violetGlow : "rgba(255,255,255,0.12)",
                       backgroundColor: active ? "rgba(90, 96, 216, 0.18)" : "rgba(255,255,255,0.04)",
                       opacity: feedbackBusy && feedbackBusy !== choice ? 0.55 : 1,
                     }}
                   >
                     <Text style={{ color: active ? "#fff" : C.frost3, fontSize: 12, fontWeight: "700" }}>
                       {feedbackBusy === choice ? "Saving..." : label}
                     </Text>
                   </Pressable>
                 );
               })}
             </View>
           </View>
           <Text style={{ color: "#fff", fontSize: 13, marginTop: 14, fontWeight: "600" }}>{inlineResult.recommended_action}</Text>
        </TmCard>
        </View>
      )}

    </View>
  );
}

// ─── Reports screen ───────────────────────────────────────────────────────────
function QuickScanNotice({ title, body }: { title: string; body: string }) {
  const [expanded, setExpanded] = React.useState(false);
  return (
    <Pressable
      onPress={() => setExpanded(!expanded)}
      style={{
        marginTop: 10,
        paddingVertical: 7,
        paddingHorizontal: 10,
        borderRadius: 8,
        backgroundColor: "rgba(255,255,255,0.03)",
        borderWidth: 0.5,
        borderColor: "rgba(255,255,255,0.08)",
      }}
    >
      <View style={{ flexDirection: "row", alignItems: "center", gap: 5 }}>
        <Ionicons name="information-circle-outline" size={13} color={C.frost4} />
        <Text style={{ color: C.frost4, fontSize: 10, fontWeight: "600", letterSpacing: 0.3, flex: 1 }}>
          {title.toUpperCase()}
        </Text>
        <Ionicons name={expanded ? "chevron-up" : "chevron-down"} size={12} color={C.frost4} />
      </View>
      {expanded && (
        <Text style={{ color: C.frost4, fontSize: 11, lineHeight: 16, marginTop: 6 }}>{body}</Text>
      )}
    </Pressable>
  );
}

function buildInlineArtifactRows(result: InstantScanResult): Array<{ label: string; value: string }> {
  const artifacts = result.artifacts || {};
  const rows: Array<{ label: string; value: string }> = [];
  const addValue = (label: string, value?: string | number | null) => {
    if (value === null || value === undefined || value === "") return;
    rows.push({ label, value: String(value) });
  };
  const addList = (label: string, items?: Array<string | null | undefined>) => {
    const filtered = (items || []).filter(Boolean) as string[];
    if (!filtered.length) return;
    rows.push({ label, value: filtered.join(", ") });
  };

  if (result.channel === "sms") {
    addValue("Sender ID", artifacts.sender_id);
    addValue("Sender Type", artifacts.sender_type);
    addList("Detected Links", artifacts.urls);
    addList("Claimed Brands", artifacts.brand_claims);
    addList("Urgency Markers", artifacts.urgency_markers);
    addList("Intent Markers", artifacts.intent_markers);
  } else if (result.channel === "url") {
    addValue("Submitted URL", artifacts.submitted_url);
    addValue("Normalized URL", artifacts.normalized_url);
    addValue("Final URL", artifacts.final_url);
    addValue("Final Domain", artifacts.final_domain);
    addValue("Landing Page Title", artifacts.landing_page_title);
    addList("Redirect Chain", artifacts.redirect_chain);
    addList("Reputation Hits", artifacts.reputation_hits);
  } else if (result.channel === "file") {
    addValue("Filename", artifacts.filename);
    addValue("Detected File Type", artifacts.detected_file_type || artifacts.detected_type);
    addValue("Extraction Method", artifacts.extraction_method);
    addValue("Parser Quality", artifacts.parser_quality);
    addValue(
      "Document Malware Risk",
      typeof artifacts.document_malware_risk === "number" ? `${Math.round(artifacts.document_malware_risk * 100)}%` : null
    );
    addValue(
      "Social Engineering Risk",
      typeof artifacts.social_engineering_risk === "number" ? `${Math.round(artifacts.social_engineering_risk * 100)}%` : null
    );
    addList("Extracted URLs", artifacts.extracted_urls || artifacts.urls);
    addList("Attachment Names", artifacts.attachment_names);
    addList("Active Content Flags", artifacts.embedded_active_content);
  }

  addList("Domains", artifacts.domains);
  addList("Phone Numbers", artifacts.phone_numbers);
  addList("Email Addresses", artifacts.email_addresses);
  return rows;
}

function ReportsScreen({ scans, onOpenReport }: {
  scans: ScanSummary[];
  onOpenReport: (id: string, kind: "pdf" | "json") => void;
}) {
  const list = scans.filter(s => s.final_label !== "queued" && s.final_label !== "failed" && (!!s.report_pdf || !!s.report_json));
  return (
    <View style={{ gap: 10 }}>
      <Text style={S.pageTitle}>Reports</Text>
      {list.length === 0 && (
        <TmCard style={{ alignItems: "center", padding: 30 }}>
          <Ionicons name="document-text-outline" size={32} color={C.frost4} />
          <Text style={[S.muted, { marginTop: 10, textAlign: "center" }]}>Full forensic reports appear here after email or Gmail scans. Quick SMS, URL, and file scans stay inline and do not create report files.</Text>
        </TmCard>
      )}
      {list.slice(0, 8).map(scan => {
        const col = verdictColor(scan.final_label);
        return (
          <TmCard key={scan.id}>
            <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
              <Text style={[S.frost, { flex: 1, fontSize: 13, fontWeight: "600" }]} numberOfLines={1}>{scan.subject}</Text>
              <View style={{ borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3, backgroundColor: col + "20", borderWidth: 1, borderColor: col + "55" }}>
                <Text style={{ fontSize: 9, fontWeight: "800", color: col }}>{scan.final_label.toUpperCase()}</Text>
              </View>
            </View>
            <Text style={[S.muted, { marginTop: 4 }]}>{new Date(scan.created_at).toLocaleString()}</Text>
            <View style={{ flexDirection: "row", gap: 10, marginTop: 12 }}>
              <Pressable style={S.reportBtn} onPress={() => onOpenReport(scan.id, "pdf")}>
                <Ionicons name="document-text" size={14} color={C.violetGlow} />
                <Text style={S.reportBtnText}>PDF</Text>
              </Pressable>
              <Pressable style={S.reportBtn} onPress={() => onOpenReport(scan.id, "json")}>
                <Ionicons name="code-slash" size={14} color={C.violetGlow} />
                <Text style={S.reportBtnText}>JSON</Text>
              </Pressable>
            </View>
          </TmCard>
        );
      })}
    </View>
  );
}

// ─── Settings screen (exact SettingsScreen.tsx) ────────────────────────────────
function SettingsScreen({ health, email, password, apiUrl, authState, gmailState,
  onEmail, onPassword, onApiUrl, onSaveApiUrl, onLogin, onConnectGmail,
  onRefreshGmail, onSetupGmailLabels, onRunGmailScan, onForgot, onShowToast,
  notificationPreferences, onUpdateNotificationPreference,
  googleBackupUser, googleBackupSyncTime, syncingBackup, scans,
  onConnectGoogle, onDisconnectGoogle, onSyncGoogle, onSwitchTab,
  onLogout, onClearCache }: any) {

  return (
    <View style={{ gap: 0, paddingBottom: 20 }}>
      <Text style={S.pageTitle}>Settings</Text>

      <Eyebrow label="Account" />
      <TmCard style={{ padding: 20, marginBottom: 16, flexDirection: "row", alignItems: "center", gap: 14 }}>
        <View style={{
          width: 44, height: 44, borderRadius: 22,
          alignItems: "center", justifyContent: "center",
          backgroundColor: "rgba(59, 65, 191, 0.1)",
          borderWidth: 1, borderColor: "rgba(59, 65, 191, 0.25)",
        }}>
          <Ionicons name="person-outline" size={20} color={C.violetGlow} />
        </View>
        <View style={{ flex: 1 }}>
          <Text style={[S.frost, { fontSize: 14, fontWeight: "700" }]}>
            Connected Account
          </Text>
          <Text style={[S.muted, { fontSize: 12, marginTop: 2, lineHeight: 16 }]}>
            Logged in as: {email}
          </Text>
        </View>
      </TmCard>



      {/* Notification Preferences */}
      <Eyebrow label="Preferences" />
      <TmCard style={{ marginBottom: 16, padding: 20, gap: 16 }}>
        <View style={{ flexDirection: "row", alignItems: "center", justifyContent: "space-between" }}>
          <View style={{ flexDirection: "row", alignItems: "center", gap: 12 }}>
            <View style={{ width: 36, height: 36, borderRadius: 18, backgroundColor: "rgba(224,138,174,0.15)", alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "rgba(224,138,174,0.3)" }}>
              <Ionicons name="warning" size={18} color={C.rose} />
            </View>
            <View>
              <Text style={{ fontSize: 13, fontWeight: "600", color: C.frost }}>Critical Threat Alerts</Text>
              <Text style={{ fontSize: 10, color: C.frost4, marginTop: 2 }}>Push alerts for phishing</Text>
            </View>
          </View>
          <Switch value={notificationPreferences?.critical_alerts ?? true} onValueChange={(value) => onUpdateNotificationPreference?.("critical_alerts", value)} trackColor={{ false: "rgba(255,255,255,0.1)", true: C.emerald }} thumbColor="#fff" />
        </View>

        <View style={{ flexDirection: "row", alignItems: "center", justifyContent: "space-between" }}>
          <View style={{ flexDirection: "row", alignItems: "center", gap: 12 }}>
            <View style={{ width: 36, height: 36, borderRadius: 18, backgroundColor: "rgba(111,217,184,0.15)", alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "rgba(111,217,184,0.3)" }}>
              <Ionicons name="document-text" size={18} color={C.emerald} />
            </View>
            <View>
              <Text style={{ fontSize: 13, fontWeight: "600", color: C.frost }}>Weekly Summary</Text>
              <Text style={{ fontSize: 10, color: C.frost4, marginTop: 2 }}>Email reports</Text>
            </View>
          </View>
          <Switch value={notificationPreferences?.weekly_summary ?? true} onValueChange={(value) => onUpdateNotificationPreference?.("weekly_summary", value)} trackColor={{ false: "rgba(255,255,255,0.1)", true: C.emerald }} thumbColor="#fff" />
        </View>
      </TmCard>

      <Eyebrow label="Data & Privacy" />
      <TmCard style={{ marginBottom: 16 }}>
        <Pressable onPress={onClearCache} style={{ flexDirection: "row", alignItems: "center", gap: 12, padding: 16, borderBottomWidth: 1, borderBottomColor: "rgba(255,255,255,0.05)" }}>
          <Ionicons name="trash-outline" size={18} color={C.frost3} />
          <Text style={{ fontSize: 13, color: C.frost, fontWeight: "500" }}>Clear Local Cache</Text>
        </Pressable>
        <Pressable onPress={onLogout} style={{ flexDirection: "row", alignItems: "center", gap: 12, padding: 16 }}>
          <Ionicons name="log-out-outline" size={18} color={C.rose} />
          <Text style={{ fontSize: 13, color: C.rose, fontWeight: "500" }}>Sign Out</Text>
        </Pressable>
      </TmCard>

      <Eyebrow label="Support & About" />
      <TmCard style={{ marginBottom: 24 }}>
        <Pressable onPress={() => onSwitchTab?.("help")} style={{ flexDirection: "row", alignItems: "center", gap: 12, padding: 16, borderBottomWidth: 1, borderBottomColor: "rgba(255,255,255,0.05)" }}>
          <Ionicons name="help-circle-outline" size={18} color={C.frost3} />
          <Text style={{ fontSize: 13, color: C.frost, fontWeight: "500" }}>Help Center</Text>
        </Pressable>
        <Pressable onPress={() => onSwitchTab?.("privacy")} style={{ flexDirection: "row", alignItems: "center", gap: 12, padding: 16 }}>
          <Ionicons name="shield-checkmark-outline" size={18} color={C.frost3} />
          <Text style={{ fontSize: 13, color: C.frost, fontWeight: "500" }}>Privacy Policy</Text>
        </Pressable>
      </TmCard>

      <Text style={{ textAlign: "center", color: C.frost4, fontSize: 10, marginBottom: 40 }}>v1.0.0 (Build 42)</Text>
    </View>
  );
}

// ─── Privacy Policy Screen ───────────────────────────────────────────────────
function PrivacyPolicyScreen({ onBack }: { onBack?: () => void }) {
  return (
    <View style={{ gap: 16, paddingBottom: 40 }}>
      <View style={{ flexDirection: "row", alignItems: "center", gap: 12, marginBottom: 8 }}>
        {onBack && (
          <Pressable onPress={onBack} style={{ padding: 4, marginRight: 4 }}>
            <Ionicons name="arrow-back" size={22} color={C.frost} />
          </Pressable>
        )}
        <Ionicons name="shield-checkmark" size={32} color={C.emerald} />
        <Text style={S.pageTitle}>Privacy Policy</Text>
      </View>
      <Text style={[S.muted, { fontSize: 13, lineHeight: 20 }]}>Effective Date: January 1, 2025</Text>

      <TmCard style={{ padding: 20, gap: 16 }}>
        <Text style={[S.frost, { fontSize: 16, fontWeight: "700", color: C.violetGlow }]}>1. Data Retention Policy</Text>
        <Text style={[S.muted, { fontSize: 14, lineHeight: 22 }]}>
          SafeMail X AI is designed to minimize retained content. We do not intentionally store raw email bodies or file samples beyond the active scan flow. Scan history keeps verdict metadata, while richer content is processed transiently in memory for analysis.
        </Text>

        <Text style={[S.frost, { fontSize: 16, fontWeight: "700", color: C.violetGlow, marginTop: 12 }]}>2. Google API Services Usage</Text>
        <Text style={[S.muted, { fontSize: 14, lineHeight: 22 }]}>
          SafeMail X AI's use and transfer to any other app of information received from Google APIs will adhere to the <Text style={{ color: C.emerald }}>Google API Services User Data Policy</Text>, including the Limited Use requirements.
          {"\n\n"}
          When you connect your Gmail account, we only request read-only access to scan emails for phishing threats. Your OAuth tokens are encrypted natively on your device.
          {"\n\n"}
          For quick SMS, URL, and file scans, SafeMail X AI may also query third-party security services such as Google Safe Browsing, VirusTotal, and IPQualityScore when configured. Those checks are limited to URLs, domains, and file hashes rather than raw file bytes.
        </Text>

        <Text style={[S.frost, { fontSize: 16, fontWeight: "700", color: C.violetGlow, marginTop: 12 }]}>3. Google Drive Cloud Backup</Text>
        <Text style={[S.muted, { fontSize: 14, lineHeight: 22 }]}>
          To provide a seamless cross-device experience without compromising your data, SafeMail X AI utilizes your personal Google Drive account to backup your scanning reports and settings. We do not host your historical threat data; it lives entirely within your designated Drive application folder.
        </Text>

        <Text style={[S.frost, { fontSize: 16, fontWeight: "700", color: C.violetGlow, marginTop: 12 }]}>4. Session Security</Text>
        <Text style={[S.muted, { fontSize: 14, lineHeight: 22 }]}>
          Your login credentials are never stored in plaintext. Session tokens are persisted using your device's hardware-encrypted Keychain (iOS) or Android Keystore — both are hardware-backed encrypted stores that cannot be read by other apps or extracted without device unlock.
          {"\n\n"}
          Sessions automatically expire after 24 hours. You can manually log out at any time from Settings, which immediately clears all stored credentials from secure storage.
        </Text>

        <Text style={[S.frost, { fontSize: 16, fontWeight: "700", color: C.violetGlow, marginTop: 12 }]}>5. URL & File Scanning</Text>
        <Text style={[S.muted, { fontSize: 14, lineHeight: 22 }]}>
          When you scan a URL, it may be fetched in a controlled no-login mode to resolve redirects and inspect lightweight HTML. Only the URL itself is sent to third-party reputation services — no cookies, login sessions, or personal data are transmitted.
          {"\n\n"}
          For file scans (.eml, .pdf, .docx, images), only extracted URLs, domains, and cryptographic file hashes are checked externally. Raw file bytes are never sent to third-party providers. Image-based scans use local OCR to extract text before analysis.
        </Text>

        <Text style={[S.frost, { fontSize: 16, fontWeight: "700", color: C.violetGlow, marginTop: 12 }]}>6. Push Notifications</Text>
        <Text style={[S.muted, { fontSize: 14, lineHeight: 22 }]}>
          If you enable push notifications, only your Expo push token and device platform are stored for delivery purposes. No email content, scan results, or personal data is included in push payloads. You can disable notifications at any time from your device settings.
        </Text>
      </TmCard>

      <Text style={[S.muted, { textAlign: "center", fontSize: 11, marginTop: 24, fontStyle: "italic" }]}>
        SafeMail X AI is committed to maintaining the highest standard of cybersecurity and user privacy.
      </Text>
    </View>
  );
}

// ─── Help Center Screen ──────────────────────────────────────────────────────
function HelpCenterScreen({ onBack }: { onBack?: () => void }) {
  const faqs = [
    {
      q: "How does SafeMail X AI scan my emails?",
      a: "SafeMail X AI uses a hybrid detection pipeline: fast rule-based heuristics filter obvious threats, then AI scoring and optional external reputation checks improve accuracy. For quick scans, URLs, domains, and file hashes may be checked against providers like Google Safe Browsing, VirusTotal, and IPQualityScore when configured.",
    },
    {
      q: "Is my data stored or shared?",
      a: "SafeMail X AI minimizes retained content. Email and file bodies are processed transiently for analysis, scan history stores verdict metadata, and quick-scan privacy notices tell you when URLs, domains, or file hashes may be checked with third-party threat-intelligence providers.",
    },
    {
      q: "What does the threat score mean?",
      a: "The threat score (0–100) indicates the likelihood of malicious intent. 0–30 is Legitimate (green), 31–65 is Suspicious (amber), and 66–100 is Phishing/Scam (red). The score combines rule-based signals and AI confidence.",
    },
    {
      q: "Can I scan SMS messages and screenshots?",
      a: "Yes! Use the Scan tab and switch to SMS or Screenshot mode. For SMS, paste the message text. For screenshots, upload an image and our OCR engine will extract and analyze the text automatically.",
    },
    {
      q: "How do I connect my Gmail account?",
      a: "Go to the Scan tab → Gmail section → tap 'Connect Gmail'. You'll be redirected to Google's OAuth consent screen. We only request read-only access to scan emails you explicitly label for review.",
    },
    {
      q: "What is the Gmail Label Scan feature?",
      a: "After connecting Gmail, apply the 'SafeMail X Scan' label to any suspicious email directly in your Gmail app. Then tap 'Run Label Scan' in SafeMail X AI to automatically process all labeled emails through our detection pipeline.",
    },
    {
      q: "Why does the app show 'OFFLINE'?",
      a: "The app periodically checks the backend API health. If you see OFFLINE, ensure your backend server is running and the API URL in Settings is correct. For local development, check that Docker containers are up and the Cloudflare tunnel is active.",
    },
    {
      q: "Can I scan URLs for phishing?",
      a: "Yes! Go to the Scan tab and switch to URL mode. Paste any suspicious link and tap 'Check URL'. SafeMail X AI will resolve redirects, inspect the landing page, and check the URL against Google Safe Browsing, VirusTotal, and IPQualityScore to detect phishing, malware, and brand impersonation.",
    },
    {
      q: "Can I scan files and documents?",
      a: "Yes! Use the Text/File tab to upload .eml, .pdf, .docx, .xlsx, .pptx files or screenshot images. Files are analyzed locally — only extracted URLs, domains, and file hashes are checked against external threat intelligence. Raw file bytes are never sent to third parties.",
    },
    {
      q: "Does my session persist after closing the app?",
      a: "Yes. Your login session is securely saved using your device's hardware-encrypted Keychain (iOS) or Android Keystore. You stay logged in until you explicitly log out from Settings or your session expires after 24 hours. Your credentials are never stored in plaintext.",
    },
    {
      q: "What is Google Drive Cloud Backup?",
      a: "SafeMail X AI can back up your scan reports and settings to your personal Google Drive. Your data stays in your Drive's application folder — we never host your historical threat data on our servers. Connect from Settings → Google Drive Backup.",
    },
  ];

  const [expanded, setExpanded] = React.useState<number | null>(null);

  return (
    <View style={{ gap: 16, paddingBottom: 40 }}>
      <View style={{ flexDirection: "row", alignItems: "center", gap: 12, marginBottom: 8 }}>
        {onBack && (
          <Pressable onPress={onBack} style={{ padding: 4, marginRight: 4 }}>
            <Ionicons name="arrow-back" size={22} color={C.frost} />
          </Pressable>
        )}
        <Ionicons name="help-circle" size={32} color={C.violetGlow} />
        <Text style={S.pageTitle}>Help Center</Text>
      </View>

      <TmCard style={{ padding: 20, gap: 4 }}>
        <Text style={[S.frost, { fontSize: 16, fontWeight: "700", marginBottom: 12 }]}>Frequently Asked Questions</Text>
        {faqs.map((faq, i) => (
          <View key={i}>
            <Pressable
              onPress={() => setExpanded(expanded === i ? null : i)}
              style={{
                flexDirection: "row",
                alignItems: "center",
                justifyContent: "space-between",
                paddingVertical: 14,
                borderTopWidth: i > 0 ? 1 : 0,
                borderTopColor: "rgba(255,255,255,0.06)",
              }}
            >
              <Text style={[S.frost, { fontSize: 13, fontWeight: "600", flex: 1, paddingRight: 12 }]}>{faq.q}</Text>
              <Ionicons name={expanded === i ? "chevron-up" : "chevron-down"} size={16} color={C.frost3} />
            </Pressable>
            {expanded === i && (
              <Text style={[S.muted, { fontSize: 13, lineHeight: 20, paddingBottom: 10, paddingLeft: 4 }]}>{faq.a}</Text>
            )}
          </View>
        ))}
      </TmCard>

      <TmCard style={{ padding: 20, gap: 12 }}>
        <Text style={[S.frost, { fontSize: 16, fontWeight: "700" }]}>Still Need Help?</Text>
        <Text style={[S.muted, { fontSize: 13, lineHeight: 20 }]}>
          Our support team is ready to assist you with any questions or issues.
        </Text>
        <Pressable
          onPress={() => Linking.openURL("mailto:support@safemailx-ai.tech?subject=SafeMail X%20AI%20Support%20Request")}
          style={{
            flexDirection: "row",
            alignItems: "center",
            gap: 10,
            backgroundColor: "rgba(139, 92, 246, 0.12)",
            padding: 14,
            borderRadius: 12,
            borderWidth: 1,
            borderColor: "rgba(139, 92, 246, 0.2)",
          }}
        >
          <Ionicons name="mail-outline" size={18} color={C.violetGlow} />
          <Text style={{ fontSize: 13, color: C.violetGlow, fontWeight: "600" }}>support@safemailx-ai.tech</Text>
        </Pressable>
      </TmCard>

      <Text style={[S.muted, { textAlign: "center", fontSize: 11, marginTop: 16, fontStyle: "italic" }]}>
        SafeMail X AI v1.0.0 — Privacy-first threat detection
      </Text>
    </View>
  );
}

// ─── Spinning loader ──────────────────────────────────────────────────────────
function SpinIcon() {
  const r = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.loop(Animated.timing(r, { toValue: 1, duration: 900, useNativeDriver: true })).start();
  }, []);
  const rotate = r.interpolate({ inputRange: [0, 1], outputRange: ["0deg", "360deg"] });
  return <Animated.View style={{ transform: [{ rotate }] }}><Ionicons name="sync" size={30} color={C.violetGlow} /></Animated.View>;
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const S = StyleSheet.create({
  root: { flex: 1, backgroundColor: C.bg },

  // Header
  header: {
    flexDirection: "row", alignItems: "center", justifyContent: "space-between",
    paddingHorizontal: 24, paddingTop: 8, paddingBottom: 20,
  },
  logo: {
    fontFamily: "serif", fontSize: 20, letterSpacing: 0.5,
    color: C.frost, fontStyle: "italic",
  },

  // Frost / muted text helpers
  frost: { color: C.frost },
  muted: { color: C.frost4, fontSize: 11, lineHeight: 17 },

  eyebrow: {
    fontSize: 9, fontWeight: "600", color: C.frost4,
    letterSpacing: 1.6, textTransform: "uppercase", marginBottom: 14,
  },

  pageTitle: {
    fontSize: 26, fontWeight: "700", color: C.frost,
    fontStyle: "italic", marginBottom: 6,
  },

  // TmCard
  tmCard: {
    borderRadius: 20,
    borderWidth: 1,
    borderColor: "rgba(0, 240, 255, 0.16)", // Beautiful glowing thin cyan/teal border from website
    padding: 16,
    overflow: "hidden", // Crucial for BlurView borderRadius
    // shadow for depth
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 16 },
    shadowOpacity: 0.8,
    shadowRadius: 20,
    elevation: 8,
  },
  tmCardGold: {
    borderColor: "rgba(232, 168, 76, 0.28)", // Amber/gold border
    shadowColor: "#e8a84c",
    shadowOpacity: 0.35,
  },
  tmCardShimmer: {
    position: "absolute", top: 0, left: 0, right: 0, height: 1.2,
    backgroundColor: "rgba(255, 255, 255, 0.35)",
  },

  // Primary button
  tmPrimaryBtn: {
    flexDirection: "row", alignItems: "center", justifyContent: "center",
    borderRadius: 14, paddingVertical: 13, marginTop: 12,
    borderWidth: 1, borderColor: "rgba(242,234,253,0.22)",
    shadowColor: C.violet, shadowOffset: { width: 0, height: 14 },
    shadowOpacity: 0.7, shadowRadius: 20, elevation: 8,
  },
  tmPrimaryBtnText: { color: C.frost, fontWeight: "600", fontSize: 13, letterSpacing: 0.4 },

  // Ghost button
  tmGhostBtn: {
    flexDirection: "row", alignItems: "center", justifyContent: "center",
    borderRadius: 13, paddingVertical: 12,
    backgroundColor: "rgba(138,143,240,0.03)",
    borderWidth: 1, borderColor: C.line2,
  },
  tmGhostBtnText: { color: C.frost2, fontSize: 11, fontWeight: "500" },

  // Google button
  googleBtn: {
    flexDirection: "row", alignItems: "center", justifyContent: "center",
    backgroundColor: "#ffffff",
    borderRadius: 12, paddingVertical: 11, paddingHorizontal: 20,
    marginTop: 4, width: "100%",
    shadowColor: "#ffffff", shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.15, shadowRadius: 8, elevation: 3,
  },
  googleBtnText: { color: "#000000", fontWeight: "600", fontSize: 12, letterSpacing: 0.2 },

  // Google account lists
  googleAccountRow: {
    flexDirection: "row", alignItems: "center", gap: 12,
    backgroundColor: "rgba(255,255,255,0.04)",
    borderRadius: 12, padding: 12,
    borderWidth: 1, borderColor: "rgba(255,255,255,0.08)",
  },
  googleAvatar: {
    width: 32, height: 32, borderRadius: 16,
    backgroundColor: "#3b41bf", alignItems: "center", justifyContent: "center",
  },

  // Input
  tmInput: {
    width: "100%",
    backgroundColor: "rgba(255, 255, 255, 0.03)",
    borderWidth: 1,
    borderColor: "rgba(0, 240, 255, 0.15)",
    borderRadius: 12,
    paddingHorizontal: 13, paddingVertical: 11,
    fontSize: 12, color: C.frost,
    marginBottom: 10,
  },

  // Scan input
  scanInput: {
    minHeight: 88, color: C.frost,
    backgroundColor: "rgba(255, 255, 255, 0.03)",
    borderWidth: 1,
    borderColor: "rgba(0, 240, 255, 0.15)",
    borderRadius: 12,
    padding: 13, marginBottom: 10, textAlignVertical: "top", fontSize: 12,
  },

  // Pill
  pill: {
    flexDirection: "row", alignItems: "center", gap: 6,
    alignSelf: "flex-start", borderRadius: 999,
    paddingHorizontal: 10, paddingVertical: 5, borderWidth: 1,
  },
  pillText: { fontSize: 9, fontWeight: "600", letterSpacing: 0.6, textTransform: "uppercase" },

  // Stat
  statValue: { fontStyle: "italic", fontWeight: "700", lineHeight: 42 },
  statLabel: { fontSize: 9, fontWeight: "600", color: C.frost4, letterSpacing: 1.6, marginTop: 6, textTransform: "uppercase" },

  // Phishing shield plate
  shieldPlate: {
    width: 48, height: 48, borderRadius: 16, alignItems: "center", justifyContent: "center",
    backgroundColor: "transparent",
    borderWidth: 1, borderColor: "rgba(232,96,122,0.22)",
  },

  // Icon plate
  iconPlate: {
    width: 32, height: 32, borderRadius: 10, alignItems: "center", justifyContent: "center",
    backgroundColor: "rgba(242,234,253,0.08)",
    borderWidth: 1, borderColor: "rgba(138,143,240,0.32)",
    shadowColor: C.violet, shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.4, shadowRadius: 6,
  },

  // Pipeline dot
  pipeDot: {
    width: 18, height: 18, borderRadius: 9,
    zIndex: 10, borderWidth: 1,
  },
  pipeLabel: { fontSize: 8, fontWeight: "600", letterSpacing: 1.5, marginTop: 6 },

  // Bottom nav
  navContainer: {
    position: "absolute", left: 0, right: 0, bottom: 0,
    flexDirection: "row", alignItems: "flex-end",
    borderTopWidth: 1, borderTopColor: C.line,
    paddingHorizontal: 12, paddingTop: 12,
    // paddingBottom is set dynamically via bottomInset prop
  },
  navItem: { flex: 1, alignItems: "center", gap: 4 },
  navLabel: { fontSize: 8, fontWeight: "600", letterSpacing: 1.2, color: C.frost4 },
  navShield: {
    width: 48, height: 48, alignItems: "center", justifyContent: "center",
    shadowColor: C.violetGlow,
    shadowOffset: { width: 0, height: 0 }, shadowRadius: 18,
    marginBottom: 10,
  },

  // Scan mode
  modeRow: {
    flexDirection: "row", gap: 4,
    backgroundColor: "rgba(0,0,0,0.25)", borderRadius: 14, padding: 4,
  },
  modeBtn: { flex: 1, alignItems: "center", borderRadius: 12, paddingVertical: 10 },
  modeBtnText: { fontSize: 11, fontWeight: "600", letterSpacing: 0.4, color: C.frost3 },

  // Reports
  reportBtn: {
    flex: 1, minHeight: 38, flexDirection: "row", alignItems: "center", justifyContent: "center",
    gap: 6, borderRadius: 10, borderWidth: 1, borderColor: "rgba(138,143,240,0.3)",
    backgroundColor: "rgba(59,65,191,0.08)",
  },
  reportBtnText: { fontSize: 12, fontWeight: "700", color: C.violetGlow },

  // Toast
  toast: {
    position: "absolute", alignSelf: "center",
    flexDirection: "row", alignItems: "center", gap: 8,
    paddingHorizontal: 16, paddingVertical: 11,
    borderRadius: 22, borderWidth: 1,
    backgroundColor: C.ink3,
    shadowColor: "#000", shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.4, shadowRadius: 12,
  },
  toastText: { fontSize: 12, fontWeight: "600" },

  // Overlay
  overlay: {
    position: "absolute", top: 0, left: 0, right: 0, bottom: 0,
    backgroundColor: "rgba(1,1,4,0.75)",
    justifyContent: "center", alignItems: "center",
    zIndex: 1000, elevation: 20,
  },
});
