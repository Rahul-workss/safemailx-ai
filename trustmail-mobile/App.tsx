import React, { useEffect, useMemo, useState } from "react";
import {
  Pressable,
  Platform,
  Linking,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View
} from "react-native";
import { StatusBar } from "expo-status-bar";
import { LinearGradient } from "expo-linear-gradient";
import { Ionicons } from "@expo/vector-icons";
import * as DocumentPicker from "expo-document-picker";
import * as Notifications from "expo-notifications";

import { confirmPasswordReset, createManualScan, fetchGmailOAuthStatus, fetchHealth, fetchScans, Health, login, registerPushToken, requestPasswordReset, ScanSummary, startGmailOAuth, uploadScanFile } from "./src/api";
import { colors, verdictColor } from "./src/theme";

type Tab = "dashboard" | "scans" | "new" | "reports" | "settings";

const tabs: Array<{ id: Tab; label: string; icon: keyof typeof Ionicons.glyphMap }> = [
  { id: "dashboard", label: "Home", icon: "pulse" },
  { id: "scans", label: "Scans", icon: "mail-unread" },
  { id: "new", label: "Scan", icon: "add-circle" },
  { id: "reports", label: "Reports", icon: "document-text" },
  { id: "settings", label: "Settings", icon: "settings" }
];

class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean, errorMsg: string}> {
  constructor(props: {children: React.ReactNode}) {
    super(props);
    this.state = { hasError: false, errorMsg: "" };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, errorMsg: error.message };
  }
  componentDidCatch(error: Error) {
    console.error("TrustMail App Crash:", error);
  }
  render() {
    if (this.state.hasError) {
      return (
        <SafeAreaView style={[styles.root, { justifyContent: 'center', alignItems: 'center', padding: 20 }]}>
          <Ionicons name="warning" size={48} color={colors.red} />
          <Text style={{ color: 'white', fontSize: 20, marginTop: 16, fontWeight: 'bold' }}>App Error Occurred</Text>
          <Text style={{ color: colors.muted, textAlign: 'center', marginTop: 8 }}>{this.state.errorMsg}</Text>
          <Pressable style={styles.primaryButton} onPress={() => this.setState({ hasError: false })}>
            <Text style={styles.primaryButtonText}>Try Again</Text>
          </Pressable>
        </SafeAreaView>
      );
    }
    return this.props.children;
  }
}

export default function AppWrapper() {
  return (
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  );
}

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("dashboard");
  const [health, setHealth] = useState<Health | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [manualText, setManualText] = useState("");
  const [email, setEmail] = useState("admin@trustmail.local");
  const [password, setPassword] = useState("");
  const [authState, setAuthState] = useState("local mode");
  const [gmailState, setGmailState] = useState("not checked");
  const [busy, setBusy] = useState(false);
  const [uploadBusy, setUploadBusy] = useState(false);
  
  const [toast, setToast] = useState<{msg: string, type: "error"|"success"|""}>({msg: "", type: ""});
  const showToast = (msg: string, type: "error"|"success" = "error") => {
    setToast({msg, type});
    setTimeout(() => setToast({msg: "", type: ""}), 3500);
  };

  async function refresh() {
    try {
      const [nextHealth, nextScans] = await Promise.all([fetchHealth(), fetchScans()]);
      setHealth(nextHealth);
      setScans(nextScans);
    } catch {
      setHealth({
        api: "offline",
        database: "unknown",
        redis: "unknown",
        ocr: "unknown",
        llm: "unknown",
        gmail_watcher: "unknown"
      });
    }
  }

  useEffect(() => {
    refresh();
    registerForPushNotifications();
  }, []);

  async function registerForPushNotifications() {
    try {
      const permission = await Notifications.requestPermissionsAsync();
      if (!permission.granted) return;
      const token = await Notifications.getExpoPushTokenAsync();
      await registerPushToken(token.data, Platform.OS);
    } catch {
      // Push notifications are optional
    }
  }

  const stats = useMemo(() => ({
    safe: scans.filter((scan) => scan.final_label === "legitimate").length,
    suspicious: scans.filter((scan) => scan.final_label === "suspicious").length,
    phishing: scans.filter((scan) => scan.final_label === "phishing").length
  }), [scans]);

  async function submitManualScan() {
    if (!manualText.trim()) return;
    setBusy(true);
    try {
      await createManualScan(manualText.trim());
      setManualText("");
      setActiveTab("scans");
      await refresh();
      showToast("Scan queued successfully", "success");
    } catch (err: any) {
      showToast(err.message || "Manual scan failed");
    } finally {
      setBusy(false);
    }
  }

  async function submitUploadScan() {
    const result = await DocumentPicker.getDocumentAsync({
      copyToCacheDirectory: true,
      multiple: false,
      type: ["text/plain", "message/rfc822", "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "image/*"]
    });
    if (result.canceled || !result.assets[0]) return;

    setUploadBusy(true);
    try {
      const asset = result.assets[0];
      await uploadScanFile({ uri: asset.uri, name: asset.name, mimeType: asset.mimeType });
      setActiveTab("scans");
      await refresh();
      showToast("File uploaded and scanned", "success");
    } catch (err: any) {
      showToast(err.message || "Upload scan failed");
    } finally {
      setUploadBusy(false);
    }
  }

  async function submitLogin() {
    if (!email.trim() || !password) return;
    setAuthState("signing in");
    setBusy(true);
    try {
      await login(email.trim(), password);
      setPassword("");
      setAuthState("signed in");
      await refresh();
      await refreshGmailStatus();
      await registerForPushNotifications();
      showToast("Signed in successfully", "success");
    } catch {
      setAuthState("login failed");
      showToast("Invalid email or password");
    } finally {
      setBusy(false);
    }
  }

  async function refreshGmailStatus() {
    try {
      const connected = await fetchGmailOAuthStatus();
      setGmailState(connected ? "connected" : "not connected");
    } catch {
      setGmailState("sign in required");
    }
  }

  async function connectGmail() {
    try {
      const url = await startGmailOAuth();
      await Linking.openURL(url);
      setGmailState("authorization opened");
    } catch (err: any) {
      setGmailState("connect failed");
      showToast(err.message || "Gmail connection failed");
    }
  }

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar style="light" />
      <LinearGradient colors={["#0B1320", "#080B12"]} style={styles.header}>
        <View>
          <Text style={styles.eyebrow}>TRUSTMAIL AI</Text>
          <Text style={styles.title}>Mobile Security Console</Text>
        </View>
        <StatusPill label={health?.api || "loading"} />
      </LinearGradient>

      <ScrollView style={styles.content} contentContainerStyle={styles.contentInner}>
        {activeTab === "dashboard" && (
          <Dashboard health={health} stats={stats} latest={scans[0]} />
        )}
        {activeTab === "scans" && <Scans scans={scans} />}
        {activeTab === "new" && (
          <NewScan
            value={manualText}
            busy={busy}
            uploadBusy={uploadBusy}
            onChange={setManualText}
            onSubmit={submitManualScan}
            onUpload={submitUploadScan}
          />
        )}
        {activeTab === "reports" && <Reports scans={scans} />}
        {activeTab === "settings" && (
          <Settings
            health={health}
            email={email}
            password={password}
            authState={authState}
            gmailState={gmailState}
            onEmail={setEmail}
            onPassword={setPassword}
            onLogin={submitLogin}
            onConnectGmail={connectGmail}
            onRefreshGmail={refreshGmailStatus}
            onShowToast={showToast}
          />
        )}
      </ScrollView>

      <View style={styles.nav}>
        {tabs.map((tab) => {
          const active = activeTab === tab.id;
          return (
            <Pressable key={tab.id} style={styles.navItem} onPress={() => setActiveTab(tab.id)}>
              <Ionicons name={tab.icon} size={22} color={active ? colors.blue : colors.muted} />
              <Text style={[styles.navLabel, active && styles.navLabelActive]}>{tab.label}</Text>
            </Pressable>
          );
        })}
      </View>
      
      {toast.msg ? (
        <View style={[styles.toast, toast.type === "error" ? styles.toastError : styles.toastSuccess]}>
          <Ionicons name={toast.type === "error" ? "alert-circle" : "checkmark-circle"} size={20} color="white" />
          <Text style={styles.toastText}>{toast.msg}</Text>
        </View>
      ) : null}
      
      {busy && (
        <View style={styles.loadingOverlay}>
          <View style={styles.loadingBox}>
            <Ionicons name="sync" size={32} color={colors.blue} style={{ marginBottom: 12 }} />
            <Text style={{ color: 'white', fontWeight: 'bold' }}>Processing...</Text>
          </View>
        </View>
      )}
    </SafeAreaView>
  );
}

function Dashboard({ health, stats, latest }: {
  health: Health | null;
  stats: { safe: number; suspicious: number; phishing: number };
  latest?: ScanSummary;
}) {
  return (
    <View style={styles.stack}>
      <View style={styles.scoreGrid}>
        <Metric label="Safe" value={stats.safe} color={colors.green} />
        <Metric label="Suspicious" value={stats.suspicious} color={colors.amber} />
        <Metric label="Phishing" value={stats.phishing} color={colors.red} />
      </View>
      <PipelineCard />
      {latest && <ScanCard scan={latest} />}
      <HealthGrid health={health} />
    </View>
  );
}

function PipelineCard() {
  const stages = ["Intake", "OCR", "URL", "Qwen", "Veto", "Report"];
  return (
    <View style={styles.card}>
      <Text style={styles.cardTitle}>Live Scan Pipeline</Text>
      <View style={styles.pipeline}>
        {stages.map((stage, index) => (
          <View key={stage} style={styles.pipelineStep}>
            <View style={[styles.dot, index < 3 && styles.dotActive]} />
            <Text style={styles.pipelineText}>{stage}</Text>
          </View>
        ))}
      </View>
    </View>
  );
}

function Scans({ scans }: { scans: ScanSummary[] }) {
  return (
    <View style={styles.stack}>
      {scans.length === 0 ? <Empty text="No scans yet. Run a manual scan or connect Gmail." /> : null}
      {scans.map((scan) => <ScanCard key={scan.id} scan={scan} />)}
    </View>
  );
}

function NewScan({ value, busy, uploadBusy, onChange, onSubmit, onUpload }: {
  value: string;
  busy: boolean;
  uploadBusy: boolean;
  onChange: (value: string) => void;
  onSubmit: () => void;
  onUpload: () => void;
}) {
  return (
    <View style={styles.stack}>
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Manual Email Scan</Text>
        <Text style={styles.muted}>Paste suspicious email text or upload a PDF, DOCX, image, EML, HTML, or TXT file.</Text>
        <TextInput
          multiline
          value={value}
          onChangeText={onChange}
          placeholder="Paste email body here..."
          placeholderTextColor={colors.muted}
          style={styles.input}
        />
        <Pressable style={styles.primaryButton} onPress={onSubmit} disabled={busy}>
          <Text style={styles.primaryButtonText}>{busy ? "Scanning..." : "Run TrustMail Scan"}</Text>
        </Pressable>
        <Pressable style={styles.secondaryButton} onPress={onUpload} disabled={uploadBusy}>
          <Ionicons name="cloud-upload" size={18} color={colors.blue} />
          <Text style={styles.secondaryButtonText}>{uploadBusy ? "Uploading..." : "Upload File Scan"}</Text>
        </Pressable>
      </View>
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Demo Samples</Text>
        {["Safe notification", "Marketing reward lure", "Credential phishing", "PDF attachment case"].map((sample) => (
          <View key={sample} style={styles.demoRow}>
            <Ionicons name="play-circle" size={18} color={colors.blue} />
            <Text style={styles.demoText}>{sample}</Text>
          </View>
        ))}
      </View>
    </View>
  );
}

function Reports({ scans }: { scans: ScanSummary[] }) {
  return (
    <View style={styles.stack}>
      <Text style={styles.sectionTitle}>Recent Reports</Text>
      {scans.slice(0, 5).map((scan) => (
        <View key={scan.id} style={styles.card}>
          <Text style={styles.cardTitle}>{scan.subject}</Text>
          <Text style={styles.muted}>PDF and JSON export are available from the API endpoints.</Text>
        </View>
      ))}
    </View>
  );
}

function Settings({ health, email, password, authState, gmailState, onEmail, onPassword, onLogin, onConnectGmail, onRefreshGmail, onShowToast }: {
  health: Health | null;
  email: string;
  password: string;
  authState: string;
  gmailState: string;
  onEmail: (value: string) => void;
  onPassword: (value: string) => void;
  onLogin: () => void;
  onConnectGmail: () => void;
  onRefreshGmail: () => void;
  onShowToast: (msg: string, type?: "error"|"success") => void;
}) {
  const [mode, setMode] = useState<"login" | "forgot" | "reset">("login");
  const [resetToken, setResetToken] = useState("");
  const [resetPassword, setResetPassword] = useState("");

  const handleForgot = async () => {
    if (!email.trim()) {
      onShowToast("Please enter your email", "error");
      return;
    }
    try {
      await requestPasswordReset(email.trim());
      onShowToast("Reset link sent if account exists", "success");
      setMode("reset");
    } catch {
      onShowToast("Failed to send reset link", "error");
    }
  };

  const handleResetConfirm = async () => {
    if (!resetToken.trim() || !resetPassword.trim()) {
      onShowToast("Enter reset token and new password", "error");
      return;
    }
    try {
      await confirmPasswordReset(resetToken.trim(), resetPassword);
      setResetToken("");
      setResetPassword("");
      onShowToast("Password reset complete", "success");
      setMode("login");
    } catch {
      onShowToast("Failed to reset password", "error");
    }
  };

  return (
    <View style={styles.stack}>
      <HealthGrid health={health} />
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Account</Text>
        <Text style={styles.muted}>
          {mode === "login" ? authState : mode === "forgot" ? "Enter your email to request a reset token." : "Enter the reset token and a new password."}
        </Text>
        
        <TextInput
          value={email}
          onChangeText={onEmail}
          placeholder="Email"
          placeholderTextColor={colors.muted}
          autoCapitalize="none"
          keyboardType="email-address"
          style={styles.compactInput}
        />
        
        {mode === "login" && (
          <TextInput
            value={password}
            onChangeText={onPassword}
            placeholder="Password"
            placeholderTextColor={colors.muted}
            secureTextEntry
            style={styles.compactInput}
          />
        )}

        {mode === "reset" && (
          <>
            <TextInput
              value={resetToken}
              onChangeText={setResetToken}
              placeholder="Reset token"
              placeholderTextColor={colors.muted}
              autoCapitalize="none"
              style={styles.compactInput}
            />
            <TextInput
              value={resetPassword}
              onChangeText={setResetPassword}
              placeholder="New password"
              placeholderTextColor={colors.muted}
              secureTextEntry
              style={styles.compactInput}
            />
          </>
        )}
        
        {mode === "login" ? (
          <>
            <Pressable style={styles.primaryButton} onPress={onLogin}>
              <Text style={styles.primaryButtonText}>Sign In</Text>
            </Pressable>
            <Pressable style={{ marginTop: 12, alignItems: "center" }} onPress={() => setMode("forgot")}>
              <Text style={{ color: colors.blue, fontSize: 13 }}>Forgot Password?</Text>
            </Pressable>
          </>
        ) : mode === "forgot" ? (
          <>
            <Pressable style={styles.primaryButton} onPress={handleForgot}>
              <Text style={styles.primaryButtonText}>Send Reset Link</Text>
            </Pressable>
            <Pressable style={{ marginTop: 12, alignItems: "center" }} onPress={() => setMode("login")}>
              <Text style={{ color: colors.muted, fontSize: 13 }}>&larr; Back to Sign In</Text>
            </Pressable>
          </>
        ) : (
          <>
            <Pressable style={styles.primaryButton} onPress={handleResetConfirm}>
              <Text style={styles.primaryButtonText}>Reset Password</Text>
            </Pressable>
            <Pressable style={{ marginTop: 12, alignItems: "center" }} onPress={() => setMode("login")}>
              <Text style={{ color: colors.muted, fontSize: 13 }}>&larr; Back to Sign In</Text>
            </Pressable>
          </>
        )}
      </View>
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Gmail</Text>
        <Text style={styles.muted}>{gmailState}</Text>
        <Pressable style={styles.secondaryButton} onPress={onConnectGmail}>
          <Ionicons name="mail" size={18} color={colors.blue} />
          <Text style={styles.secondaryButtonText}>Connect Gmail</Text>
        </Pressable>
        <Pressable style={styles.secondaryButton} onPress={onRefreshGmail}>
          <Ionicons name="refresh" size={18} color={colors.blue} />
          <Text style={styles.secondaryButtonText}>Refresh Status</Text>
        </Pressable>
      </View>
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Scan Mode</Text>
        <View style={styles.segmented}>
          {["Strict", "Balanced", "Fast"].map((m) => (
            <View key={m} style={[styles.segment, m === "Balanced" && styles.segmentActive]}>
              <Text style={[styles.segmentText, m === "Balanced" && styles.segmentTextActive]}>{m}</Text>
            </View>
          ))}
        </View>
      </View>
    </View>
  );
}

function ScanCard({ scan }: { scan: ScanSummary }) {
  const color = verdictColor(scan.final_label);
  return (
    <View style={styles.card}>
      <View style={styles.row}>
        <Text style={styles.cardTitle} numberOfLines={1}>{scan.subject}</Text>
        <Text style={[styles.verdict, { color }]}>{scan.final_label.toUpperCase()}</Text>
      </View>
      <Text style={styles.muted}>{scan.sender}</Text>
      <View style={styles.meterTrack}>
        <View style={[styles.meterFill, { width: `${Math.round(scan.final_score * 100)}%`, backgroundColor: color }]} />
      </View>
      <Text style={styles.muted}>{Math.round(scan.final_score * 100)}/100 - Qwen {scan.llm_used ? "used" : "not used"}</Text>
    </View>
  );
}

function HealthGrid({ health }: { health: Health | null }) {
  const items = [
    ["API", health?.api],
    ["Qwen", health?.llm],
    ["OCR", health?.ocr],
    ["Gmail", health?.gmail_watcher]
  ];
  return (
    <View style={styles.healthGrid}>
      {items.map(([label, value]) => (
        <View key={label} style={styles.healthCard}>
          <Text style={styles.muted}>{label}</Text>
          <StatusPill label={value || "loading"} />
        </View>
      ))}
    </View>
  );
}

function Metric({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <View style={styles.metricCard}>
      <Text style={[styles.metricValue, { color }]}>{value}</Text>
      <Text style={styles.muted}>{label}</Text>
    </View>
  );
}

function StatusPill({ label }: { label: string }) {
  const online = ["online", "configured"].includes(label);
  return (
    <View style={[styles.pill, online && styles.pillOnline]}>
      <Text style={[styles.pillText, online && styles.pillTextOnline]}>{label}</Text>
    </View>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <View style={styles.card}>
      <Text style={styles.muted}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bg },
  header: { paddingHorizontal: 18, paddingTop: 20, paddingBottom: 18, flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  eyebrow: { color: colors.blue, fontSize: 11, fontWeight: "800", letterSpacing: 2 },
  title: { color: colors.text, fontSize: 22, fontWeight: "900", marginTop: 4 },
  content: { flex: 1 },
  contentInner: { padding: 16, paddingBottom: 96 },
  stack: { gap: 14 },
  card: { backgroundColor: colors.panel, borderColor: colors.border, borderWidth: 1, borderRadius: 16, padding: 16 },
  cardTitle: { color: colors.text, fontSize: 16, fontWeight: "800", flex: 1 },
  sectionTitle: { color: colors.text, fontSize: 18, fontWeight: "900" },
  muted: { color: colors.muted, fontSize: 13, lineHeight: 19 },
  row: { flexDirection: "row", alignItems: "center", gap: 10 },
  scoreGrid: { flexDirection: "row", gap: 10 },
  metricCard: { flex: 1, backgroundColor: colors.panel, borderRadius: 14, padding: 14, borderColor: colors.border, borderWidth: 1 },
  metricValue: { fontSize: 26, fontWeight: "900" },
  verdict: { fontSize: 11, fontWeight: "900" },
  meterTrack: { height: 8, backgroundColor: "#263145", borderRadius: 999, overflow: "hidden", marginVertical: 12 },
  meterFill: { height: 8, borderRadius: 999 },
  pipeline: { flexDirection: "row", justifyContent: "space-between", marginTop: 14 },
  pipelineStep: { alignItems: "center", gap: 6, width: 48 },
  dot: { width: 14, height: 14, borderRadius: 7, backgroundColor: "#283246", borderWidth: 2, borderColor: colors.border },
  dotActive: { backgroundColor: colors.blue, borderColor: colors.blue },
  pipelineText: { color: colors.muted, fontSize: 10, textAlign: "center" },
  healthGrid: { flexDirection: "row", flexWrap: "wrap", gap: 10 },
  healthCard: { width: "48%", backgroundColor: colors.panel2, borderRadius: 14, padding: 12, borderColor: colors.border, borderWidth: 1 },
  pill: { alignSelf: "flex-start", borderRadius: 999, paddingHorizontal: 9, paddingVertical: 5, backgroundColor: "#2B2230", marginTop: 6 },
  pillOnline: { backgroundColor: "#0D2B1A" },
  pillText: { color: colors.amber, fontSize: 11, fontWeight: "800" },
  pillTextOnline: { color: colors.green },
  input: { minHeight: 180, color: colors.text, borderColor: colors.border, borderWidth: 1, borderRadius: 14, padding: 12, marginTop: 14, textAlignVertical: "top", backgroundColor: "#0C111C" },
  compactInput: { color: colors.text, borderColor: colors.border, borderWidth: 1, borderRadius: 12, padding: 12, marginTop: 12, backgroundColor: "#0C111C" },
  primaryButton: { backgroundColor: colors.blue, borderRadius: 14, alignItems: "center", paddingVertical: 14, marginTop: 14 },
  primaryButtonText: { color: "#06111A", fontWeight: "900" },
  secondaryButton: { borderColor: colors.blue, borderWidth: 1, borderRadius: 14, alignItems: "center", justifyContent: "center", paddingVertical: 13, marginTop: 10, flexDirection: "row", gap: 8 },
  secondaryButtonText: { color: colors.blue, fontWeight: "900" },
  demoRow: { flexDirection: "row", alignItems: "center", gap: 8, paddingVertical: 9 },
  demoText: { color: colors.text, fontSize: 14 },
  segmented: { flexDirection: "row", gap: 8, marginTop: 14 },
  segment: { flex: 1, alignItems: "center", borderRadius: 12, paddingVertical: 10, backgroundColor: "#0C111C", borderColor: colors.border, borderWidth: 1 },
  segmentActive: { backgroundColor: "#0F3145", borderColor: colors.blue },
  segmentText: { color: colors.muted, fontWeight: "800" },
  segmentTextActive: { color: colors.blue },
  nav: { position: "absolute", left: 12, right: 12, bottom: 14, flexDirection: "row", justifyContent: "space-around", backgroundColor: "#0D1420", borderColor: colors.border, borderWidth: 1, borderRadius: 22, paddingVertical: 10 },
  navItem: { alignItems: "center", gap: 3, minWidth: 54 },
  navLabel: { color: colors.muted, fontSize: 10, fontWeight: "700" },
  navLabelActive: { color: colors.blue },
  toast: { position: "absolute", bottom: 90, alignSelf: "center", flexDirection: "row", alignItems: "center", gap: 8, paddingHorizontal: 16, paddingVertical: 12, borderRadius: 24, elevation: 5, shadowColor: "#000", shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.3, shadowRadius: 8 },
  toastError: { backgroundColor: "#8A1C1C" },
  toastSuccess: { backgroundColor: "#0D5930" },
  toastText: { color: "white", fontWeight: "700", fontSize: 13 },
  loadingOverlay: { position: "absolute", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(0,0,0,0.6)", justifyContent: "center", alignItems: "center", zIndex: 1000 },
  loadingBox: { backgroundColor: colors.panel, padding: 30, borderRadius: 20, alignItems: "center", borderColor: colors.border, borderWidth: 1, shadowColor: "#000", shadowOffset: { width: 0, height: 10 }, shadowOpacity: 0.5, shadowRadius: 20 }
});
