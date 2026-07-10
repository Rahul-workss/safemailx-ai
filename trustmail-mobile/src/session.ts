/**
 * session.ts — Centralized secure session storage for SafeMail X.
 *
 * All reads/writes to secure storage go through this module.
 * Do NOT call SecureStore directly from App.tsx or api.ts.
 *
 * Security note: expo-secure-store uses the platform Keychain (iOS) /
 * Android Keystore (Android) — both are hardware-backed encrypted stores.
 * This is intentionally NOT AsyncStorage which is unencrypted plaintext.
 */
import * as SecureStore from "expo-secure-store";

const TOKEN_KEY = "safemailx_access_token";
const EMAIL_KEY = "safemailx_email";

// --------------------------------------------------------------------------
// Expiry deduplication — prevents multiple concurrent 401s from firing
// multiple logout redirects. Reset only when a new session is saved.
// --------------------------------------------------------------------------
let sessionExpiredHandler: (() => void) | null = null;
let hasTriggeredExpiry = false;

export function registerSessionExpiredHandler(handler: () => void): void {
  sessionExpiredHandler = handler;
}

export function triggerSessionExpired(): void {
  if (hasTriggeredExpiry) return; // already fired for this expiry episode
  hasTriggeredExpiry = true;
  if (sessionExpiredHandler) {
    sessionExpiredHandler();
  }
}

// --------------------------------------------------------------------------
// Core storage helpers
// --------------------------------------------------------------------------

/**
 * Persist both the access token and the user email to encrypted storage.
 * Also resets the expiry-dedup flag so the next 401 after a fresh login
 * will correctly trigger the logout flow again.
 */
export async function saveSession(token: string, email: string): Promise<void> {
  await SecureStore.setItemAsync(TOKEN_KEY, token);
  await SecureStore.setItemAsync(EMAIL_KEY, email);
  hasTriggeredExpiry = false; // reset for the new session
}

/**
 * Load a previously persisted session.
 * Returns null if either key is missing or empty — partial state is
 * treated as no session (never return a half-populated object).
 */
export async function loadSession(): Promise<{ token: string; email: string } | null> {
  try {
    const token = await SecureStore.getItemAsync(TOKEN_KEY);
    const email = await SecureStore.getItemAsync(EMAIL_KEY);
    if (!token || !email) return null;
    return { token, email };
  } catch {
    // Storage failure on read = treat as no session, never crash
    return null;
  }
}

/**
 * Remove both session keys from secure storage.
 * Wrapped in try/catch — a storage failure here must never throw
 * and must never block the caller from proceeding to the login screen.
 */
export async function clearSession(): Promise<void> {
  try {
    await SecureStore.deleteItemAsync(TOKEN_KEY);
    await SecureStore.deleteItemAsync(EMAIL_KEY);
  } catch {
    // Swallow silently — we still navigate to login
  }
}
