/**
 * SafeMailX AI — Subscription Service
 * Handles Razorpay order creation and payment verification via the backend API.
 *
 * Android flow:
 *   1. createSubscriptionOrder(plan) → backend creates Razorpay order → returns checkout_url + order_id
 *   2. User pays via Razorpay hosted page (opened in expo-web-browser)
 *   3. verifySubscriptionPayment(orderId, paymentId, signature) → backend verifies with Razorpay HMAC
 *
 * iOS: Apple IAP wired separately. These functions are Android-only for now.
 */

import { loadSession } from '../session';

// Re-uses the same base URL as the rest of the app
const BASE_URL = process.env.EXPO_PUBLIC_API_BASE_URL || 'https://safemailx-ai-production.up.railway.app';

export type PlanKey = 'shield' | 'pro';

export interface RazorpayOrder {
  order_id: string;
  amount: number;          // in paise (₹399 = 39900)
  currency: string;        // 'INR'
  checkout_url: string;    // Razorpay hosted checkout URL
  plan: PlanKey;
}

export interface SubscriptionStatus {
  tier: 'free' | 'shield' | 'pro';
  expires_at: string | null;
  is_active: boolean;
}

/**
 * Ask the backend to create a Razorpay order for the given plan.
 * Backend calls Razorpay Orders API and returns the hosted checkout URL.
 */
export async function createSubscriptionOrder(plan: PlanKey): Promise<RazorpayOrder> {
  const session = await loadSession();
  const token = session?.token ?? '';

  const response = await fetch(`${BASE_URL}/api/subscriptions/create-order`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      'Bypass-Tunnel-Reminder': 'true',
    },
    body: JSON.stringify({ plan }),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Order creation failed (${response.status}): ${detail}`);
  }

  return response.json();
}

/**
 * After Razorpay redirects back, verify the payment signature with the backend.
 * Returns true if the payment is genuine and the user tier has been upgraded.
 */
export async function verifySubscriptionPayment(
  orderId: string,
  paymentId: string,
  signature: string,
): Promise<boolean> {
  const session = await loadSession();
  const token = session?.token ?? '';

  const response = await fetch(`${BASE_URL}/api/subscriptions/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      'Bypass-Tunnel-Reminder': 'true',
    },
    body: JSON.stringify({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
    }),
  });

  if (!response.ok) return false;
  const data = await response.json();
  return data?.verified === true;
}

/**
 * Fetch the current user's subscription status.
 * Used on app load and after payment to determine which features to gate.
 */
export async function fetchSubscriptionStatus(): Promise<SubscriptionStatus> {
  const session = await loadSession();
  const token = session?.token ?? '';

  const response = await fetch(`${BASE_URL}/api/subscriptions/status`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Bypass-Tunnel-Reminder': 'true',
    },
  });

  if (!response.ok) {
    // Graceful fallback — treat as free if backend unreachable
    return { tier: 'free', expires_at: null, is_active: false };
  }

  return response.json();
}
