// ─── SafeMail X Indigo Nocturne palette (exact from Lovable source) ────────────
export const C = {
  // Backgrounds
  bg:       "#010104",   // Black Hole
  ink:      "#07071a",
  ink2:     "#0d0d28",
  ink3:     "#151538",   // Lost in Sadness
  ink4:     "#2c2e6e",   // Blue Rose

  // Frost (Placebo Purple tints)
  frost:    "#f2eafd",   // primary text
  frost2:   "#d6cce8",
  frost3:   "#a39ab8",
  frost4:   "#83808c",   // muted / twilight

  // Brand
  violet:      "#3b41bf",   // Early Spring Night
  violetSoft:  "#5a60d8",
  violetGlow:  "#8a8ff0",   // sapphire

  // Status
  emerald: "#6fd9b8",
  rose:    "#e08aae",
  gold:    "#e8a84c",   // used for suspicious / unknown

  // Hairlines
  line:  "rgba(242,234,253,0.05)",
  line2: "rgba(242,234,253,0.12)",
};

export const colors = {
  bg: C.bg,
  panel: C.ink3,
  panel2: C.ink2,
  border: C.ink4,
  borderSubtle: C.line2,
  text: C.frost,
  muted: C.frost4,
  accent: C.violet,
  accentBright: C.violetSoft,
  accentGlow: C.violetGlow,
  green: C.emerald,
  amber: C.gold,
  red: C.rose,
  glow1: "rgba(59,65,191,0.28)",
  glow2: "rgba(242,234,253,0.06)",
  glow3: "rgba(44,46,110,0.45)",
};

export function verdictColor(label: string) {
  if (label === "phishing")   return C.rose;
  if (label === "suspicious") return C.gold;
  if (label === "queued")     return C.frost4;
  if (label === "failed")     return C.rose;
  return C.emerald;  // legitimate / safe
}
