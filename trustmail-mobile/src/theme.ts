export const colors = {
  bg: "#080B12",
  panel: "#111722",
  panel2: "#151D2B",
  border: "#243044",
  text: "#F4F7FB",
  muted: "#8C9AAF",
  blue: "#4FC3F7",
  green: "#30D158",
  amber: "#FF9F0A",
  red: "#FF3B3B"
};

export function verdictColor(label: string) {
  if (label === "phishing") return colors.red;
  if (label === "suspicious") return colors.amber;
  return colors.green;
}
