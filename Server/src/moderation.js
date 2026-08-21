export const BlockedTerms = new Set(["badword", "examplehateword"]);

const LeetMap = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };

function normalize(text) {
  let normalized = text.toLowerCase();
  for (const [digit, letter] of Object.entries(LeetMap)) {
    normalized = normalized.split(digit).join(letter);
  }
  return normalized.replace(/[^a-z0-9\s]/g, "");
}

export function containsBlockedTerm(text) {
  const normalized = normalize(text);
  const words = normalized.split(/\s+/).filter(Boolean);
  const collapsed = words.join("");
  for (const term of BlockedTerms) {
    const normalizedTerm = normalize(term);
    if (words.includes(normalizedTerm) || collapsed.includes(normalizedTerm)) {
      return true;
    }
  }
  return false;
}
