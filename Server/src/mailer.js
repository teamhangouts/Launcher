const listeners = new Set();

export function onSend(handler) {
  listeners.add(handler);
  return () => listeners.delete(handler);
}

export async function sendCode(email, code, purpose) {
  console.warn(`[mailer:stub] would send ${purpose} code ${code} to ${email} -- wire up a real provider in mailer.js`);
  for (const handler of listeners) {
    handler({ email, code, purpose });
  }
}
