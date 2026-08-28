const TERMINAL_CONTROL_BYTES = new Map([
  ["c", "\x03"],
  ["d", "\x04"],
]);

export function terminalControlBytes(event) {
  if (!event.ctrlKey || event.altKey || event.metaKey) return null;
  return TERMINAL_CONTROL_BYTES.get(event.key.toLowerCase()) ?? null;
}
