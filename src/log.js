// Structured diagnostics log: what the extension did, in order, without secrets.
//
// The rules are enforced here, not at the call sites, because one careless call site
// is enough to leak a vault password into a file the user will email to someone:
//   - a recursive key denylist (password/pin/code/secret/sdata/…) replaces values
//   - long strings, base64/hex blobs, otpauth URIs and 6-digit runs are redacted
//   - an Error is never stored raw, only errInfo()
//   - the buffer is bounded (drop oldest), so a long session cannot grow forever
//
// The buffer lives in chrome.storage.session: it survives a service-worker restart
// (the whole point, MV3 kills the worker every ~30s) but not a browser restart, so
// it never becomes a browsing history on disk. Warnings and errors are additionally
// mirrored to chrome.storage.local (bounded) so they survive a browser restart.

export const SESSION_KEY = "op.diag.log.v1";
export const ERRORS_KEY = "op.diag.errors.v1";
export const FORMAT = 1;

const MAX_EVENTS = 900;
const MAX_CHARS = 500_000;
const MAX_ERRORS = 25;
const MAX_STRING = 300;
const MAX_KEYS = 48;
const MAX_ARRAY = 40;
const MAX_DEPTH = 4;
const FLUSH_DELAY_MS = 120;

// exact key names that must never carry a value into the log
const DROP_EXACT =
  /^(pw|pwd|pass|passwd|password|passphrase|pin|passcode|otp|totp|code|codes|secret|sharedkey|hamk|salt|sdata|smsg|pake|payload|cookie|token|authorization|credential|credentials|privatekey|clientprivatekey)$/i;
// substring match, so "userPassword" or "apiToken" is caught too
const DROP_PART = /(password|passwd|secret|token|cookie|privatekey|sharedkey|apikey)/i;

/** Redact a single string: URLs, blobs, and anything that looks like a code. */
export function redactText(input) {
  let s;
  if (typeof input === "string") s = input;
  else if (input instanceof Error) s = input.message || input.name || "error";
  else s = String(input);
  s = s.replace(/(?:apple-)?otpauth:\/\/[^\s"'<>]+/gi, "[otpauth]");
  s = s.replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, "[b64]");
  s = s.replace(/\b[0-9a-f]{40,}\b/gi, "[hex]");
  // a bare six-digit run is a pairing code or a TOTP; never worth the risk
  s = s.replace(/(?<!\d)\d{6}(?!\d)/g, "[6d]");
  if (s.length > MAX_STRING) s = s.slice(0, MAX_STRING) + `…(+${s.length - MAX_STRING})`;
  return s;
}

/** Keep the shape of a field descriptor small enough to read. */
export function trunc(input, max = 48) {
  const s = String(input ?? "");
  return s.length > max ? s.slice(0, max) + "…" : s;
}

/** host + path only: query strings and fragments routinely carry session tokens. */
export function safeUrl(u) {
  try {
    const url = new URL(String(u));
    if (url.protocol !== "http:" && url.protocol !== "https:") return `${url.protocol}//`;
    const p = url.pathname.length > 80 ? `${url.pathname.slice(0, 80)}…` : url.pathname;
    return `${url.hostname}${p}`;
  } catch {
    return "[unparsable-url]";
  }
}

/** j•••n@example.com: enough to tell two accounts apart, not enough to be a credential. */
export function maskUser(input) {
  const s = String(input ?? "");
  if (!s) return "";
  const at = s.indexOf("@");
  const local = at > 0 ? s.slice(0, at) : s;
  const domain = at > 0 ? s.slice(at) : "";
  let masked;
  if (local.length <= 1) masked = "*";
  else if (local.length === 2) masked = `${local[0]}*`;
  else masked = `${local[0]}${"•".repeat(Math.min(6, local.length - 2))}${local.slice(-1)}`;
  return `${masked}${domain}`;
}

/** Never hand an Error to the log: the stack and message are the useful parts. */
export function errInfo(e) {
  if (e === null || e === undefined) return { name: "unknown", msg: "(no error object)" };
  if (typeof e === "string") return { name: "Thrown", msg: redactText(e) };
  const name = e.name ? String(e.name) : "Error";
  const out = { name, msg: redactText(e.message ?? "") };
  // not "code": that key name is on the denylist and would be redacted
  if (e.code !== undefined && e.code !== null) out.errCode = trunc(String(e.code), 60);
  if (typeof e.stack === "string") {
    const frames = e.stack
      .split("\n")
      .slice(1, 5)
      .map((l) => redactText(l.trim()))
      .filter(Boolean);
    if (frames.length) out.frames = frames;
  }
  return out;
}

function sanitizeNode(value, depth, seen) {
  if (value === null || value === undefined) return undefined;
  const kind = typeof value;
  if (kind === "number") return Number.isFinite(value) ? value : null;
  if (kind === "boolean") return value;
  if (kind === "string") return redactText(value);
  if (kind === "bigint") return "[bigint]";
  if (kind !== "object") return undefined;
  if (value instanceof Error) return errInfo(value);
  if (seen.has(value)) return "[circular]";
  if (depth >= MAX_DEPTH) return "[deep]";
  seen.add(value);

  if (Array.isArray(value)) {
    const out = value.slice(0, MAX_ARRAY).map((v) => sanitizeNode(v, depth + 1, seen));
    if (value.length > MAX_ARRAY) out.push(`…(+${value.length - MAX_ARRAY})`);
    return out;
  }
  if (value instanceof Map) return `[Map ${value.size}]`;
  if (value instanceof Set) return `[Set ${value.size}]`;

  const out = {};
  const keys = Object.keys(value);
  keys.slice(0, MAX_KEYS).forEach((key) => {
    if (DROP_EXACT.test(key) || DROP_PART.test(key)) {
      out[key] = "[redacted]";
      return;
    }
    const sv = sanitizeNode(value[key], depth + 1, seen);
    if (sv !== undefined) out[key] = sv;
  });
  if (keys.length > MAX_KEYS) out["…"] = `(+${keys.length - MAX_KEYS} keys)`;
  return out;
}

/** Public safety net: whatever a call site passes in, this is what gets stored. */
export function sanitize(value) {
  try {
    return sanitizeNode(value, 0, new WeakSet());
  } catch (e) {
    return { "[sanitize-failed]": errInfo(e) };
  }
}

function sessionArea() {
  return typeof chrome !== "undefined" && chrome?.storage?.session ? chrome.storage.session : null;
}
function localArea() {
  return typeof chrome !== "undefined" && chrome?.storage?.local ? chrome.storage.local : null;
}

/**
 * Bounded, persistent-enough event buffer. One instance per context; only the
 * service worker appends, the popup reads and clears.
 */
export class DiagLog {
  constructor(opts = {}) {
    this.maxEvents = opts.maxEvents || MAX_EVENTS;
    this.maxChars = opts.maxChars || MAX_CHARS;
    this.events = [];
    this.errors = [];
    this.seq = 0;
    this.chars = 0;
    this.meta = {};
    this._timer = null;
    this._chain = Promise.resolve();
    this._broken = false;
  }

  async load(meta = {}) {
    this.meta = { startedAt: Date.now(), ...meta };
    const session = sessionArea();
    try {
      if (session) {
        const got = await session.get({ [SESSION_KEY]: null });
        const prev = got?.[SESSION_KEY];
        if (prev && Array.isArray(prev.events)) {
          // events pushed while we were reading stay, a boot log must not erase them
          this.events = [...prev.events, ...this.events].slice(-this.maxEvents);
          this.seq = Math.max(Number(prev.seq) || 0, this.seq);
          this.chars = this.events.reduce((n, e) => n + this._size(e), 0);
          if (prev.meta?.startedAt) this.meta.startedAt = prev.meta.startedAt;
          this.meta.loaded = prev.events.length;
        }
      }
    } catch (_) {
      /* an unreadable buffer is not worth crashing over */
    }
    try {
      const local = localArea();
      if (local) {
        const got = await local.get({ [ERRORS_KEY]: null });
        const prev = got?.[ERRORS_KEY];
        if (prev && Array.isArray(prev.events)) this.errors = prev.events.slice(-MAX_ERRORS).map(sanitize);
      }
    } catch (_) {}
    return this;
  }

  _size(entry) {
    try {
      return JSON.stringify(entry)?.length || 0;
    } catch (_) {
      return 64;
    }
  }

  /** @returns {object} the stored entry, so a caller can echo its id if needed */
  push(ev = {}) {
    const level = ev.lvl || "debug";
    const entry = {
      id: ++this.seq,
      ts: Date.now(),
      t: trunc(ev.t || "event", 40),
      lvl: level,
    };
    if (ev.trace) entry.trace = trunc(ev.trace, 40);
    if (ev.ctx) entry.ctx = sanitize(ev.ctx);
    if (ev.d !== undefined) entry.d = sanitize(ev.d);
    this.events.push(entry);
    this.chars += this._size(entry);
    this._trim();
    if (level === "error" || level === "warn") this._rememberError(entry);
    this._schedule(level === "error" || level === "warn");
    return entry;
  }

  _trim() {
    while (this.events.length > this.maxEvents || (this.chars > this.maxChars && this.events.length > 1)) {
      const gone = this.events.shift();
      this.chars -= this._size(gone);
      if (this.chars < 0) this.chars = 0;
    }
  }

  _rememberError(entry) {
    this.errors.push({
      id: entry.id,
      ts: entry.ts,
      t: entry.t,
      lvl: entry.lvl,
      trace: entry.trace,
      ctx: entry.ctx,
      d: entry.d,
    });
    if (this.errors.length > MAX_ERRORS) this.errors.splice(0, this.errors.length - MAX_ERRORS);
    const local = localArea();
    if (!local) return;
    this._chain = this._chain
      .then(() => local.set({ [ERRORS_KEY]: { at: Date.now(), events: this.errors.slice(-MAX_ERRORS) } }))
      .catch(() => {});
  }

  _schedule(now = false) {
    if (this._broken) return;
    if (now) {
      clearTimeout(this._timer);
      this._timer = null;
      this.flush();
      return;
    }
    if (this._timer) return;
    this._timer = setTimeout(() => {
      this._timer = null;
      this.flush();
    }, FLUSH_DELAY_MS);
  }

  flush() {
    const session = sessionArea();
    if (!session || this._broken) return this._chain;
    // snapshot the reference: storage serializes synchronously on call
    const payload = {
      seq: this.seq,
      meta: { startedAt: this.meta.startedAt, ver: this.meta.ver, incognito: this.meta.incognito },
      events: this.events,
    };
    this._chain = this._chain
      .then(() => session.set({ [SESSION_KEY]: payload }))
      .catch((e) => {
        // stop hammering a storage area that refuses us, keep logging in memory
        this._broken = true;
        try {
          console.warn("[Open Passwords] diagnostics disabled, session storage refused:", e?.message);
        } catch (_) {}
      });
    return this._chain;
  }

  async clear() {
    this.events = [];
    this.errors = [];
    this.chars = 0;
    const session = sessionArea();
    const local = localArea();
    try {
      await session?.remove(SESSION_KEY);
    } catch (_) {}
    try {
      await local?.remove(ERRORS_KEY);
    } catch (_) {}
  }

  snapshot(extra = {}) {
    return {
      app: "Open Passwords",
      format: FORMAT,
      generatedAt: new Date().toISOString(),
      counts: { events: this.events.length, errors: this.errors.length, droppedOldest: Math.max(0, this.seq - this.events.length) },
      meta: { ...this.meta, ...sanitize(extra) },
      errors: this.errors.slice(-MAX_ERRORS),
      events: this.events.slice(),
    };
  }
}

/** Serialized, human-diffable export. */
export function serialize(snapshot) {
  return JSON.stringify(snapshot, null, 2);
}
